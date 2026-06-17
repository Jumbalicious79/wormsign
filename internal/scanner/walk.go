package scanner

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Jumbalicious79/wormsign/internal/ioc"
)

// Discovery collects the artifacts a walk produces. Slice fields are
// guarded by mu; atomic counters can be read from any goroutine for
// progress reporting while the walk is still in flight.
type Discovery struct {
	mu sync.Mutex

	Repos            []string
	NodeModules      []string
	PersistenceFiles map[string]string // exact path -> stat-like evidence line

	TasksJSON         []string
	PayloadCandidates []string // bundle.js (V1) + setup_bun.js / bun_environment.js (Sha1-Hulud V2)
	ShaiWorkflowYML   []string
	RopePYZ           []string
	RequirementsFiles []string
	ClaudeSettings    []string // settings.json files located directly inside a .claude dir (home + repos)
	IDELoaderDrops    []string // setup.mjs / execution.js / bun_environment.js inside a .claude or .vscode dir
	TmpLockHits       []string
	DurabletaskDists  []string // durabletask-*.dist-info / egg-info dirs (installed-package metadata)

	ContentScanQueue []string

	// Atomic counters — safe to read concurrently with the walk.
	DirsVisited    atomic.Int64
	FilesVisited   atomic.Int64
	ContentScanned atomic.Int64
	ContentMatches atomic.Int64
	BundlesHashed  atomic.Int64
	BundlesBad     atomic.Int64
}

// NewDiscovery constructs an empty Discovery ready for use.
func NewDiscovery() *Discovery {
	return &Discovery{
		PersistenceFiles: make(map[string]string),
	}
}

// ReposCount returns the number of repos discovered so far. Holds mu
// briefly so progress reads don't race with walker appends.
func (d *Discovery) ReposCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.Repos)
}

// NodeModulesCount returns the number of node_modules directories found so far.
func (d *Discovery) NodeModulesCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.NodeModules)
}

// ContentQueueCount returns the size of the content-scan queue.
func (d *Discovery) ContentQueueCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.ContentScanQueue)
}

// Snapshot returns a defensive copy of every slice on Discovery that
// downstream checks read. After Walk() returns, the slices are
// effectively immutable, but going through Snapshot() gives explicit
// race-detector-friendly happens-before with the walker's appends and
// future-proofs the code against refactors that might run a check
// concurrently with the walk.
type Snapshot struct {
	Repos             []string
	NodeModules       []string
	TasksJSON         []string
	PayloadCandidates []string
	ShaiWorkflowYML   []string
	RopePYZ           []string
	RequirementsFiles []string
	ClaudeSettings    []string // settings.json files located directly inside a .claude dir (home + repos)
	IDELoaderDrops    []string // setup.mjs / execution.js / bun_environment.js inside a .claude or .vscode dir
	TmpLockHits       []string
	DurabletaskDists  []string
	ContentScanQueue  []string
	PersistenceFiles  map[string]string
}

func (d *Discovery) Snapshot() *Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	snap := &Snapshot{
		Repos:             append([]string(nil), d.Repos...),
		NodeModules:       append([]string(nil), d.NodeModules...),
		TasksJSON:         append([]string(nil), d.TasksJSON...),
		PayloadCandidates: append([]string(nil), d.PayloadCandidates...),
		ShaiWorkflowYML:   append([]string(nil), d.ShaiWorkflowYML...),
		RopePYZ:           append([]string(nil), d.RopePYZ...),
		RequirementsFiles: append([]string(nil), d.RequirementsFiles...),
		ClaudeSettings:    append([]string(nil), d.ClaudeSettings...),
		IDELoaderDrops:    append([]string(nil), d.IDELoaderDrops...),
		TmpLockHits:       append([]string(nil), d.TmpLockHits...),
		DurabletaskDists:  append([]string(nil), d.DurabletaskDists...),
		ContentScanQueue:  append([]string(nil), d.ContentScanQueue...),
		PersistenceFiles:  make(map[string]string, len(d.PersistenceFiles)),
	}
	for k, v := range d.PersistenceFiles {
		snap.PersistenceFiles[k] = v
	}
	return snap
}

// walkConfig is the immutable configuration for a Walk.
type walkConfig struct {
	homeDir         string
	roots           []string
	excludePaths    []string
	searchDirPrefix []string
	persistenceSet  map[string]bool
	// outputPath, when non-empty, is the absolute path of the report
	// wormsign is about to write. The walker skips it so a re-run with
	// the same --output doesn't pick up the prior report as a low-sig
	// hit (it contains literal IoC strings in its own bodies).
	outputPath  string
	concurrency int
	logger      *slog.Logger
}

type walkItem struct {
	path        string
	inRepo      bool
	inSearchDir bool
}

// walker carries the immutable state plus the work channel. The walker
// is request-scoped (one per Walk call); storing ctx on it is the
// pragmatic choice here — passing ctx through every classifyFile /
// enqueue call doubles every signature without buying anything, and
// the "no context in struct" rule is aimed at long-lived services.
type walker struct {
	ctx            context.Context
	cfg            *walkConfig
	d              *Discovery
	excl           []string
	searchPrefixes []string

	work chan walkItem
	wg   sync.WaitGroup

	seenMu sync.Mutex
	seen   map[string]bool
}

// Walk performs a single concurrent traversal of the configured roots,
// populating the supplied Discovery. The caller owns Discovery's
// lifecycle so a Progress display can read counters from it while the
// walk is still in flight.
func Walk(ctx context.Context, d *Discovery, cfg walkConfig) {
	if cfg.concurrency <= 0 {
		cfg.concurrency = max(4, runtime.NumCPU())
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}

	excl := make([]string, 0, len(cfg.excludePaths))
	for _, p := range cfg.excludePaths {
		excl = append(excl, filepath.Clean(p))
	}
	searchPrefixes := make([]string, 0, len(cfg.searchDirPrefix))
	for _, p := range cfg.searchDirPrefix {
		searchPrefixes = append(searchPrefixes, filepath.Clean(p))
	}

	w := &walker{
		ctx:            ctx,
		cfg:            &cfg,
		d:              d,
		excl:           excl,
		searchPrefixes: searchPrefixes,
		work:           make(chan walkItem, cfg.concurrency*4),
		seen:           make(map[string]bool),
	}

	for range cfg.concurrency {
		go func() {
			for item := range w.work {
				w.process(item)
				w.wg.Done()
			}
		}()
	}

	for _, root := range cfg.roots {
		root = filepath.Clean(root)
		// Lstat so we don't crash on broken symlinks; ReadDir below
		// will follow if the root is a symlink to a real directory —
		// that's the intended behavior for cloud-sync roots which on
		// macOS are commonly symlinks (e.g. ~/Dropbox).
		info, err := os.Lstat(root)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			cfg.logger.Debug("walking through symlinked discovery root", "path", root)
		}
		w.enqueue(walkItem{path: root, inSearchDir: prefixMatch(root, searchPrefixes)})
	}

	w.wg.Wait()
	close(w.work)

	// Stat exact-path persistence IoCs that may not lie under any walked
	// root (/tmp/processor.sh etc. are checked here even though /tmp is
	// usually in the search-dir set).
	for p := range cfg.persistenceSet {
		if ctx.Err() != nil {
			return
		}
		if info, err := os.Lstat(p); err == nil {
			w.d.mu.Lock()
			w.d.PersistenceFiles[p] = lsla(info, p)
			w.d.mu.Unlock()
		}
	}
}

// enqueue places item on the work channel. If the channel is full, the
// directory is processed synchronously to keep the pool from deadlocking.
// Deduplicates against w.seen.
func (w *walker) enqueue(item walkItem) {
	w.seenMu.Lock()
	if w.seen[item.path] {
		w.seenMu.Unlock()
		return
	}
	w.seen[item.path] = true
	w.seenMu.Unlock()

	w.wg.Add(1)
	select {
	case w.work <- item:
	default:
		// Channel full — process inline rather than block. The walker's
		// ctx is carried on the struct so a SIGINT during deep
		// recursion still propagates through the inline path.
		w.process(item)
		w.wg.Done()
	}
}

// process reads a directory and classifies its entries.
func (w *walker) process(item walkItem) {
	if w.ctx.Err() != nil {
		return
	}
	if isExcluded(item.path, w.excl) {
		return
	}
	entries, err := os.ReadDir(item.path)
	if err != nil {
		return
	}

	w.d.DirsVisited.Add(1)

	// Is this dir a repo root (contains .git as child)?
	isRepo := false
	for _, e := range entries {
		if e.Name() == ".git" {
			isRepo = true
			break
		}
	}
	if isRepo {
		w.d.mu.Lock()
		w.d.Repos = append(w.d.Repos, item.path)
		w.d.mu.Unlock()
		item.inRepo = true
	}

	for _, e := range entries {
		name := e.Name()
		full := filepath.Join(item.path, name)

		if name == ".git" {
			// Recorded above; never recurse into git internals.
			continue
		}

		if e.IsDir() {
			// Record durabletask package metadata dirs even if we choose
			// not to descend (they're leaf metadata dirs anyway). Detected
			// here so the §6d check never has to execute a Python runtime.
			if isDurabletaskDistDir(name) {
				w.d.appendStr(&w.d.DurabletaskDists, full)
			}
			if pruneDir(name) {
				continue
			}
			if isExcluded(full, w.excl) {
				continue
			}
			if name == "node_modules" {
				w.d.mu.Lock()
				w.d.NodeModules = append(w.d.NodeModules, full)
				w.d.mu.Unlock()
			}
			inSearch := item.inSearchDir || prefixMatch(full, w.searchPrefixes)
			w.enqueue(walkItem{
				path:        full,
				inRepo:      item.inRepo,
				inSearchDir: inSearch,
			})
			continue
		}

		w.d.FilesVisited.Add(1)
		w.classifyFile(item, full, name)
	}
}

// classifyFile records a file in the relevant Discovery lists. Cheap —
// filename matching only. Dataless / NUL / size filtering happens when
// the file is actually read in content.go.
func (w *walker) classifyFile(item walkItem, full, name string) {
	d := w.d

	switch {
	case name == "tasks.json":
		d.appendStr(&d.TasksJSON, full)
	case ioc.PayloadFileNames[name]:
		// bundle.js (V1) + setup_bun.js / bun_environment.js (Sha1-Hulud
		// V2). All three are hashed against AllPayloadHashes().
		d.appendStr(&d.PayloadCandidates, full)
	case name == "rope.pyz":
		d.appendStr(&d.RopePYZ, full)
	}

	// Python requirements / lock files — sourced from the IoC corpus so
	// the corpus is the single source of truth. The bash script does
	// not gate on "inside a discovered repo"; we follow suit so that
	// loose pyproject.toml files (prototype directories, scratch
	// scripts) aren't missed.
	if ioc.RequirementsFileNames[name] {
		d.appendStr(&d.RequirementsFiles, full)
	} else {
		lname := strings.ToLower(name)
		if strings.HasSuffix(lname, ".txt") {
			for _, pre := range ioc.RequirementsFilePrefixes {
				if strings.HasPrefix(lname, pre) {
					d.appendStr(&d.RequirementsFiles, full)
					break
				}
			}
		}
	}

	// /tmp/tmp.ts*.lock pattern (framework daemon PID lock).
	if strings.HasPrefix(name, "tmp.ts") && strings.HasSuffix(name, ".lock") {
		dir := filepath.Dir(full)
		switch dir {
		case "/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp":
			d.appendStr(&d.TmpLockHits, full)
		}
	}

	// shai-hulud workflow YAML inside .github/workflows/.
	if strings.HasPrefix(strings.ToLower(name), "shai-hulud") &&
		(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
		sep := string(filepath.Separator)
		marker := sep + ".github" + sep + "workflows" + sep
		if strings.Contains(full, marker) {
			d.appendStr(&d.ShaiWorkflowYML, full)
		}
	}

	// Mini Shai-Hulud IDE persistence drops into per-project `.claude/`
	// and `.vscode/` directories: a `settings.json` SessionStart hook, a
	// `tasks.json` folderOpen task, and the loader/payload files those
	// invoke (`setup.mjs` + `execution.js`). We key off the immediate
	// parent directory name so legitimate Claude Code plugin code nested
	// deeper under `~/.claude/plugins/` (whose parent is `hooks`, `bin`,
	// a version dir, etc.) is not flagged.
	parent := filepath.Base(item.path)
	if parent == ".claude" && name == "settings.json" {
		// Claude SessionStart hooks live in `.claude/settings.json`.
		d.appendStr(&d.ClaudeSettings, full)
	}
	if (parent == ".claude" || parent == ".vscode") && ioc.IDELoaderFileNames[name] {
		d.appendStr(&d.IDELoaderDrops, full)
	}

	// Skip the user's own report output (could otherwise self-match on
	// re-runs against the same --output path).
	if w.cfg.outputPath != "" && full == w.cfg.outputPath {
		return
	}

	if (item.inSearchDir || item.inRepo) && shouldContentScan(name) {
		d.appendStr(&d.ContentScanQueue, full)
	}
}

// appendStr appends to one of Discovery's string slices under mu. Cuts
// down the visual noise of repeated lock/append/unlock in classifyFile.
func (d *Discovery) appendStr(slot *[]string, v string) {
	d.mu.Lock()
	*slot = append(*slot, v)
	d.mu.Unlock()
}

// shouldContentScan applies a cheap filename pre-filter to skip obvious
// binaries before any I/O.
func shouldContentScan(name string) bool {
	if strings.HasPrefix(name, "wormsign-") && strings.HasSuffix(name, ".md") {
		return false
	}
	if strings.HasPrefix(name, "macos-shai-hulud-iocs-") && strings.HasSuffix(name, ".md") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
		".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".dmg", ".pkg", ".iso", ".rar",
		".mp3", ".mp4", ".mov", ".avi", ".m4a", ".wav", ".webm", ".flv", ".mkv",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".class", ".jar", ".war",
		".pyc", ".pyo",
		".so", ".dylib", ".a", ".o", ".obj",
		".exe", ".dll", ".bin":
		return false
	}
	return true
}

// pruneDir returns true for directory names we never recurse into.
func pruneDir(name string) bool {
	switch name {
	case ".Trash", ".Spotlight-V100", ".fseventsd",
		".DocumentRevisions-V100", ".TemporaryItems",
		".HFS+ Private Directory Data", "$RECYCLE.BIN":
		return true
	}
	return false
}

// hasPathPrefix returns true if path is exactly base or sits under it
// in the filesystem tree. Special-cases base == "/" so we don't compose
// "//" when checking children of the root.
func hasPathPrefix(path, base string) bool {
	if path == base {
		return true
	}
	if base == string(filepath.Separator) {
		return strings.HasPrefix(path, base)
	}
	return strings.HasPrefix(path, base+string(filepath.Separator))
}

func isExcluded(path string, excludes []string) bool {
	for _, e := range excludes {
		if hasPathPrefix(path, e) {
			return true
		}
	}
	return false
}

func prefixMatch(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if hasPathPrefix(path, p) {
			return true
		}
	}
	return false
}

func lsla(info os.FileInfo, path string) string {
	if info == nil {
		return path
	}
	return info.Mode().String() + "  " +
		humanSize(info.Size()) + "  " +
		info.ModTime().Format("2006-01-02 15:04:05") + "  " +
		path
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	div, exp := int64(unit), 0
	for nn := n / unit; nn >= unit; nn /= unit {
		div *= unit
		exp++
	}
	// %.1f keeps one decimal so "1.9 MiB" doesn't render as "1MiB".
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) +
		string("KMGTPE"[exp]) + "iB"
}
