// Package scanner orchestrates the full Shai-Hulud IoC hunt: walks the
// configured filesystem roots once, dispatches parallel content/hash/
// network checks, and writes findings into a report.Reporter.
package scanner

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jumbalicious79/wormsign/internal/ioc"
	"github.com/Jumbalicious79/wormsign/internal/report"
)

// Options configures a full scan run.
type Options struct {
	HomeDir        string
	ExtraRoots     []string
	Concurrency    int
	MaxFileSize    int64
	NoDefaultRoots bool // when true, only ExtraRoots are walked (test mode)
	// OutputPath is the absolute path of the report file we are about
	// to write. The walker skips this file so re-runs against the same
	// --output don't self-match on the previous report's IoC literals.
	OutputPath string
	// ProgressOut, when non-nil, receives a live counter display
	// (uses \r line redraw — caller should pass a TTY-bound writer).
	ProgressOut io.Writer
	Logger      *slog.Logger
}

// Result is what the orchestrator hands back to the caller.
type Result struct {
	Discovery *Discovery
	Report    *report.Reporter
	Roots     []string
	Excludes  []string
	Duration  time.Duration
}

// Run executes every check, in the order that matches the bash script's
// markdown layout. Discovery (the filesystem walk) is the single most
// expensive step — independent checks (network, credentials) run
// concurrently with it.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = max(4, runtime.NumCPU())
	}

	start := time.Now()
	r := report.New()

	// Expand {HOME} placeholders for all the IoC corpus tables.
	var roots []string
	if !opts.NoDefaultRoots {
		roots = append(roots, expandAll(ioc.DiscoveryRoots, opts.HomeDir)...)
		roots = append(roots, expandAll(ioc.SearchDirs, opts.HomeDir)...)
	}
	roots = append(roots, opts.ExtraRoots...)
	roots = dedupSlice(roots)

	excludes := expandAll(ioc.ExcludePaths, opts.HomeDir)
	searchDirs := expandAll(ioc.SearchDirs, opts.HomeDir)
	persistencePaths := expandAll(ioc.PersistenceFiles, opts.HomeDir)
	persistenceSet := make(map[string]bool, len(persistencePaths))
	for _, p := range persistencePaths {
		persistenceSet[p] = true
	}

	// Pre-register every section in canonical order so concurrent
	// checks that call r.Section later don't race for ordering. The
	// later calls only update the preamble; nextOrder is fixed here.
	for _, title := range []string{
		sectionDiscovery,
		sectionPersistence,
		sectionIDE,
		sectionContentHigh,
		sectionContentLow,
		sectionNetwork,
		sectionCreds,
		sectionBundle,
		sectionWorkflow,
		sectionPyPI,
		sectionTokens,
	} {
		r.Section(title, "")
	}
	r.Section(sectionDiscovery, "Walking discovery roots ONCE, in parallel. Repos and node_modules are recorded as the walk goes; content-scan zones are the union of search dirs and discovered repos.")

	// Pre-create Discovery so Progress can read counters from it while
	// the walk runs.
	d := NewDiscovery()
	progress := newProgress(d, opts.ProgressOut)
	progress.start()
	defer progress.stop()

	// `walkDone` synchronizes the discovery walk with the post-walk
	// checks. All other check goroutines feed a single WaitGroup so a
	// panic inside any check still hits `defer wg.Done()` and unblocks
	// Run() rather than hanging the scan forever.
	walkDone := make(chan struct{}, 1)
	go func() {
		defer func() { walkDone <- struct{}{} }()
		opts.Logger.Debug("starting filesystem walk", "roots", len(roots), "concurrency", opts.Concurrency)
		Walk(ctx, d, walkConfig{
			homeDir:         opts.HomeDir,
			roots:           roots,
			excludePaths:    excludes,
			searchDirPrefix: searchDirs,
			persistenceSet:  persistenceSet,
			outputPath:      opts.OutputPath,
			concurrency:     opts.Concurrency,
			logger:          opts.Logger,
		})
		progress.setPhase("scanning")
	}()

	var checks sync.WaitGroup
	runCheck := func(fn func()) {
		checks.Add(1)
		go func() {
			defer checks.Done()
			fn()
		}()
	}

	// Network + credential checks don't depend on walk output.
	runCheck(func() { checkNetwork(ctx, opts.HomeDir, r) })
	runCheck(func() { checkCredentials(opts.HomeDir, r) })

	<-walkDone
	opts.Logger.Debug("walk complete",
		"repos", d.ReposCount(),
		"node_modules", d.NodeModulesCount(),
		"files_visited", d.FilesVisited.Load(),
		"dirs_visited", d.DirsVisited.Load(),
		"content_queue", d.ContentQueueCount())

	emitDiscovery(d, roots, excludes, r)

	// Take a single snapshot of every Discovery slice now that the walk
	// is finished. Each check reads only from snap; if the walk is ever
	// refactored to run concurrently with checks, this snapshot is what
	// keeps the reads race-free.
	snap := d.Snapshot()

	// Build the content scanner up front (regex compile) so the
	// goroutine body is just the scan work.
	cs := newContentScanner()
	if opts.MaxFileSize > 0 {
		cs.maxFileSize = opts.MaxFileSize
	}

	// Post-walk checks all run concurrently.
	runCheck(func() { checkPersistence(snap, persistencePaths, r) })
	runCheck(func() { checkIDEPersistence(snap, opts.HomeDir, r) })
	runCheck(func() { checkBundleHashes(ctx, d, snap, r) })
	runCheck(func() { checkShaiWorkflows(snap, r) })
	runCheck(func() { checkPyPI(opts.HomeDir, snap, r) })
	runCheck(func() {
		matches := cs.ScanFiles(ctx, d, snap.ContentScanQueue, opts.Concurrency)
		recordContentMatches(matches, r)
		opts.Logger.Debug("content scan complete",
			"files_scanned", len(snap.ContentScanQueue), "matches", len(matches))
	})

	checks.Wait()

	return &Result{
		Discovery: d,
		Report:    r,
		Roots:     roots,
		Excludes:  excludes,
		Duration:  time.Since(start),
	}, nil
}

func emitDiscovery(d *Discovery, roots, excludes []string, r *report.Reporter) {
	var ev strings.Builder
	ev.WriteString("Discovery roots:\n")
	for _, p := range roots {
		ev.WriteString("  - " + p + "\n")
	}
	ev.WriteString("\nExcluded paths (pruned):\n")
	for _, p := range excludes {
		ev.WriteString("  - " + p + "\n")
	}
	ev.WriteString("\n")
	ev.WriteString("Dirs visited:    " + strconv.FormatInt(d.DirsVisited.Load(), 10) + "\n")
	ev.WriteString("Files visited:   " + strconv.FormatInt(d.FilesVisited.Load(), 10) + "\n")
	ev.WriteString("Repos found:     " + strconv.Itoa(d.ReposCount()) + "\n")
	ev.WriteString("node_modules:    " + strconv.Itoa(d.NodeModulesCount()) + "\n")
	ev.WriteString("Content queue:   " + strconv.Itoa(d.ContentQueueCount()) + "\n")

	// Snapshot the repo list under the lock so we don't race a late append.
	// emitDiscovery runs after <-walkDone in Run(), so this is defensive
	// for future refactors rather than fixing a current bug.
	d.mu.Lock()
	repoSnapshot := append([]string(nil), d.Repos...)
	d.mu.Unlock()
	// Sort: the walk appends repos in concurrent-completion order, which
	// is non-deterministic. Sorting makes two runs against an unchanged
	// host byte-identical (the determinism guarantee this report claims)
	// and keeps the truncated "first 50" stable rather than an arbitrary
	// 50 per run.
	sort.Strings(repoSnapshot)
	if len(repoSnapshot) > 0 {
		ev.WriteString("\nFirst 50 repos:\n")
		limit := min(len(repoSnapshot), 50)
		for _, p := range repoSnapshot[:limit] {
			ev.WriteString("  " + p + "\n")
		}
		if len(repoSnapshot) > 50 {
			ev.WriteString("  ... (" + strconv.Itoa(len(repoSnapshot)-50) + " more)\n")
		}
	}
	r.Add(report.Finding{
		Section:  sectionDiscovery,
		Status:   report.StatusInfo,
		Message:  "Discovery complete (informational — does not affect hit count):",
		Evidence: ev.String(),
	})
}

func expandAll(in []string, home string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, strings.ReplaceAll(p, "{HOME}", home))
	}
	return out
}

// withTimeout wraps context.WithTimeout but tolerates seconds <= 0
// (returns the parent ctx + no-op cancel).
func withTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
