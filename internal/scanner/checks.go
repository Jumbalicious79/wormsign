package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/Jumbalicious79/wormsign/internal/fsutil"
	"github.com/Jumbalicious79/wormsign/internal/ioc"
	"github.com/Jumbalicious79/wormsign/internal/report"
)

// Section titles — referenced from scanner.go orchestration so the
// markdown layout stays consistent with the bash script. (gosec's G101
// rule flags some of these for containing the words "credential" /
// "token"; they are report-section labels, not secrets.)
const (
	sectionDiscovery   = "0. Repository and node_modules discovery"
	sectionPersistence = "1. Persistence file presence (exact paths)"
	sectionIDE         = "2. IDE-based persistence"
	sectionContentHigh = "3. On-disk content-string grep — high-signal IoCs"
	sectionContentLow  = "4. Lower-signal strings (megalodon / shai-hulud / sha1-hulud / teampcp)"
	sectionNetwork     = "5. Network IoCs (domains + IP)"
	sectionCreds       = "6. Credential-target files the framework would read" // #nosec G101 -- section title, not a credential
	sectionBundle      = "6b. Known-malicious payload hash check (V1 bundle.js + V2 setup_bun.js / bun_environment.js)"
	sectionWorkflow    = "6c. V1 shai-hulud-workflow.yml workflow files"
	sectionPyPI        = "6d. PyPI compromised durabletask versions (2026-05-20)"
	sectionTokens      = "7. Token-string scan — ghp_ / gho_ / ghu_ / ghs_ / ghr_" // #nosec G101 -- section title, not a token
)

// --- §1 persistence ---------------------------------------------------------

// checkPersistence records the presence/absence of each exact-path IoC.
// Discovery has already Lstat'd them — we just read the snapshot.
func checkPersistence(snap *Snapshot, persistencePaths []string, r *report.Reporter) {
	r.Section(sectionPersistence, "")
	for _, p := range persistencePaths {
		if evidence, ok := snap.PersistenceFiles[p]; ok {
			r.Hit(sectionPersistence, fmt.Sprintf("Found persistence indicator: `%s`", p), evidence)
		} else {
			r.Clean(sectionPersistence, fmt.Sprintf("Not present: `%s`", p))
		}
	}
	if len(snap.TmpLockHits) > 0 {
		r.Hit(sectionPersistence,
			"Found lock-file pattern `/tmp/tmp.ts*.lock` (framework daemon PID lock)",
			strings.Join(snap.TmpLockHits, "\n"))
	} else {
		r.Clean(sectionPersistence, "No `tmp.ts*.lock` files in /tmp or /var/tmp")
	}
}

// --- §2 IDE-based persistence -----------------------------------------------

var runOnFolderOpenRE = regexp.MustCompile(`"runOn"\s*:\s*"folderOpen"`)
var sessionStartRE = regexp.MustCompile(`(?i)"session.?start"`)

// loaderCmdRE matches a hook/task command that invokes one of the worm's
// loader/payload files (e.g. `node .claude/setup.mjs`, `node
// .vscode/setup.mjs`, `bun execution.js`). Built at init from the IoC
// corpus so the loader-name set has a single source of truth. A
// folderOpen task or SessionStart hook whose command references one of
// these is the Mini Shai-Hulud IDE-persistence wiring, not a
// developer-authored build task.
var loaderCmdRE = func() *regexp.Regexp {
	names := make([]string, 0, len(ioc.IDELoaderFileNames))
	for n := range ioc.IDELoaderFileNames {
		names = append(names, regexp.QuoteMeta(n))
	}
	sort.Strings(names) // deterministic alternation order
	return regexp.MustCompile(strings.Join(names, "|"))
}()

func checkIDEPersistence(snap *Snapshot, homeDir string, r *report.Reporter) {
	r.Section(sectionIDE, "The Mini Shai-Hulud worm (May 2026) persists by committing a VS Code `tasks.json` `runOn: folderOpen` task and a Claude `settings.json` `SessionStart` hook that each re-run a loader (`node .claude/setup.mjs` / `node .vscode/setup.mjs`) on folder-open / session-start, plus the loader+payload pair (`setup.mjs` + `execution.js`) inside the project's `.claude/` and `.vscode/` directories. We flag a folder-open task or session-start hook as a high-confidence hit only when its command invokes a known loader; a configured-but-unattributed auto-run is reported separately for manual review. Sources: Phoenix Security, StepSecurity, Picus, Microsoft (May 2026).")

	checkFolderOpenTasks(snap, r)
	checkSessionStartHooks(snap, homeDir, r)
	checkLoaderDrops(snap, r)
}

// checkFolderOpenTasks inspects every discovered tasks.json for a
// `runOn: folderOpen` auto-run, separating the worm signature (the task
// command invokes a known loader) from a benign-but-noteworthy
// folder-open task (a developer build/watch task) that only warrants a
// glance.
func checkFolderOpenTasks(snap *Snapshot, r *report.Reporter) {
	if len(snap.TasksJSON) == 0 {
		r.Clean(sectionIDE, "No `tasks.json` files found in walked tree")
		return
	}
	var wormHits, reviewHits []string
	for _, f := range snap.TasksJSON {
		if fsutil.IsDataless(f) {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- scanner inspects discovered tasks.json files
		if err != nil {
			continue
		}
		if !runOnFolderOpenRE.Match(data) {
			continue
		}
		if loaderCmdRE.Match(data) {
			wormHits = append(wormHits, f)
		} else {
			reviewHits = append(reviewHits, f)
		}
	}
	sort.Strings(wormHits)
	sort.Strings(reviewHits)

	if len(wormHits) == 0 && len(reviewHits) == 0 {
		r.Clean(sectionIDE, fmt.Sprintf("No `tasks.json` (of %d inspected) runs a task on `folderOpen`", len(snap.TasksJSON)))
		return
	}
	if len(wormHits) > 0 {
		r.Hit(sectionIDE,
			fmt.Sprintf("%d `tasks.json` file(s) run a known loader (`setup.mjs` / `execution.js` / `bun_environment.js`) on `folderOpen` — matches Mini Shai-Hulud IDE persistence", len(wormHits)),
			strings.Join(wormHits, "\n"))
	}
	if len(reviewHits) > 0 {
		r.Hit(sectionIDE,
			fmt.Sprintf("%d `tasks.json` file(s) run a task on `folderOpen` but reference no known loader — likely a developer build task; confirm you authored it", len(reviewHits)),
			strings.Join(reviewHits, "\n"))
	}
}

// checkSessionStartHooks inspects every `.claude/settings.json` found in
// the walked tree (home config + any repo checkout) for a SessionStart
// hook. File contents are NEVER embedded in the report — settings.json
// can hold MCP tokens / API keys / env vars, and the scanner's headline
// promise is "no secret value is captured." A hook whose command invokes
// a known loader is the worm signature; a hook that does not is reported
// for manual confirmation.
func checkSessionStartHooks(snap *Snapshot, homeDir string, r *report.Reporter) {
	const claudeSettingsMax = 256 * 1024 // 256 KiB cap; legit Claude config is well under this

	// Union of discovered `.claude/settings.json` files with the user's
	// home settings path — the walk always covers $HOME, but include it
	// explicitly so the home check never depends on walk timing.
	paths := append([]string(nil), snap.ClaudeSettings...)
	paths = append(paths, filepath.Join(homeDir, ".claude", "settings.json"))
	paths = dedupSlice(paths)
	sort.Strings(paths)

	var wormHits, reviewHits []string
	inspected := 0
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if fsutil.IsDataless(path) {
			r.Skipped(sectionIDE, fmt.Sprintf("`%s` is a cloud placeholder (dataless) — skipped to avoid download", path))
			continue
		}
		if info.Size() > claudeSettingsMax {
			r.Skipped(sectionIDE, fmt.Sprintf("`%s` is %s (over the %dKiB inspection cap) — skipped", path, humanSize(info.Size()), claudeSettingsMax/1024))
			continue
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- scanner reads user-configured settings file
		if readErr != nil {
			r.Skipped(sectionIDE, fmt.Sprintf("could not read `%s`: %v", path, readErr))
			continue
		}
		inspected++
		if !sessionStartRE.Match(data) {
			continue
		}
		if loaderCmdRE.Match(data) {
			wormHits = append(wormHits, path)
		} else {
			reviewHits = append(reviewHits, path)
		}
	}
	sort.Strings(wormHits)
	sort.Strings(reviewHits)

	if inspected == 0 {
		r.Clean(sectionIDE, "No `.claude/settings.json` files present (home config or any repo checkout)")
		return
	}
	if len(wormHits) == 0 && len(reviewHits) == 0 {
		r.Clean(sectionIDE, fmt.Sprintf("No `.claude/settings.json` (of %d inspected) contains a `SessionStart` hook", inspected))
		return
	}
	if len(wormHits) > 0 {
		r.Hit(sectionIDE,
			fmt.Sprintf("%d `.claude/settings.json` file(s) have a `SessionStart` hook that runs a known loader (`setup.mjs` / `execution.js`) — matches Mini Shai-Hulud IDE persistence", len(wormHits)),
			strings.Join(wormHits, "\n")+"\n(hook contents redacted — settings.json may contain MCP tokens or API keys)")
	}
	if len(reviewHits) > 0 {
		r.Hit(sectionIDE,
			fmt.Sprintf("%d `.claude/settings.json` file(s) have a `SessionStart` hook that references no known loader — open each and verify the hook is one you configured yourself", len(reviewHits)),
			strings.Join(reviewHits, "\n")+"\n(hook contents redacted — settings.json may contain MCP tokens or API keys)")
	}
}

// checkLoaderDrops reports the worm's loader/payload files
// (`setup.mjs` / `execution.js` / `bun_environment.js`) found directly
// inside a `.claude/` or `.vscode/` directory. A directory holding the
// full `setup.mjs` + `execution.js` pair is the highest-confidence
// signal (a legitimate Claude/VS Code config dir contains neither a Bun
// loader nor an `execution.js`), so those directories are called out.
func checkLoaderDrops(snap *Snapshot, r *report.Reporter) {
	if len(snap.IDELoaderDrops) == 0 {
		r.Clean(sectionIDE, "No worm loader/payload files (`setup.mjs` / `execution.js` / `bun_environment.js`) inside any `.claude/` or `.vscode/` directory")
		return
	}

	// Group basenames by directory so we can flag the setup.mjs +
	// execution.js pair that the worm always drops together.
	byDir := make(map[string]map[string]bool)
	for _, f := range snap.IDELoaderDrops {
		dir := filepath.Dir(f)
		if byDir[dir] == nil {
			byDir[dir] = make(map[string]bool)
		}
		byDir[dir][filepath.Base(f)] = true
	}

	drops := append([]string(nil), snap.IDELoaderDrops...)
	sort.Strings(drops)

	var ev strings.Builder
	pairs := 0
	for _, f := range drops {
		names := byDir[filepath.Dir(f)]
		if names["setup.mjs"] && names["execution.js"] {
			fmt.Fprintf(&ev, "%s  *** setup.mjs + execution.js PAIR — Mini Shai-Hulud drop ***\n", f)
		} else {
			fmt.Fprintf(&ev, "%s\n", f)
		}
	}
	for _, names := range byDir {
		if names["setup.mjs"] && names["execution.js"] {
			pairs++
		}
	}

	msg := fmt.Sprintf("Found %d worm loader/payload file(s) inside `.claude/` or `.vscode/` directories — these are not legitimate Claude/VS Code config files", len(drops))
	if pairs > 0 {
		msg = fmt.Sprintf("Found the Mini Shai-Hulud `setup.mjs` + `execution.js` drop in %d director(ies) (%d loader/payload file(s) total) — this host has a compromised repo checked out", pairs, len(drops))
	}
	r.Hit(sectionIDE, msg, ev.String())
}

// --- §3, §4, §7 content matches ---------------------------------------------

// recordContentMatches takes the output of ContentScanner.ScanFiles and
// emits §3/§4/§7 findings. We separate high-signal from low-signal so
// the report mirrors the bash layout.
func recordContentMatches(matches []ContentMatch, r *report.Reporter) {
	r.Section(sectionContentHigh, "These strings only legitimately appear in Shai-Hulud / Sha1-Hulud / TeamPCP malware source or in security-research write-ups. A hit on this host is meaningful unless it traces to a research / IoC-list file you downloaded.")
	r.Section(sectionContentLow, "These can appear in legitimate research-paper PDFs, blog posts, IR-report drafts, or other awareness materials. A hit is not automatic compromise — it's a flag for human review.")
	r.Section(sectionTokens, "Plaintext GitHub-token patterns (`ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_`). Any hit means a token is at risk of harvesting by an infostealer. Token-tail bytes are redacted in this report.")

	var highFiles, lowFiles, tokenFiles []ContentMatch
	for _, m := range matches {
		hasHigh, hasLow := false, false
		for _, h := range m.StringMatches {
			if h.LowSignal {
				hasLow = true
			} else {
				hasHigh = true
			}
		}
		if hasHigh {
			highFiles = append(highFiles, m)
		}
		if hasLow {
			lowFiles = append(lowFiles, m)
		}
		if len(m.TokenMatches) > 0 {
			tokenFiles = append(tokenFiles, m)
		}
	}

	// Sort each bucket by path so two runs against an unchanged host
	// produce byte-identical reports (enables diff-based triage).
	sortByPath := func(s []ContentMatch) {
		sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
	}
	sortByPath(highFiles)
	sortByPath(lowFiles)
	sortByPath(tokenFiles)

	if len(highFiles) == 0 {
		r.Clean(sectionContentHigh, "No high-signal IoC strings found in any framework-target directory or discovered repo")
	} else {
		var ev strings.Builder
		for _, m := range highFiles {
			fmt.Fprintf(&ev, "%s\n", m.Path)
			for _, h := range m.StringMatches {
				if h.LowSignal {
					continue
				}
				fmt.Fprintf(&ev, "  [%s] %s\n", h.IoC, h.Line)
			}
		}
		r.Hit(sectionContentHigh,
			fmt.Sprintf("Found %d file(s) containing high-signal IoC strings — investigate each", len(highFiles)),
			ev.String())
	}

	if len(lowFiles) == 0 {
		r.Clean(sectionContentLow, "No lower-signal IoC strings found")
	} else {
		var ev strings.Builder
		for _, m := range lowFiles {
			fmt.Fprintf(&ev, "%s\n", m.Path)
			for _, h := range m.StringMatches {
				if !h.LowSignal {
					continue
				}
				fmt.Fprintf(&ev, "  [%s] %s\n", h.IoC, h.Line)
			}
		}
		r.Hit(sectionContentLow,
			fmt.Sprintf("Found %d file(s) containing lower-signal IoC strings — manual review (likely awareness materials)", len(lowFiles)),
			ev.String())
	}

	if len(tokenFiles) == 0 {
		r.Clean(sectionTokens, "No `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` token patterns found in scanned paths")
	} else {
		var ev strings.Builder
		for _, m := range tokenFiles {
			fmt.Fprintf(&ev, "%s\n", m.Path)
			for _, t := range m.TokenMatches {
				fmt.Fprintf(&ev, "  %s\n", t)
			}
		}
		r.Hit(sectionTokens,
			fmt.Sprintf("Plaintext GitHub-token patterns found on disk in %d file(s) — manual review required", len(tokenFiles)),
			ev.String())
	}
}

// --- §5 network IoCs --------------------------------------------------------

// netNeedles is the union of every domain + IP IoC. netRE is its compiled
// alternation with dots escaped so they match literal `.`. Built at
// package init from the IoC corpus so it isn't rebuilt per scan.
var (
	netNeedles []string
	netRE      *regexp.Regexp
)

func init() {
	netNeedles = append(netNeedles, ioc.AllDomains()...)
	netNeedles = append(netNeedles, ioc.IPs...)
	parts := make([]string, len(netNeedles))
	for i, t := range netNeedles {
		parts[i] = regexp.QuoteMeta(t)
	}
	netRE = regexp.MustCompile(strings.Join(parts, "|"))
}

func checkNetwork(ctx context.Context, homeDir string, r *report.Reporter) {
	r.Section(sectionNetwork, "")

	// /etc/hosts
	if data, err := os.ReadFile("/etc/hosts"); err == nil {
		if locs := netRE.FindAllIndex(data, -1); locs != nil {
			var ev strings.Builder
			for _, loc := range locs {
				fmt.Fprintf(&ev, "%s\n", extractLine(data, loc[0]))
			}
			r.Hit(sectionNetwork, "Network IoC found in `/etc/hosts`", ev.String())
		} else {
			r.Clean(sectionNetwork, "No IoC domains or IPs in `/etc/hosts`")
		}
	} else {
		r.Skipped(sectionNetwork, fmt.Sprintf("could not read /etc/hosts: %v", err))
	}

	// dscacheutil DNS cache. On macOS Sonoma+ this command returns no
	// entries by design (the resolver moved); treat empty output as a
	// skip rather than as a clean signal so we don't mask the gap.
	if runtime.GOOS == "darwin" {
		cctx, cancel := withTimeout(ctx, 5)
		defer cancel()
		out, err := exec.CommandContext(cctx, "dscacheutil", "-q", "host").CombinedOutput() // #nosec G204 -- fixed argv, no user input
		switch {
		case err != nil:
			r.Skipped(sectionNetwork, fmt.Sprintf("dscacheutil failed: %v", err))
		case len(bytes.TrimSpace(out)) == 0:
			r.Skipped(sectionNetwork, "`dscacheutil -q host` returned no entries (macOS Sonoma+ no longer exposes the DNS cache here); check skipped")
		default:
			if locs := netRE.FindAllIndex(out, -1); locs != nil {
				var ev strings.Builder
				for _, loc := range locs {
					fmt.Fprintf(&ev, "%s\n", extractLine(out, loc[0]))
				}
				r.Hit(sectionNetwork, "DNS cache contains an IoC entry", ev.String())
			} else {
				r.Clean(sectionNetwork, "No IoC domains or IPs in current DNS cache")
			}
		}
	}

	// Browser histories (Chromium-family + Safari + Firefox) — exec sqlite3
	// per DB. Failures are logged as skipped rather than treated as clean,
	// since "no sqlite3" or "locked DB" would otherwise pass silently.
	checkBrowserHistories(ctx, homeDir, netNeedles, r)
}

func checkBrowserHistories(ctx context.Context, homeDir string, needles []string, r *report.Reporter) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		r.Skipped(sectionNetwork, "`sqlite3` not in PATH — browser history not inspected")
		return
	}

	whereChrome := buildURLWhereClause(needles)
	whereSafari := whereChrome // schema differs only in table/column names

	dbs := make([]string, 0, len(ioc.BrowserHistoryDBs)+2)
	for _, p := range ioc.BrowserHistoryDBs {
		dbs = append(dbs, strings.ReplaceAll(p, "{HOME}", homeDir))
	}
	dbs = append(dbs, strings.ReplaceAll(ioc.SafariHistoryDB, "{HOME}", homeDir))
	// Firefox profile glob
	firefoxGlob := strings.ReplaceAll(ioc.FirefoxProfilesGlob, "{HOME}", homeDir)
	if matches, _ := filepath.Glob(firefoxGlob); len(matches) > 0 {
		dbs = append(dbs, matches...)
	}

	for _, db := range dbs {
		if _, err := os.Lstat(db); err != nil {
			continue
		}
		if fsutil.IsDataless(db) {
			r.Skipped(sectionNetwork, fmt.Sprintf("browser DB is dataless: `%s`", db))
			continue
		}

		var query string
		label := filepath.Base(filepath.Dir(db))
		switch {
		case strings.Contains(db, "Safari/History.db"):
			query = fmt.Sprintf("SELECT url FROM history_items WHERE %s LIMIT 50;", whereSafari)
			label = "Safari"
		case strings.HasSuffix(db, "places.sqlite"):
			query = fmt.Sprintf("SELECT url FROM moz_places WHERE %s LIMIT 50;", whereChrome)
			label = "Firefox " + filepath.Base(filepath.Dir(db))
		default:
			query = fmt.Sprintf(
				"SELECT url, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls WHERE %s LIMIT 50;",
				whereChrome,
			)
		}

		cctx, cancel := withTimeout(ctx, 10)
		out, err := exec.CommandContext(cctx, "sqlite3", "-readonly", db, query).Output() // #nosec G204 -- needles are package-level corpus literals, not user input
		cancel()
		if err != nil {
			// Locked DB is the common failure mode on macOS. Don't treat
			// as a hit; report as skipped so the operator knows.
			r.Skipped(sectionNetwork, fmt.Sprintf("could not query %s history (%s): %v", label, db, err))
			continue
		}
		if len(bytes.TrimSpace(out)) > 0 {
			r.Hit(sectionNetwork, fmt.Sprintf("IoC URL found in %s history", label), string(out))
		} else {
			r.Clean(sectionNetwork, fmt.Sprintf("No IoC URLs in %s history", label))
		}
	}
}

func buildURLWhereClause(needles []string) string {
	parts := make([]string, len(needles))
	for i, n := range needles {
		escaped := strings.ReplaceAll(n, "'", "''")
		parts[i] = fmt.Sprintf("url LIKE '%%%s%%'", escaped)
	}
	return strings.Join(parts, " OR ")
}

// --- §6 credentials presence ------------------------------------------------

func checkCredentials(homeDir string, r *report.Reporter) {
	r.Section(sectionCreds, "Files below are what the framework's FileSystemService scans on a host. We are NOT dumping contents — just recording presence, mtime, and size so you can correlate against expected state.")

	var ev strings.Builder
	for _, p := range ioc.CredentialTargets {
		full := strings.ReplaceAll(p, "{HOME}", homeDir)
		info, err := os.Lstat(full)
		if err != nil {
			fmt.Fprintf(&ev, "(not present)  %s\n", full)
			continue
		}
		fmt.Fprintf(&ev, "%s  %s\n",
			info.ModTime().Format("2006-01-02 15:04:05"),
			full+"  ("+humanSize(info.Size())+", "+info.Mode().String()+")")
	}
	r.Add(report.Finding{
		Section:  sectionCreds,
		Status:   report.StatusInfo,
		Message:  "Credential-target presence captured (informational — does not affect hit count):",
		Evidence: ev.String(),
	})
}

// --- §6b bundle.js hash -----------------------------------------------------

// maxBundleHashSize caps the per-file read for payload hashing. The V1
// `bundle.js` payload was <1 MiB and the Sha1-Hulud V2 `bun_environment.js`
// is ~10 MiB — this 50 MiB bound exists only to keep a runaway node_modules
// with multi-GiB files from blocking the scan.
const maxBundleHashSize = 50 * 1024 * 1024

type bundleHashResult struct {
	path string
	hash string
	bad  bool
	skip string // "" for success, otherwise reason: dataless / too-large / stat-failed / open-failed / io-failed / canceled
}

func checkBundleHashes(ctx context.Context, d *Discovery, snap *Snapshot, r *report.Reporter) {
	r.Section(sectionBundle, "Shai-Hulud V1's payload was published as `bundle.js` inside compromised npm packages; the Sha1-Hulud / V2 (Nov 2025) worm injects `setup_bun.js` and `bun_environment.js` via a `preinstall` script. If any of these on this host hashes to a known-bad SHA-256 (Wiz / Checkmarx for V1; Datadog Security Labs for V2), that wave's payload was installed at some point.")

	candidates := filterBundleCandidates(snap.PayloadCandidates, snap.NodeModules)
	for _, p := range snap.PayloadCandidates {
		dir := filepath.Dir(p)
		if dir == "/tmp" || dir == "/var/tmp" || dir == "/private/tmp" || dir == "/private/var/tmp" {
			candidates = append(candidates, p)
		}
	}
	candidates = dedupSlice(candidates)
	sort.Strings(candidates)

	if len(candidates) == 0 {
		r.Clean(sectionBundle, "No `bundle.js` / `setup_bun.js` / `bun_environment.js` files found in node_modules trees or /tmp")
		return
	}

	allHashes := ioc.AllPayloadHashes()
	known := make(map[string]bool, len(allHashes))
	for _, h := range allHashes {
		known[h] = true
	}

	results := hashBundlesParallel(ctx, candidates, known, max(2, runtime.NumCPU()/2))
	// Sort by path so the evidence block in the report is stable
	// run-to-run (worker completion order is non-deterministic).
	sort.Slice(results, func(i, j int) bool { return results[i].path < results[j].path })

	var ev strings.Builder
	bad, hashed, skippedDataless, skippedOther := 0, 0, 0, 0
	fmt.Fprintf(&ev, "Inspecting %d candidate file(s)...\n\n", len(candidates))
	for _, res := range results {
		switch res.skip {
		case "dataless":
			fmt.Fprintf(&ev, "(dataless — content not on disk, not hashed)  %s\n", res.path)
			skippedDataless++
		case "too-large":
			fmt.Fprintf(&ev, "(>%dMiB — skipped)  %s\n", maxBundleHashSize/(1024*1024), res.path)
			skippedOther++
		case "":
			if res.bad {
				fmt.Fprintf(&ev, "%s  %s  *** MATCHES KNOWN-MALICIOUS PAYLOAD HASH ***\n", res.hash, res.path)
				bad++
				d.BundlesBad.Add(1)
			} else {
				fmt.Fprintf(&ev, "%s  %s\n", res.hash, res.path)
			}
			hashed++
			d.BundlesHashed.Add(1)
		default:
			// stat-failed / open-failed / io-failed / canceled
			fmt.Fprintf(&ev, "(%s)  %s\n", res.skip, res.path)
			skippedOther++
		}
	}

	switch {
	case bad > 0:
		r.Hit(sectionBundle, fmt.Sprintf("Found %d payload file(s) matching a known-malicious Shai-Hulud / Sha1-Hulud SHA-256", bad), ev.String())
	case skippedDataless > 0 || skippedOther > 0:
		r.Clean(sectionBundle, fmt.Sprintf("%d payload file(s) hashed, none match known V1/V2 hashes; %d dataless + %d other skip(s)", hashed, skippedDataless, skippedOther))
	default:
		r.Clean(sectionBundle, fmt.Sprintf("%d payload file(s) inspected, none match known V1/V2 hashes", hashed))
	}
}

// hashBundlesParallel runs the SHA-256 over every candidate using a
// bounded worker pool, with three guarantees:
//
//  1. Every input emits exactly one result (worker error paths return a
//     bundleHashResult with a non-empty `skip` field).
//  2. Context cancellation is propagated to both producer and workers
//     without deadlock — the producer abandons un-sent items via a
//     select on ctx.Done(); workers continue draining `in` after
//     cancellation but skip work, ensuring the producer never blocks on
//     `in <- p`.
//  3. `out` is closed only after every worker has returned, so the
//     receiver can use `for ... range out` and terminate cleanly.
func hashBundlesParallel(ctx context.Context, candidates []string, known map[string]bool, conc int) []bundleHashResult {
	in := make(chan string, conc*2)
	out := make(chan bundleHashResult, conc*2)
	var wg sync.WaitGroup

	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range in {
				out <- hashOneBundle(ctx, p, known)
			}
		}()
	}

	go func() {
		defer close(in)
		for _, p := range candidates {
			select {
			case <-ctx.Done():
				return
			case in <- p:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	results := make([]bundleHashResult, 0, len(candidates))
	for r := range out {
		results = append(results, r)
	}
	return results
}

// hashOneBundle performs the per-file inspection. It always returns a
// result; on cancellation or any I/O error it sets `skip` to a label
// the caller can record in the evidence.
func hashOneBundle(ctx context.Context, p string, known map[string]bool) bundleHashResult {
	if ctx.Err() != nil {
		return bundleHashResult{path: p, skip: "canceled"}
	}
	if fsutil.IsDataless(p) {
		return bundleHashResult{path: p, skip: "dataless"}
	}
	info, err := os.Lstat(p)
	if err != nil {
		return bundleHashResult{path: p, skip: "stat-failed"}
	}
	if !info.Mode().IsRegular() {
		return bundleHashResult{path: p, skip: "not-regular"}
	}
	if info.Size() > maxBundleHashSize {
		return bundleHashResult{path: p, skip: "too-large"}
	}
	f, err := os.Open(p) // #nosec G304 -- bundle.js hashing reads discovered npm payload files
	if err != nil {
		return bundleHashResult{path: p, skip: "open-failed"}
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return bundleHashResult{path: p, skip: "io-failed"}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return bundleHashResult{path: p, hash: sum, bad: known[sum]}
}

func filterBundleCandidates(all, nodeModules []string) []string {
	if len(nodeModules) == 0 {
		return nil
	}
	prefixes := make([]string, len(nodeModules))
	for i, p := range nodeModules {
		prefixes[i] = p + string(filepath.Separator)
	}
	var out []string
	for _, p := range all {
		for _, pre := range prefixes {
			if strings.HasPrefix(p, pre) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// --- §6c workflow files -----------------------------------------------------

func checkShaiWorkflows(snap *Snapshot, r *report.Reporter) {
	r.Section(sectionWorkflow, "Shai-Hulud V1 plants a GitHub Actions workflow named `shai-hulud-workflow.yml` in repositories it compromises. Presence of this file in any local clone on this host indicates a previously-compromised repo was checked out (and may still carry the payload).")
	if len(snap.ShaiWorkflowYML) == 0 {
		r.Clean(sectionWorkflow, "No `shai-hulud-workflow.yml` files found in any `.github/workflows/` directory under any walked root")
		return
	}
	r.Hit(sectionWorkflow,
		fmt.Sprintf("Found %d `shai-hulud-workflow.yml` file(s) in local repos — these clones carry the V1 payload", len(snap.ShaiWorkflowYML)),
		strings.Join(snap.ShaiWorkflowYML, "\n"))
}

// --- §6d PyPI durabletask ---------------------------------------------------

func checkPyPI(homeDir string, snap *Snapshot, r *report.Reporter) {
	r.Section(sectionPyPI, "TeamPCP compromised Microsoft's official `durabletask` PyPI package and published malicious versions `1.4.1`, `1.4.2`, `1.4.3` (Wiz / The Hacker News, 2026-05-20). Any environment that installed one of these versions executed the dropper at import time. The infostealer payload's Linux-only execution branch means macOS hosts that installed it were not stealer-impacted, but the malicious package on disk is still a finding. Detection is purely on-disk — wormsign never invokes a Python interpreter or `pip`.")

	// Installed durabletask, detected from on-disk package metadata.
	checkInstalledDurabletask(homeDir, snap, r)
	// Requirements/lock files anywhere in the walked tree
	checkPyRequirements(snap, r)
	// rope.pyz second-stage payload presence
	if len(snap.RopePYZ) == 0 {
		r.Clean(sectionPyPI, "No `rope.pyz` files found under any walked root")
	} else {
		sortedRope := append([]string(nil), snap.RopePYZ...)
		sort.Strings(sortedRope)
		r.Hit(sectionPyPI,
			fmt.Sprintf("Found %d `rope.pyz` file(s) — TeamPCP second-stage payload", len(sortedRope)),
			strings.Join(sortedRope, "\n"))
	}
}

// durabletaskDistRE matches a pip/wheel-installed durabletask metadata
// directory — `durabletask-<version>.dist-info` (modern wheels) or
// `durabletask-<version>.egg-info` (legacy) — capturing the version.
// The leading `durabletask-` (hyphen, then a version) is what pip writes
// for the `durabletask` project specifically; sibling packages like
// `durabletask-azure` normalize to `durabletask_azure-...` (underscore),
// so this does not false-match them.
var durabletaskDistRE = regexp.MustCompile(`(?i)^durabletask-(.+?)\.(?:dist-info|egg-info)$`)

// isDurabletaskDistDir reports whether a directory entry name is the
// installed-package metadata dir for the durabletask project. The walker
// records matches into Discovery.DurabletaskDists.
func isDurabletaskDistDir(name string) bool {
	if name == "durabletask.egg-info" { // legacy unversioned egg-info
		return true
	}
	return durabletaskDistRE.MatchString(name)
}

// durabletaskSitePackageGlobs returns globs over the system site-packages
// locations the filesystem walk does NOT descend into (the walk already
// covers $HOME venvs/pyenv/conda and /opt homebrew). Bounded, no
// recursion — each pattern resolves a metadata dir directly.
func durabletaskSitePackageGlobs(homeDir string) []string {
	sitePackages := []string{
		"/usr/local/lib/python*/site-packages",
		"/usr/local/lib/python*/dist-packages",
		"/opt/homebrew/lib/python*/site-packages",
		"/Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages",
		filepath.Join(homeDir, "Library/Python/*/lib/python/site-packages"), // pip --user
	}
	out := make([]string, 0, len(sitePackages)*3)
	for _, sp := range sitePackages {
		out = append(out,
			filepath.Join(sp, "durabletask-*.dist-info"),
			filepath.Join(sp, "durabletask-*.egg-info"),
			filepath.Join(sp, "durabletask.egg-info"),
		)
	}
	return out
}

// checkInstalledDurabletask reports whether a malicious durabletask
// version is installed on disk WITHOUT executing any Python interpreter,
// pip, or other discovered binary. It locates the package's installed
// metadata directory (`durabletask-<version>.dist-info`, written by
// pip/wheel) from two sources:
//
//   - directories the filesystem walk already discovered under the
//     configured roots (covers venvs / pyenv / conda / homebrew under
//     $HOME and /opt), and
//   - a bounded glob over the system site-packages locations the walk
//     does not descend into (/usr/local, Python.framework, pip --user).
//
// The installed version is read from the dist-info directory name, with
// a fallback to the METADATA / PKG-INFO `Version:` field.
func checkInstalledDurabletask(homeDir string, snap *Snapshot, r *report.Reporter) {
	bad := make(map[string]bool, len(ioc.BadDurabletaskVersions))
	for _, v := range ioc.BadDurabletaskVersions {
		bad[v] = true
	}

	dists := append([]string(nil), snap.DurabletaskDists...)
	for _, pat := range durabletaskSitePackageGlobs(homeDir) {
		if m, _ := filepath.Glob(pat); len(m) > 0 {
			dists = append(dists, m...)
		}
	}
	dists = dedupSlice(dists)
	sort.Strings(dists) // stable evidence ordering run-to-run

	if len(dists) == 0 {
		r.Clean(sectionPyPI, "No `durabletask` package metadata found on disk (no `durabletask-*.dist-info` in any walked tree or common site-packages location)")
		return
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "durabletask installations found on disk: %d\n\n", len(dists))
	var hits []string
	for _, dir := range dists {
		ver := durabletaskInstalledVersion(dir)
		if ver == "" {
			fmt.Fprintf(&ev, "%s: durabletask (version undetermined)\n", dir)
			continue
		}
		marker := ""
		if bad[ver] {
			marker = "  *** MALICIOUS VERSION ***"
			hits = append(hits, fmt.Sprintf("%s -> durabletask %s", dir, ver))
		}
		fmt.Fprintf(&ev, "%s: durabletask %s%s\n", dir, ver, marker)
	}
	sort.Strings(hits)

	if len(hits) > 0 {
		r.Hit(sectionPyPI, "Malicious `durabletask` version installed on disk", ev.String()+"\n"+strings.Join(hits, "\n"))
	} else {
		r.Clean(sectionPyPI, "No malicious `durabletask` versions installed on disk in any detected location")
		r.Add(report.Finding{
			Section:  sectionPyPI,
			Status:   report.StatusInfo,
			Message:  "Installed durabletask metadata directories:",
			Evidence: ev.String(),
		})
	}
}

// durabletaskInstalledVersion derives the installed durabletask version
// from a dist-info / egg-info directory. It prefers the version embedded
// in the directory name (pip's canonical layout — no I/O), falling back
// to the `Version:` field of METADATA (dist-info) or PKG-INFO
// (egg-info). Dataless placeholders are skipped; no subprocess is run.
func durabletaskInstalledVersion(distDir string) string {
	if m := durabletaskDistRE.FindStringSubmatch(filepath.Base(distDir)); m != nil && m[1] != "" {
		return m[1]
	}
	for _, meta := range []string{"METADATA", "PKG-INFO"} {
		p := filepath.Join(distDir, meta)
		if fsutil.IsDataless(p) {
			continue
		}
		data, err := os.ReadFile(p) // #nosec G304 -- reads package metadata in a discovered durabletask dist-info dir
		if err != nil {
			continue
		}
		if v := extractMetadataVersion(data); v != "" {
			return v
		}
	}
	return ""
}

// extractMetadataVersion pulls the `Version:` field out of a Python
// package metadata file (dist-info METADATA / egg-info PKG-INFO — both
// RFC822-style). Tolerates CRLF and scans every line so a leading
// header (e.g. `Metadata-Version:`) doesn't shadow it.
func extractMetadataVersion(out []byte) string {
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return ""
}

// Regexes for §6d durabletask requirements scanning. Compiled once at
// package init from the IoC corpus; reused across every scan run.
var (
	durabletaskNameRE = regexp.MustCompile(`(?m)(?:^|[^A-Za-z0-9_-])durabletask([^A-Za-z0-9_-]|$)`)
	durabletaskPinRE  *regexp.Regexp
	durabletaskLockRE *regexp.Regexp
)

func init() {
	versionAlt := strings.Join(ioc.BadDurabletaskVersions, "|")
	durabletaskPinRE = regexp.MustCompile(`durabletask[ \t]*(?:==|=|@|:|>=|~=)[ \t]*["'(]?(` + versionAlt + `)`)
	durabletaskLockRE = regexp.MustCompile(`version[ \t]*=[ \t]*["'](` + versionAlt + `)["']`)
}

func checkPyRequirements(snap *Snapshot, r *report.Reporter) {
	if len(snap.RequirementsFiles) == 0 {
		r.Clean(sectionPyPI, "No Python requirements/lock files in walked tree")
		return
	}

	var hits []string
	for _, f := range snap.RequirementsFiles {
		if fsutil.IsDataless(f) {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- scanner inspects discovered Python requirements files
		if err != nil {
			continue
		}
		if !durabletaskNameRE.Match(data) {
			continue
		}
		if loc := durabletaskPinRE.FindSubmatchIndex(data); loc != nil {
			ver := string(data[loc[2]:loc[3]])
			hits = append(hits, fmt.Sprintf("%s: pins durabletask %s", f, ver))
			continue
		}
		// poetry/uv style: check name + lockVer co-occur
		if loc := durabletaskLockRE.FindSubmatchIndex(data); loc != nil {
			ver := string(data[loc[2]:loc[3]])
			hits = append(hits, fmt.Sprintf("%s: lock file pins durabletask %s", f, ver))
		}
	}
	sort.Strings(hits)
	if len(hits) == 0 {
		r.Clean(sectionPyPI, fmt.Sprintf("No requirements/lock files in walked tree (%d inspected) pin `durabletask` to 1.4.1, 1.4.2, or 1.4.3", len(snap.RequirementsFiles)))
	} else {
		r.Hit(sectionPyPI, "Requirements/lock file(s) pin `durabletask` to a malicious version", strings.Join(hits, "\n"))
	}
}

// --- helpers ----------------------------------------------------------------

func dedupSlice(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
