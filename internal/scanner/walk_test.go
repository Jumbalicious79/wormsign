package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// helpers used across scanner_test.go too — defined here.

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir parent of %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestWalkFindsRepoAndNodeModules plants the canonical Shai-Hulud
// indicators (a .git directory, a node_modules tree with bundle.js,
// and a shai-hulud-workflow.yml) and checks the walker records all of
// them.
func TestWalkFindsRepoAndNodeModules(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	mustMkdir(t, filepath.Join(repo, ".git"))
	mustMkdir(t, filepath.Join(repo, ".github", "workflows"))
	mustMkdir(t, filepath.Join(repo, "node_modules", "pkg"))
	mustWrite(t, filepath.Join(repo, "node_modules", "pkg", "bundle.js"), "// payload")
	mustWrite(t, filepath.Join(repo, ".github", "workflows", "shai-hulud-workflow.yml"), "name: shai-hulud")
	mustWrite(t, filepath.Join(repo, "requirements.txt"), "durabletask==1.4.2")

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:       []string{root},
		concurrency: 2,
	})

	if got := d.ReposCount(); got != 1 {
		t.Errorf("ReposCount: got %d, want 1 (repos: %v)", got, d.Repos)
	}
	if got := d.NodeModulesCount(); got != 1 {
		t.Errorf("NodeModulesCount: got %d, want 1", got)
	}
	if len(d.PayloadCandidates) != 1 {
		t.Errorf("PayloadCandidates: got %d, want 1", len(d.PayloadCandidates))
	}
	if len(d.ShaiWorkflowYML) != 1 {
		t.Errorf("ShaiWorkflowYML: got %d, want 1", len(d.ShaiWorkflowYML))
	}
	if len(d.RequirementsFiles) == 0 {
		t.Error("RequirementsFiles should include requirements.txt")
	}
}

// TestWalkPrunesNoiseDirs verifies macOS metadata dirs are skipped so
// we don't waste time walking Spotlight indexes or Trash.
func TestWalkPrunesNoiseDirs(t *testing.T) {
	root := t.TempDir()
	for _, noisy := range []string{".Spotlight-V100", ".fseventsd", ".Trash"} {
		mustWrite(t, filepath.Join(root, noisy, "ignored.txt"), "should be skipped")
	}
	mustWrite(t, filepath.Join(root, "kept.txt"), "should be visited")

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:       []string{root},
		concurrency: 2,
	})

	if got := d.FilesVisited.Load(); got != 1 {
		t.Errorf("FilesVisited: got %d, want 1 (noisy dirs should be pruned)", got)
	}
}

// TestWalkDescendsIntoNodeModules is the project-defining behavior:
// sietch prunes node_modules but wormsign MUST walk into it because
// V1's bundle.js payload lives deep inside compromised npm packages.
func TestWalkDescendsIntoNodeModules(t *testing.T) {
	root := t.TempDir()
	deepBundle := filepath.Join(root, "repo", "node_modules", "@scope", "pkg",
		"node_modules", "nested", "node_modules", "deeper", "bundle.js")
	mustWrite(t, deepBundle, "// nested payload")
	mustMkdir(t, filepath.Join(root, "repo", ".git"))

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:       []string{root},
		concurrency: 4,
	})

	found := false
	for _, p := range d.PayloadCandidates {
		if p == deepBundle {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deeply nested bundle.js not discovered: %s\nfound: %v", deepBundle, d.PayloadCandidates)
	}
}

// TestWalkSkipsExcludedPaths — anything under excludePaths must not
// be entered.
func TestWalkSkipsExcludedPaths(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "skip", "secret.txt"), "x")
	mustWrite(t, filepath.Join(root, "keep.txt"), "y")

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:        []string{root},
		excludePaths: []string{filepath.Join(root, "skip")},
		concurrency:  2,
	})

	if got := d.FilesVisited.Load(); got != 1 {
		t.Errorf("FilesVisited: got %d, want 1 (excluded path should be skipped)", got)
	}
}

// TestWalkSkipsOutputFile verifies that a re-run with the same
// --output path doesn't pick up the prior report as a content-scan
// target (which would cause low-signal self-matches on every re-run).
func TestWalkSkipsOutputFile(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "report.md")
	mustWrite(t, output, "# prior wormsign report\nshai-hulud literal in here\n")
	// Force the file into the content-scan zone via a search-dir prefix
	// that covers it.
	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:           []string{root},
		searchDirPrefix: []string{root},
		outputPath:      output,
		concurrency:     2,
	})

	for _, p := range d.ContentScanQueue {
		if p == output {
			t.Errorf("output file %s should be excluded from content scan queue, but got: %v", output, d.ContentScanQueue)
		}
	}
}

// TestWalkRecordsPersistenceFiles — the walker stats a fixed set of
// exact-path persistence IoCs after the tree walk completes. Verify
// it records the ones that exist and omits the ones that don't.
func TestWalkRecordsPersistenceFiles(t *testing.T) {
	root := t.TempDir()
	present := filepath.Join(root, "persist1")
	mustWrite(t, present, "")
	missing := filepath.Join(root, "persist2")

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:          []string{root},
		persistenceSet: map[string]bool{present: true, missing: true},
		concurrency:    2,
	})

	if _, ok := d.PersistenceFiles[present]; !ok {
		t.Errorf("expected to record %s in PersistenceFiles, got: %v", present, d.PersistenceFiles)
	}
	if _, ok := d.PersistenceFiles[missing]; ok {
		t.Errorf("did not expect missing %s in PersistenceFiles", missing)
	}
}

// TestWalkClassifiesSha1HuludPayloads — Sha1-Hulud V2 (Nov 2025) injects
// `setup_bun.js` and `bun_environment.js` via a `preinstall` script in
// node_modules. The walker must classify these as PayloadCandidates so
// they get hashed against the Datadog V2 SHA-256 list, alongside V1's
// `bundle.js`.
func TestWalkClassifiesSha1HuludPayloads(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "repo", ".git"))
	setupBun := filepath.Join(root, "repo", "node_modules", "pkg", "setup_bun.js")
	bunEnv := filepath.Join(root, "repo", "node_modules", "pkg", "bun_environment.js")
	bundle := filepath.Join(root, "repo", "node_modules", "pkg", "bundle.js")
	mustWrite(t, setupBun, "// V2 dropper")
	mustWrite(t, bunEnv, "// V2 payload")
	mustWrite(t, bundle, "// V1 payload")

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		roots:       []string{root},
		concurrency: 2,
	})

	want := map[string]bool{setupBun: false, bunEnv: false, bundle: false}
	for _, p := range d.PayloadCandidates {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("PayloadCandidates missing %s — Sha1-Hulud V2 / V1 hashing won't fire", path)
		}
	}
}

// TestWalkClassifiesIDEPersistence pins the precise IDE-persistence
// classification: the walker collects worm loader/payload files and
// SessionStart-hook configs ONLY when their immediate parent directory
// is `.claude` or `.vscode`. Legitimate Claude Code plugin `.mjs` files
// nested deeper under `~/.claude/plugins/` (the original false-positive
// source) must be ignored.
func TestWalkClassifiesIDEPersistence(t *testing.T) {
	home := t.TempDir()

	// Worm drop: setup.mjs + execution.js in a repo's .claude dir, a
	// .vscode/setup.mjs, a .claude/settings.json hook, and a tasks.json.
	claudeSetup := filepath.Join(home, "repo", ".claude", "setup.mjs")
	claudeExec := filepath.Join(home, "repo", ".claude", "execution.js")
	claudeSettings := filepath.Join(home, "repo", ".claude", "settings.json")
	vscodeSetup := filepath.Join(home, "repo", ".vscode", "setup.mjs")
	tasksJSON := filepath.Join(home, "repo", ".vscode", "tasks.json")
	mustWrite(t, claudeSetup, "// loader")
	mustWrite(t, claudeExec, "// payload")
	mustWrite(t, claudeSettings, `{"hooks":{}}`)
	mustWrite(t, vscodeSetup, "// loader")
	mustWrite(t, tasksJSON, `{"version":"2.0.0"}`)

	// Legitimate plugin code nested under ~/.claude/plugins/ — parent dirs
	// are `bin` / `hooks`, NOT `.claude`, so these must NOT be collected.
	pluginMjs := filepath.Join(home, ".claude", "plugins", "cache", "x", "1.0.0", "bin", "postinstall.mjs")
	pluginHook := filepath.Join(home, ".claude", "plugins", "cache", "y", "2.0.0", "hooks", "session-start.mjs")
	mustWrite(t, pluginMjs, "export default {}")
	mustWrite(t, pluginHook, "export default {}")

	d := NewDiscovery()
	Walk(context.Background(), d, walkConfig{
		homeDir:     home,
		roots:       []string{home},
		concurrency: 2,
	})

	loaderSet := map[string]bool{}
	for _, p := range d.IDELoaderDrops {
		loaderSet[p] = true
	}
	for _, want := range []string{claudeSetup, claudeExec, vscodeSetup} {
		if !loaderSet[want] {
			t.Errorf("IDELoaderDrops missing worm drop %s", want)
		}
	}
	for _, unwanted := range []string{pluginMjs, pluginHook} {
		if loaderSet[unwanted] {
			t.Errorf("IDELoaderDrops wrongly flagged legitimate plugin file %s", unwanted)
		}
	}

	settingsSet := map[string]bool{}
	for _, p := range d.ClaudeSettings {
		settingsSet[p] = true
	}
	if !settingsSet[claudeSettings] {
		t.Errorf("ClaudeSettings missing %s", claudeSettings)
	}

	tasksSet := map[string]bool{}
	for _, p := range d.TasksJSON {
		tasksSet[p] = true
	}
	if !tasksSet[tasksJSON] {
		t.Errorf("TasksJSON missing %s", tasksJSON)
	}
}

// TestPruneDirHelper — defensive check that node_modules is NEVER
// pruned. If anyone adds it to the list by mistake, V1 bundle.js
// discovery silently breaks.
func TestPruneDirHelper(t *testing.T) {
	if pruneDir("node_modules") {
		t.Fatal("node_modules must NEVER be in pruneDir — V1 bundle.js detection depends on walking into it")
	}
	if !pruneDir(".Spotlight-V100") {
		t.Error(".Spotlight-V100 should be pruned")
	}
	if !pruneDir(".fseventsd") {
		t.Error(".fseventsd should be pruned")
	}
}

// TestHasPathPrefix — the root "/" special case must not produce
// false matches like "//etc/hosts" or miss legitimate children.
func TestHasPathPrefix(t *testing.T) {
	cases := []struct {
		path, base string
		want       bool
	}{
		{"/", "/", true},
		{"/etc/hosts", "/", true},
		{"/etc", "/etc", true},
		{"/etc/hosts", "/etc", true},
		{"/etcfoo/hosts", "/etc", false}, // not a /etc child
		{"/usr/local/bin", "/var", false},
	}
	for _, tc := range cases {
		got := hasPathPrefix(tc.path, tc.base)
		if got != tc.want {
			t.Errorf("hasPathPrefix(%q, %q): got %v, want %v", tc.path, tc.base, got, tc.want)
		}
	}
}
