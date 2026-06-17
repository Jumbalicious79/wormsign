package scanner

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Jumbalicious79/wormsign/internal/report"
)

// plantFixture builds a fixture tree with one of every Shai-Hulud
// indicator the scanner should fire on. Returns the root path.
func plantFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	mustMkdir(t, filepath.Join(repo, ".git"))
	mustMkdir(t, filepath.Join(repo, ".github", "workflows"))
	mustMkdir(t, filepath.Join(repo, "node_modules", "badpkg"))

	mustWrite(t, filepath.Join(repo, "note.txt"),
		"# A reference to Shai-Hulud Migration here\n")
	mustWrite(t, filepath.Join(repo, "node_modules", "badpkg", "bundle.js"),
		"// exfil to bb8ca5f6-4175-45d2-b042-fc9ebb8170b7\n")
	// Sha1-Hulud V2 (Nov 2025) payload pair — the worm injects both
	// via a `preinstall` script. Filenames alone get them queued for
	// the V2 hash pass; presence in the report's §6b evidence block
	// proves the V2 plumbing is intact end-to-end.
	mustWrite(t, filepath.Join(repo, "node_modules", "badpkg", "setup_bun.js"),
		"// V2 dropper stub\n")
	mustWrite(t, filepath.Join(repo, "node_modules", "badpkg", "bun_environment.js"),
		"// V2 payload stub — references Sha1-Hulud: The Second Coming\n")
	mustWrite(t, filepath.Join(repo, ".github", "workflows", "shai-hulud-workflow.yml"),
		"name: shai-hulud\n")
	mustWrite(t, filepath.Join(repo, "leak.txt"),
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n")
	mustWrite(t, filepath.Join(repo, "requirements.txt"),
		"durabletask==1.4.2\n")

	// A loose Python project outside any git repo — the round-1 fix
	// removed the inRepo gate, so this should also be caught.
	mustWrite(t, filepath.Join(root, "loose", "pyproject.toml"),
		"[tool.poetry.dependencies]\ndurabletask = \"1.4.1\"\n")

	// An *installed* malicious durabletask — on-disk package metadata in a
	// venv-shaped site-packages tree. Detected purely from the dist-info
	// directory name; wormsign never executes the interpreter.
	mustWrite(t,
		filepath.Join(root, "venv", "lib", "python3.13", "site-packages",
			"durabletask-1.4.2.dist-info", "METADATA"),
		"Metadata-Version: 2.1\nName: durabletask\nVersion: 1.4.2\n")

	return root
}

// runIntegration runs scanner.Run against a planted fixture and
// returns the resulting Result.
func runIntegration(t *testing.T, fixture string) *Result {
	t.Helper()
	// HomeDir is a clean tempdir so credential-target / IDE-persistence
	// checks find nothing of substance and don't introduce host-specific
	// noise into the test output.
	homeDir := t.TempDir()
	// Silence the scanner's debug logs in test output.
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	result, err := Run(context.Background(), Options{
		HomeDir:        homeDir,
		ExtraRoots:     []string{fixture},
		NoDefaultRoots: true,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("scanner.Run: %v", err)
	}
	return result
}

// renderReport writes Result.Report into a buffer with a deterministic
// Meta so the test output is comparable across runs.
func renderReport(t *testing.T, result *Result) string {
	t.Helper()
	var buf bytes.Buffer
	err := result.Report.Write(&buf, report.Meta{
		Hostname:     "test-host",
		MacOSVersion: "test-os",
		User:         "test-user",
		CaptureUTC:   "0000-00-00 00:00:00",
		CaptureLocal: "0000-00-00 00:00:00 TST",
		OutputPath:   "/dev/null",
		WormsignVer:  "test",
	})
	if err != nil {
		t.Fatalf("Report.Write: %v", err)
	}
	return buf.String()
}

// TestScannerIntegration is the headline end-to-end test: plant every
// IoC the scanner is supposed to flag, run the full scanner.Run, and
// verify each expected indicator surfaces in the report.
func TestScannerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test invokes external dscacheutil/sqlite3 subprocesses; skip with -short")
	}
	fixture := plantFixture(t)
	result := runIntegration(t, fixture)

	_, hit, _ := result.Report.Counts()
	if hit < 6 {
		t.Errorf("expected at least 6 HITs (workflow + high-sig + low-sig + token + durabletask pin + installed durabletask), got %d", hit)
	}

	out := renderReport(t, result)

	// Every planted indicator must surface somewhere in the report.
	mustContain := []string{
		// high-signal V1
		"Shai-Hulud Migration",
		"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
		// high-signal V2 (Sha1-Hulud) — content match is the HIT. The
		// setup_bun.js / bun_environment.js stubs hash clean (only a
		// known-bad hash is a HIT), so they no longer surface in the
		// report body — clean findings are intentionally omitted.
		"Sha1-Hulud: The Second Coming",
		// workflow file path
		"shai-hulud-workflow.yml",
		// token (redacted form)
		"ghp_ABCD",
		"(redacted)",
		// durabletask versions — both repo and loose
		"requirements.txt: pins durabletask 1.4.2",
		"pyproject.toml: pins durabletask 1.4.1",
		// installed durabletask detected on disk (no interpreter executed)
		"Malicious `durabletask` version installed on disk",
		"durabletask-1.4.2.dist-info",
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("report missing expected substring: %q", want)
		}
	}

	// Privacy assertion: the full GitHub token must NOT appear in the
	// rendered report — only the 8-char prefix + redaction marker.
	const fullToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if strings.Contains(out, fullToken) {
		t.Errorf("FULL token leaked into the report — privacy regression")
	}
}

// TestScannerDeterministicReport — two back-to-back Run() calls in the
// same process against the same fixture must produce byte-identical
// reports (modulo the volatile header fields that vary by run).
//
// This is the property scanner.Run guarantees via pre-registered
// section order + sorted result slices.
func TestScannerDeterministicReport(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test invokes external dscacheutil/sqlite3 subprocesses; skip with -short")
	}
	fixture := plantFixture(t)

	r1 := renderReport(t, runIntegration(t, fixture))
	r2 := renderReport(t, runIntegration(t, fixture))

	r1 = stripVolatile(r1)
	r2 = stripVolatile(r2)

	if r1 != r2 {
		// Find the first diverging line to make the failure useful.
		l1 := strings.Split(r1, "\n")
		l2 := strings.Split(r2, "\n")
		n := len(l1)
		if len(l2) < n {
			n = len(l2)
		}
		for i := 0; i < n; i++ {
			if l1[i] != l2[i] {
				t.Fatalf("reports diverge at line %d:\nrun1: %s\nrun2: %s", i+1, l1[i], l2[i])
			}
		}
		t.Fatalf("reports have different lengths: %d vs %d", len(l1), len(l2))
	}
}

// tempPathRE matches `t.TempDir()`-style paths that differ between runs.
// These are rooted at os.TempDir() (macOS: /var/folders/<rand>/T, often
// aliased through /private; Linux/CI/sandboxes: /tmp or $TMPDIR), so we
// anchor the pattern on the actual temp root rather than hardcoding the
// macOS `/var/folders` layout — the old regex silently failed to mask
// these paths anywhere $TMPDIR wasn't under /var/folders, making the
// determinism check pass/fail depending on the host. We REPLACE the
// prefix with a placeholder rather than dropping whole lines, so fixed
// content like the `/tmp/processor.sh` persistence entries — emitted on
// every run — still participates in the determinism check.
var tempPathRE = regexp.MustCompile(
	`(?:/private)?` + regexp.QuoteMeta(strings.TrimRight(os.TempDir(), "/")) + `/[^\s)]+`)

func stripVolatile(s string) string {
	return tempPathRE.ReplaceAllString(s, "<TEMP>")
}

// TestScannerNoHitsOnCleanFixture — empty fixture should produce zero
// HITs. Also asserts the report is non-empty (clean count > 0) to
// catch the regression where the scanner silently produced an empty
// report on a real host.
func TestScannerNoHitsOnCleanFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("invokes external subprocesses")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "cleanrepo", ".git"))
	mustWrite(t, filepath.Join(root, "cleanrepo", "README.md"), "# nothing to see\n")

	result := runIntegration(t, root)
	clean, hit, _ := result.Report.Counts()
	if hit != 0 {
		t.Errorf("expected 0 HITs on a clean fixture, got %d", hit)
		t.Logf("report:\n%s", renderReport(t, result))
	}
	if clean == 0 {
		t.Errorf("expected clean count > 0 (every check should emit at least one finding), got 0")
	}
}

// TestScannerPropagatesCancellation — a cancelled ctx should cause
// Run to return promptly without hanging on a deadlock. The timeout
// arm exists so a real deadlock fails the test instead of the suite
// timing out 10 minutes later.
func TestScannerPropagatesCancellation(t *testing.T) {
	fixture := plantFixture(t)
	homeDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run starts

	type runResult struct {
		result *Result
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		r, err := Run(ctx, Options{
			HomeDir:        homeDir,
			ExtraRoots:     []string{fixture},
			NoDefaultRoots: true,
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		done <- runResult{r, err}
	}()

	select {
	case rr := <-done:
		// Run must return something — either a Result or an error.
		// Returning (nil, nil) on cancellation would be a contract
		// regression that's easy to introduce and hard to spot.
		if rr.result == nil && rr.err == nil {
			t.Fatal("Run returned (nil, nil) on cancellation; expected either a Result or an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of cancellation — possible deadlock")
	}
}
