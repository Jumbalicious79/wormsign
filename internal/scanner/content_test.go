package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestContentScannerMatchesHighSignal verifies the alternation regex
// fires on a planted high-signal IoC literal and returns the matching
// IoC identity (not just the raw byte slice).
func TestContentScannerMatchesHighSignal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	mustWrite(t, path, "// reference to Shai-Hulud Migration in passing\n")

	cs := newContentScanner()
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	found := false
	for _, h := range results[0].StringMatches {
		if h.IoC == "Shai-Hulud Migration" && !h.LowSignal {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected high-signal hit on 'Shai-Hulud Migration'; got: %+v", results[0].StringMatches)
	}
}

// TestContentScannerMatchesSha1HuludLiteral — the Nov 2025 worm's repo
// description is the literal "Sha1-Hulud: The Second Coming" (digit 1).
// Datadog/Tenable/Semgrep/SentinelOne/Sumologic all pivot on this exact
// spelling. A regression that loses it would let real V2 infections past
// the high-signal grep.
func TestContentScannerMatchesSha1HuludLiteral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc-list.md")
	mustWrite(t, path, "Exfil repo description: Sha1-Hulud: The Second Coming\n")

	cs := newContentScanner()
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	found := false
	for _, h := range results[0].StringMatches {
		if h.IoC == "Sha1-Hulud: The Second Coming" && !h.LowSignal {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected high-signal hit on canonical Sha1-Hulud literal; got: %+v", results[0].StringMatches)
	}
}

// TestContentScannerLowSignalMatchesCaseInsensitively ensures the low-
// signal regex carries (?i) and the LowSignal flag is set on hits.
func TestContentScannerLowSignalMatchesCaseInsensitively(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	mustWrite(t, path, "we use SHAI-HULUD detection here\n")

	cs := newContentScanner()
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	low := false
	for _, h := range results[0].StringMatches {
		if h.LowSignal && strings.EqualFold(h.IoC, "shai-hulud") {
			low = true
			break
		}
	}
	if !low {
		t.Errorf("expected case-insensitive low-signal hit; got: %+v", results[0].StringMatches)
	}
}

// TestContentScannerRedactsTokens — the headline security promise is
// that token tails never appear in the report. Verify the published
// match is truncated.
func TestContentScannerRedactsTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.txt")
	const fullToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	mustWrite(t, path, fullToken+"\n")

	cs := newContentScanner()
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if len(results[0].TokenMatches) != 1 {
		t.Fatalf("expected 1 token match, got %d", len(results[0].TokenMatches))
	}
	got := results[0].TokenMatches[0]
	if strings.Contains(got, fullToken) {
		t.Errorf("token was NOT redacted: %q", got)
	}
	if !strings.Contains(got, "(redacted)") {
		t.Errorf("expected redaction marker, got %q", got)
	}
	if !strings.HasPrefix(got, "ghp_") {
		t.Errorf("expected redaction to preserve prefix; got %q", got)
	}
}

// TestContentScannerTokenWordBoundary verifies the leading \b anchor
// — an alphanumeric character immediately before "ghp_" should
// prevent a match (otherwise minified JS produces false positives).
func TestContentScannerTokenWordBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minified.js")
	// "xghp_..." should NOT match because there's no word boundary
	// before "ghp_".
	mustWrite(t, path, "var a=xghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345;\n")

	cs := newContentScanner()
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	for _, r := range results {
		if len(r.TokenMatches) > 0 {
			t.Errorf("token regex without leading \\b matched in embedded position: %v", r.TokenMatches)
		}
	}
}

// TestContentScannerSkipsBinaryFiles — NUL byte in the first 512 bytes
// should cause the file to be skipped entirely.
func TestContentScannerSkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.dat")
	// Plant a NUL byte before a high-signal literal.
	content := []byte{0x00, 0x01, 0x02}
	content = append(content, []byte("Shai-Hulud Migration")...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	cs := newContentScanner()
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	if len(results) != 0 {
		t.Errorf("binary file (NUL in head) should be skipped; got %d results", len(results))
	}
}

// TestContentScannerSkipsOversize — files past maxFileSize should be
// skipped before any regex runs.
func TestContentScannerSkipsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.txt")
	body := strings.Repeat("padding ", 4000) + "Shai-Hulud Migration"
	mustWrite(t, path, body)

	cs := newContentScanner()
	cs.maxFileSize = 1024 // 1KB cap, way below the file
	results := cs.ScanFiles(context.Background(), nil, []string{path}, 2)
	if len(results) != 0 {
		t.Errorf("oversize file should be skipped; got %d results", len(results))
	}
}

// TestContentScannerCountersOnlyOnRealScan verifies the scanned/
// matched counter semantics fixed in round 3: dataless / oversize /
// binary skips should NOT bump ContentScanned.
func TestContentScannerCountersOnlyOnRealScan(t *testing.T) {
	dir := t.TempDir()
	huge := filepath.Join(dir, "huge.txt")
	mustWrite(t, huge, strings.Repeat("x", 2048))
	binary := filepath.Join(dir, "binary.dat")
	if err := os.WriteFile(binary, []byte{0x00, 0x01, 0x02, 'a', 'b', 'c'}, 0o600); err != nil {
		t.Fatal(err)
	}
	normal := filepath.Join(dir, "ok.txt")
	mustWrite(t, normal, "// nothing interesting here\n")

	d := NewDiscovery()
	cs := newContentScanner()
	cs.maxFileSize = 1024 // skips `huge`

	_ = cs.ScanFiles(context.Background(), d, []string{huge, binary, normal}, 2)

	if got := d.ContentScanned.Load(); got != 1 {
		t.Errorf("ContentScanned: got %d, want 1 (only the normal file was actually scanned)", got)
	}
	if got := d.ContentMatches.Load(); got != 0 {
		t.Errorf("ContentMatches: got %d, want 0", got)
	}
}

// TestContentScannerCtxCancellation — workers must not deadlock when
// ctx is cancelled mid-scan. The timeout arm is what makes this useful
// — a deadlock here would otherwise hang until the suite-wide test
// timeout, with no useful message.
func TestContentScannerCtxCancellation(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 50)
	for i := range paths {
		paths[i] = filepath.Join(dir, "f"+strconv.Itoa(i)+".txt")
		mustWrite(t, paths[i], "// payload\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before we start

	cs := newContentScanner()
	done := make(chan struct{})
	go func() {
		_ = cs.ScanFiles(ctx, nil, paths, 4)
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(5 * time.Second):
		t.Fatal("ScanFiles did not return within 5s of cancellation — possible deadlock")
	}
}
