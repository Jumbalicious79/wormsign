package report

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestCounts(t *testing.T) {
	r := New()
	r.Clean("§1", "ok")
	r.Clean("§1", "also ok")
	r.Hit("§1", "found", "ev")
	r.Skipped("§2", "missing tool")
	// StatusInfo must not count toward any of clean/hit/skipped.
	r.Add(Finding{Section: "§2", Status: StatusInfo, Message: "informational"})

	clean, hit, skipped := r.Counts()
	if clean != 2 {
		t.Errorf("clean count: got %d, want 2", clean)
	}
	if hit != 1 {
		t.Errorf("hit count: got %d, want 1", hit)
	}
	if skipped != 1 {
		t.Errorf("skipped count: got %d, want 1", skipped)
	}
}

func TestInfoStatusExcludedFromCounts(t *testing.T) {
	r := New()
	r.Add(Finding{Section: "X", Status: StatusInfo, Message: "info 1"})
	r.Add(Finding{Section: "X", Status: StatusInfo, Message: "info 2"})
	clean, hit, skipped := r.Counts()
	if clean != 0 || hit != 0 || skipped != 0 {
		t.Errorf("info-only reporter should have zero counts; got clean=%d hit=%d skipped=%d",
			clean, hit, skipped)
	}
}

// TestSectionOrderPreservedByRegistration verifies that HIT sections
// render in the order they were first registered, regardless of the
// order findings are subsequently added. This is the property scanner.Run
// relies on by pre-registering all sections up front. Only HIT sections
// appear in the body, so every section here is given a hit.
func TestSectionOrderPreservedByRegistration(t *testing.T) {
	r := New()
	r.Section("§A", "preamble A")
	r.Section("§B", "preamble B")
	r.Section("§C", "preamble C")

	// Add findings in a deliberately scrambled order.
	r.Hit("§C", "c finding", "")
	r.Hit("§A", "a finding", "")
	r.Hit("§B", "b finding", "")

	var buf bytes.Buffer
	if err := r.Write(&buf, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	iA := strings.Index(out, "## §A")
	iB := strings.Index(out, "## §B")
	iC := strings.Index(out, "## §C")
	if iA == -1 || iB == -1 || iC == -1 {
		t.Fatalf("missing section header: A=%d B=%d C=%d", iA, iB, iC)
	}
	if iA >= iB || iB >= iC {
		t.Errorf("section order mismatch: A=%d B=%d C=%d (expected A < B < C)", iA, iB, iC)
	}
}

// TestCleanAndInfoFindingsOmittedFromBody verifies the report body lists
// only HITs: clean and informational findings (and their sections, when
// they contain no hits) must not appear.
func TestCleanAndInfoFindingsOmittedFromBody(t *testing.T) {
	r := New()
	r.Section("§clean-only", "")
	r.Section("§has-hit", "")
	r.Clean("§clean-only", "nothing here")
	r.Add(Finding{Section: "§clean-only", Status: StatusInfo, Message: "discovery goo", Evidence: "lots\nof\nlines"})
	r.Clean("§has-hit", "this neighbor is clean")
	r.Hit("§has-hit", "found an indicator", "evidence line")

	var buf bytes.Buffer
	if err := r.Write(&buf, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "## §clean-only") {
		t.Error("a section with no HITs must not render in the body")
	}
	// Note: ✅ still legitimately appears in the summary table at the
	// bottom, so it is not in this list — only body content is checked.
	for _, unwanted := range []string{"nothing here", "discovery goo", "lots", "this neighbor is clean"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("clean/info content leaked into body: %q", unwanted)
		}
	}
	if !strings.Contains(out, "## §has-hit") || !strings.Contains(out, "found an indicator") {
		t.Error("HIT finding and its section must render")
	}
}

// TestNoHitsRendersCleanBanner verifies the body shows a single "no IoCs"
// note instead of per-section clean bullets when nothing matched.
func TestNoHitsRendersCleanBanner(t *testing.T) {
	r := New()
	r.Section("§A", "")
	r.Clean("§A", "all good")

	var buf bytes.Buffer
	if err := r.Write(&buf, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No Shai-Hulud") {
		t.Error("zero-hit report should contain the no-IoCs banner")
	}
	if strings.Contains(out, "## §A") {
		t.Error("clean-only section should not render when there are no hits")
	}
}

// TestSkippedChecksListedCompactly verifies skipped checks surface in
// their own section as one-liners (coverage gaps), not as body findings.
func TestSkippedChecksListedCompactly(t *testing.T) {
	r := New()
	r.Section("§net", "")
	r.Skipped("§net", "curl not installed")

	var buf bytes.Buffer
	if err := r.Write(&buf, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "## Skipped checks") {
		t.Error("skipped checks section missing")
	}
	if !strings.Contains(out, "- **§net** — curl not installed") {
		t.Errorf("skipped check not listed compactly; got:\n%s", out)
	}
}

// TestRepeatedSectionCallUpdatesPreambleNotOrder verifies a later
// Section() with a non-empty preamble updates the preamble but does
// NOT change the section's position. scanner.Run depends on this when
// it pre-registers with "" and individual checks fill in preambles
// later.
func TestRepeatedSectionCallUpdatesPreambleNotOrder(t *testing.T) {
	r := New()
	r.Section("§A", "")
	r.Section("§B", "")
	// Second call to §A with a preamble should not move it after §B.
	r.Section("§A", "final preamble A")
	r.Hit("§A", "a finding", "")
	r.Hit("§B", "b finding", "")

	var buf bytes.Buffer
	if err := r.Write(&buf, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	iA := strings.Index(out, "## §A")
	iB := strings.Index(out, "## §B")
	if iA == -1 || iB == -1 {
		t.Fatalf("missing section: A=%d B=%d", iA, iB)
	}
	if iA >= iB {
		t.Errorf("repeated Section call moved §A; iA=%d iB=%d", iA, iB)
	}
	if !strings.Contains(out, "final preamble A") {
		t.Error("preamble update was lost")
	}
}

// TestConcurrentAddIsSafe — Reporter is hit from multiple goroutines
// in scanner.Run; race detector should report nothing.
func TestConcurrentAddIsSafe(t *testing.T) {
	r := New()
	r.Section("§X", "")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				switch (i + j) % 3 {
				case 0:
					r.Clean("§X", "c")
				case 1:
					r.Hit("§X", "h", "ev")
				default:
					r.Skipped("§X", "s")
				}
			}
		}(i)
	}
	wg.Wait()
	clean, hit, skipped := r.Counts()
	if clean+hit+skipped != 16*50 {
		t.Errorf("lost findings under concurrency: got %d, want %d", clean+hit+skipped, 16*50)
	}
}

// TestHitWithEvidenceRendersInCodeBlock — quick smoke test that
// evidence is fenced.
func TestHitWithEvidenceRendersInCodeBlock(t *testing.T) {
	r := New()
	r.Section("§E", "")
	r.Hit("§E", "found stuff", "line1\nline2")
	var buf bytes.Buffer
	if err := r.Write(&buf, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Evidence:") {
		t.Error("hit evidence label missing")
	}
	if !strings.Contains(out, "  ```") {
		t.Error("evidence should be inside a fenced code block")
	}
	if !strings.Contains(out, "  line1") {
		t.Error("evidence line not present")
	}
}

// TestWriteRendersFullMeta exercises the header block + StatusInfo
// rendering path that the integration tests don't directly assert.
// The production code writes a populated Meta on every real run, so
// without this we have a coverage gap on the header rendering itself.
func TestWriteRendersFullMeta(t *testing.T) {
	r := New()
	r.Section("§A", "")
	r.Clean("§A", "all good")
	r.Skipped("§A", "no tool")
	r.Hit("§A", "matched indicator", "")
	r.Add(Finding{
		Section:  "§A",
		Status:   StatusInfo,
		Message:  "informational summary:",
		Evidence: "stat-line-1\nstat-line-2",
	})

	var buf bytes.Buffer
	err := r.Write(&buf, Meta{
		Hostname:       "host-123",
		MacOSVersion:   "15.5",
		User:           "alice",
		CaptureUTC:     "2026-01-01 00:00:00",
		CaptureLocal:   "2026-01-01 00:00:00 UTC",
		OutputPath:     "/tmp/scan.md",
		WormsignVer:    "v1.2.3",
		RepoCount:      42,
		NMCount:        7,
		DiscoveryRoots: []string{"/Users/alice", "/Volumes"},
		ExcludePaths:   []string{"/System", "/Library"},
		Coverage:       "test coverage description",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Header fields
	for _, want := range []string{
		"host-123",
		"15.5",
		"alice",
		"v1.2.3",
		"test coverage description",
		"| Repos discovered | 42 |",
		"| node_modules discovered | 7 |",
		"`/Users/alice`",
		"`/Volumes`",
		"`/System`",
		"`/Library`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Write output missing header substring %q", want)
		}
	}

	// Skipped checks now render in their own compact section.
	if !strings.Contains(out, "## Skipped checks") {
		t.Error("skipped checks section missing")
	}
	if !strings.Contains(out, "- **§A** — no tool") {
		t.Error("StatusSkipped should render as a one-line coverage-gap entry")
	}
	// Informational findings are omitted from the body entirely.
	if strings.Contains(out, "informational summary:") || strings.Contains(out, "stat-line-1") {
		t.Error("StatusInfo content must not render in the body")
	}
}
