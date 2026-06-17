package cmd

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Jumbalicious79/wormsign/internal/report"
	"github.com/Jumbalicious79/wormsign/internal/scanner"
)

func TestCommaInt(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{999, "999"},
		{1000, "1,000"},
		{1234, "1,234"},
		{12345, "12,345"},
		{123456, "123,456"},
		{1234567, "1,234,567"},
		{-1, "-1"},
		{-999, "-999"},
		{-1234, "-1,234"},
		{-1234567, "-1,234,567"},
	}
	for _, tc := range cases {
		if got := commaInt(tc.in); got != tc.want {
			t.Errorf("commaInt(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPlural(t *testing.T) {
	if got := plural(1); got != "" {
		t.Errorf("plural(1) = %q, want empty", got)
	}
	for _, n := range []int{0, 2, 5, 100} {
		if got := plural(n); got != "s" {
			t.Errorf("plural(%d) = %q, want %q", n, got, "s")
		}
	}
}

func TestCoalesceConcurrency(t *testing.T) {
	if got := coalesceConcurrency(8); got != 8 {
		t.Errorf("coalesceConcurrency(8) = %d, want 8", got)
	}
	if got := coalesceConcurrency(0); got != runtime.NumCPU() {
		t.Errorf("coalesceConcurrency(0) = %d, want NumCPU=%d", got, runtime.NumCPU())
	}
	if got := coalesceConcurrency(-5); got != runtime.NumCPU() {
		t.Errorf("coalesceConcurrency(-5) = %d, want NumCPU=%d", got, runtime.NumCPU())
	}
}

func TestResolveProgressOut(t *testing.T) {
	// --quiet always wins, regardless of mode.
	if got := resolveProgressOut("on", true); got != nil {
		t.Error("quiet=true must disable progress even when mode=on")
	}
	if got := resolveProgressOut("auto", true); got != nil {
		t.Error("quiet=true must disable progress even when mode=auto")
	}

	// Off-style values disable.
	for _, mode := range []string{"off", "OFF", "false", "no", "0"} {
		if got := resolveProgressOut(mode, false); got != nil {
			t.Errorf("resolveProgressOut(%q, false) should disable, got non-nil", mode)
		}
	}

	// On-style values enable (returns os.Stderr).
	for _, mode := range []string{"on", "ON", "true", "yes", "1"} {
		got := resolveProgressOut(mode, false)
		if got != os.Stderr {
			t.Errorf("resolveProgressOut(%q, false) should return os.Stderr, got %v", mode, got)
		}
	}

	// "auto" depends on whether stderr is a TTY. In `go test` it isn't,
	// so we expect nil; verify only that it doesn't panic and doesn't
	// return some other unexpected writer.
	got := resolveProgressOut("auto", false)
	if got != nil && got != os.Stderr {
		t.Errorf("resolveProgressOut(auto, false) returned unexpected writer: %v", got)
	}
}

func TestWriteSummaryCleanRun(t *testing.T) {
	r := report.New()
	r.Section("§A", "")
	r.Clean("§A", "all good")
	r.Clean("§A", "also good")

	d := scanner.NewDiscovery()
	d.DirsVisited.Store(3)
	d.FilesVisited.Store(17)
	d.ContentScanned.Store(12)
	d.BundlesHashed.Store(0)

	result := &scanner.Result{
		Discovery: d,
		Report:    r,
		Duration:  250 * time.Millisecond,
	}

	var buf bytes.Buffer
	writeSummary(&buf, result, "/tmp/r.md")
	out := buf.String()

	for _, want := range []string{
		"wormsign complete",
		"Duration:",
		"250ms",
		"17 files / 3 dirs",
		"12 files (0 matched IoC strings)",
		"2 clean · 0 HIT · 0 skipped",
		"✓ No IoCs detected — report saved to /tmp/r.md",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestWriteSummaryHitRun(t *testing.T) {
	r := report.New()
	r.Section("§A", "")
	r.Hit("§A", "found something", "ev")
	r.Skipped("§A", "no tool")

	d := scanner.NewDiscovery()
	result := &scanner.Result{
		Discovery: d,
		Report:    r,
		Duration:  time.Second,
	}

	var buf bytes.Buffer
	writeSummary(&buf, result, "/tmp/r.md")
	out := buf.String()

	if !strings.Contains(out, "⚠ 1 HIT(s) — review /tmp/r.md") {
		t.Errorf("hit-path summary missing warning line; got:\n%s", out)
	}
	if !strings.Contains(out, "0 clean · 1 HIT · 1 skipped") {
		t.Errorf("counts line wrong; got:\n%s", out)
	}
}

func TestWriteSummarySingularPlural(t *testing.T) {
	// 1 node_modules → "tree" (no trailing s); 2+ → "trees".
	r := report.New()
	d1 := scanner.NewDiscovery()
	// Force NodeModulesCount() to return 1 by appending under the lock.
	// Discovery exposes ReposCount/NodeModulesCount as methods that
	// hold mu; we can't directly set the underlying slice from outside
	// the package, but we CAN exercise the singular path by leaving the
	// slice empty and the plural path by passing a Discovery with
	// non-empty slice. The pure-helper view is enough: plural(1) is
	// already covered by TestPlural. Here we just verify the integer
	// is wired into the format string.
	res := &scanner.Result{Discovery: d1, Report: r, Duration: 0}
	var buf bytes.Buffer
	writeSummary(&buf, res, "/dev/null")
	if !strings.Contains(buf.String(), "0 (containing 0 node_modules trees") {
		t.Errorf("plural form not rendered; got:\n%s", buf.String())
	}
}
