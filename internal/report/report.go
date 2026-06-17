// Package report collects findings during a scan and renders a markdown
// triage report matching the layout of triage-shai-hulud-iocs.sh.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Status of a single check.
type Status int

const (
	StatusClean Status = iota
	StatusHit
	StatusSkipped
	// StatusInfo is informational. It is rendered as a code block, not as
	// a clean/hit bullet, and is excluded from summary counts.
	StatusInfo
)

func (s Status) String() string {
	switch s {
	case StatusClean:
		return "clean"
	case StatusHit:
		return "HIT"
	case StatusSkipped:
		return "skipped"
	case StatusInfo:
		return "info"
	}
	return "unknown"
}

// Finding is a single check outcome.
type Finding struct {
	Section  string // e.g. "1. Persistence file presence (exact paths)"
	Order    int    // section order — sections are rendered in ascending Order
	Status   Status
	Message  string
	Evidence string // optional, multi-line, rendered inside a code block
}

// Reporter is a concurrency-safe collector of findings.
type Reporter struct {
	mu       sync.Mutex
	findings []Finding
	// sectionPreamble holds intro text for a section, keyed by section title.
	sectionPreamble map[string]string
	// sectionOrder remembers the order each section was first registered.
	sectionOrder map[string]int
	nextOrder    int
}

// New constructs an empty Reporter.
func New() *Reporter {
	return &Reporter{
		sectionPreamble: make(map[string]string),
		sectionOrder:    make(map[string]int),
	}
}

// Section registers a section (idempotent) so it appears in the report
// even if no findings are recorded for it, and so sections render in
// the order they were registered. Optional preamble text appears under
// the heading.
func (r *Reporter) Section(title, preamble string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sectionOrder[title]; !ok {
		r.sectionOrder[title] = r.nextOrder
		r.nextOrder++
	}
	if preamble != "" {
		r.sectionPreamble[title] = preamble
	}
}

// Add records a finding.
func (r *Reporter) Add(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sectionOrder[f.Section]; !ok {
		r.sectionOrder[f.Section] = r.nextOrder
		r.nextOrder++
	}
	r.findings = append(r.findings, f)
}

// Clean is a convenience for recording a clean finding.
func (r *Reporter) Clean(section, msg string) {
	r.Add(Finding{Section: section, Status: StatusClean, Message: msg})
}

// Hit is a convenience for recording a HIT finding.
func (r *Reporter) Hit(section, msg, evidence string) {
	r.Add(Finding{Section: section, Status: StatusHit, Message: msg, Evidence: evidence})
}

// Skipped is a convenience for recording a skipped finding.
func (r *Reporter) Skipped(section, msg string) {
	r.Add(Finding{Section: section, Status: StatusSkipped, Message: msg})
}

// Counts returns aggregate counts.
func (r *Reporter) Counts() (clean, hit, skipped int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.findings {
		switch f.Status {
		case StatusClean:
			clean++
		case StatusHit:
			hit++
		case StatusSkipped:
			skipped++
		}
	}
	return
}

// Meta is the run-level metadata that appears in the report header.
type Meta struct {
	Hostname       string
	MacOSVersion   string
	User           string
	CaptureUTC     string
	CaptureLocal   string
	OutputPath     string
	WormsignVer    string
	RepoCount      int
	NMCount        int
	DiscoveryRoots []string
	ExcludePaths   []string
	Coverage       string
}

// Write renders the markdown report to w.
func (r *Reporter) Write(w io.Writer, meta Meta) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	clean, hit, skipped := 0, 0, 0
	for _, f := range r.findings {
		switch f.Status {
		case StatusClean:
			clean++
		case StatusHit:
			hit++
		case StatusSkipped:
			skipped++
		}
	}

	bw := &strings.Builder{}

	fmt.Fprintf(bw, "# Shai-Hulud / TeamPCP / megalodon IoC Hunt — macOS Host Triage\n\n")
	fmt.Fprintf(bw, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(bw, "| Host | %s |\n", meta.Hostname)
	fmt.Fprintf(bw, "| macOS | %s |\n", meta.MacOSVersion)
	fmt.Fprintf(bw, "| Captured by | %s |\n", meta.User)
	fmt.Fprintf(bw, "| Capture time (UTC) | %s |\n", meta.CaptureUTC)
	fmt.Fprintf(bw, "| Capture time (local) | %s |\n", meta.CaptureLocal)
	fmt.Fprintf(bw, "| Tool | wormsign %s |\n", meta.WormsignVer)
	fmt.Fprintf(bw, "| Output file | %s |\n", meta.OutputPath)
	if meta.Coverage != "" {
		fmt.Fprintf(bw, "| Coverage | %s |\n", meta.Coverage)
	}
	fmt.Fprintf(bw, "| Repos discovered | %d |\n", meta.RepoCount)
	fmt.Fprintf(bw, "| node_modules discovered | %d |\n", meta.NMCount)
	fmt.Fprintf(bw, "\n")
	fmt.Fprintf(bw, "**Read-only.** No file is modified, no command escalates, no secret value is captured.\n\n")
	fmt.Fprintf(bw, "## How to read this report\n\n")
	fmt.Fprintf(bw, "This report lists **only checks that matched an indicator** (❌ HIT) — "+
		"each one requires ISO review. Clean checks are omitted so there is no goo to "+
		"scroll past; their count appears in the summary table at the bottom. Checks that "+
		"could not run are listed under \"Skipped checks\" — those are coverage gaps, not "+
		"clean results.\n\n")
	fmt.Fprintf(bw, "Discovery roots walked:\n")
	for _, root := range meta.DiscoveryRoots {
		fmt.Fprintf(bw, "- `%s`\n", root)
	}
	fmt.Fprintf(bw, "\nExcluded paths (pruned during walk):\n")
	for _, p := range meta.ExcludePaths {
		fmt.Fprintf(bw, "- `%s`\n", p)
	}
	fmt.Fprintf(bw, "\n")

	// Group findings by section while preserving each section's original order.
	type sectionEntry struct {
		title    string
		order    int
		findings []Finding
	}
	bySection := make(map[string]*sectionEntry)
	for title, order := range r.sectionOrder {
		bySection[title] = &sectionEntry{title: title, order: order}
	}
	for _, f := range r.findings {
		bySection[f.Section].findings = append(bySection[f.Section].findings, f)
	}
	sections := make([]*sectionEntry, 0, len(bySection))
	for _, s := range bySection {
		sections = append(sections, s)
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].order < sections[j].order })

	// Body: render HIT findings only, grouped by section in registration
	// order. Clean and informational findings are intentionally omitted so
	// the report shows only what needs review. Skipped checks are coverage
	// gaps rather than clean results, so they are summarized separately
	// below rather than dropped.
	if hit == 0 {
		fmt.Fprintf(bw, "## Findings\n\n")
		fmt.Fprintf(bw, "No Shai-Hulud / TeamPCP / megalodon IoCs were detected. Every "+
			"check that ran came back clean — see the summary below for the full "+
			"clean/skipped counts.\n\n")
	} else {
		for _, s := range sections {
			hits := make([]Finding, 0, len(s.findings))
			for _, f := range s.findings {
				if f.Status == StatusHit {
					hits = append(hits, f)
				}
			}
			if len(hits) == 0 {
				continue
			}
			fmt.Fprintf(bw, "## %s\n\n", s.title)
			if p, ok := r.sectionPreamble[s.title]; ok && p != "" {
				fmt.Fprintf(bw, "%s\n\n", p)
			}
			for _, f := range hits {
				fmt.Fprintf(bw, "- ❌ **HIT** — %s\n", f.Message)
				if f.Evidence != "" {
					fmt.Fprintf(bw, "\n  Evidence:\n\n  ```\n")
					for _, line := range strings.Split(strings.TrimRight(f.Evidence, "\n"), "\n") {
						fmt.Fprintf(bw, "  %s\n", line)
					}
					fmt.Fprintf(bw, "  ```\n")
				}
			}
			fmt.Fprintf(bw, "\n")
		}
	}

	// Skipped checks: listed compactly (one line each) so coverage gaps are
	// visible without reintroducing the clean-check noise.
	if skipped > 0 {
		fmt.Fprintf(bw, "## Skipped checks\n\n")
		fmt.Fprintf(bw, "These checks could not run (permissions, missing tool, etc.) and "+
			"represent coverage gaps rather than clean results:\n\n")
		for _, s := range sections {
			for _, f := range s.findings {
				if f.Status == StatusSkipped {
					fmt.Fprintf(bw, "- **%s** — %s\n", s.title, f.Message)
				}
			}
		}
		fmt.Fprintf(bw, "\n")
	}

	fmt.Fprintf(bw, "## Summary\n\n")
	fmt.Fprintf(bw, "| Outcome | Count |\n|---|---|\n")
	fmt.Fprintf(bw, "| ✅ Clean | %d |\n", clean)
	fmt.Fprintf(bw, "| ❌ Hit | %d |\n", hit)
	fmt.Fprintf(bw, "| ⚠️ Skipped | %d |\n\n", skipped)
	if hit == 0 {
		fmt.Fprintf(bw, "**Overall: no Shai-Hulud / megalodon IoCs detected on this host.** "+
			"Absence of these specific IoCs does not prove absence of compromise (an earlier "+
			"infostealer with different IoCs, or one that cleaned up after itself, would not be "+
			"detected by this script). It does establish that the public framework's persistence "+
			"and content signatures are not currently present.\n")
	} else {
		fmt.Fprintf(bw, "**Overall: %d indicator(s) matched.** Each ❌ HIT above requires manual "+
			"review by the ISO. Possible benign explanations include security-research material "+
			"on the host, IR-report drafts, or false-positive matches on legitimate code that "+
			"happens to use the same strings. Genuine compromise is possible but not assumed "+
			"without context.\n", hit)
	}

	_, err := io.WriteString(w, bw.String())
	return err
}
