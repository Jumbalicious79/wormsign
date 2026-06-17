package ioc

import (
	"regexp"
	"strings"
	"testing"
)

// TestHighSignalStringsSelfMatch verifies that the alternation regex
// built from HighSignalStrings matches every literal in the set.
// Catches regressions where a punctuation-heavy IoC is added without
// regexp.QuoteMeta protection.
func TestHighSignalStringsSelfMatch(t *testing.T) {
	parts := make([]string, len(HighSignalStrings))
	for i, s := range HighSignalStrings {
		parts[i] = regexp.QuoteMeta(s)
	}
	re := regexp.MustCompile(strings.Join(parts, "|"))
	for _, s := range HighSignalStrings {
		if !re.MatchString(s) {
			t.Errorf("compiled HighSignal regex does not match its own literal: %q", s)
		}
	}
}

// TestLowSignalStringsSelfMatch — same idea, case-insensitive.
func TestLowSignalStringsSelfMatch(t *testing.T) {
	parts := make([]string, len(LowSignalStrings))
	for i, s := range LowSignalStrings {
		parts[i] = regexp.QuoteMeta(s)
	}
	re := regexp.MustCompile("(?i)" + strings.Join(parts, "|"))
	for _, s := range LowSignalStrings {
		// Verify both the original case and an upper-cased variant
		// match — this is the whole point of the (?i) flag.
		if !re.MatchString(s) {
			t.Errorf("compiled LowSignal regex does not match literal: %q", s)
		}
		if !re.MatchString(strings.ToUpper(s)) {
			t.Errorf("compiled LowSignal regex (case-insensitive) misses upper-case variant of: %q", s)
		}
	}
}

// TestNoEmptyIoCs makes sure no slot in the corpus is silently empty —
// an empty string in an alternation regex would match every input.
func TestNoEmptyIoCs(t *testing.T) {
	groups := map[string][]string{
		"HighSignalStrings":      HighSignalStrings,
		"LowSignalStrings":       LowSignalStrings,
		"DomainsV1":              DomainsV1,
		"DomainsMini":            DomainsMini,
		"DomainsDurabletask":     DomainsDurabletask,
		"IPs":                    IPs,
		"HashesV1":               HashesV1,
		"HashesV2":               HashesV2,
		"BadDurabletaskVersions": BadDurabletaskVersions,
		"PersistenceFiles":       PersistenceFiles,
		"SearchDirs":             SearchDirs,
		"DiscoveryRoots":         DiscoveryRoots,
		"ExcludePaths":           ExcludePaths,
		"CredentialTargets":      CredentialTargets,
		"BrowserHistoryDBs":      BrowserHistoryDBs,
	}
	for name, group := range groups {
		for i, s := range group {
			if s == "" {
				t.Errorf("%s[%d] is an empty string — would break the alternation regex", name, i)
			}
		}
	}
}

// TestHashesAreLowercaseSHA256 — payload hashing compares against the
// corpus with lowercase hex. If anyone ever pastes an uppercase hash
// in, the comparison silently fails and we get a false-negative on the
// matching wave's payload. Covers V1 (bundle.js) + V2 (bun_environment.js
// / setup_bun.js).
func TestHashesAreLowercaseSHA256(t *testing.T) {
	groups := map[string][]string{
		"HashesV1": HashesV1,
		"HashesV2": HashesV2,
	}
	for name, group := range groups {
		for _, h := range group {
			if len(h) != 64 {
				t.Errorf("%s entry %q is not 64 chars (SHA-256 hex)", name, h)
				continue
			}
			for _, c := range h {
				isLowerHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
				if !isLowerHex {
					t.Errorf("%s entry %q contains non-lowercase-hex char %q", name, h, c)
					break
				}
			}
		}
	}
}

// TestAllPayloadHashesUnion — the AllPayloadHashes() helper must return
// every wave's hashes. checkBundleHashes builds its `known` map from
// this; a missing wave would silently miss that wave's payload.
func TestAllPayloadHashesUnion(t *testing.T) {
	got := AllPayloadHashes()
	want := len(HashesV1) + len(HashesV2)
	if len(got) != want {
		t.Errorf("AllPayloadHashes() returned %d entries, want %d", len(got), want)
	}
	seen := make(map[string]bool, len(got))
	for _, h := range got {
		seen[h] = true
	}
	for _, set := range [][]string{HashesV1, HashesV2} {
		for _, h := range set {
			if !seen[h] {
				t.Errorf("AllPayloadHashes() missing %q", h)
			}
		}
	}
}

// TestCorpusPlaceholderExpansion — every {HOME} appears only in places
// the orchestrator knows to expand. Catches a typo like {Home} or
// $HOME that would never get substituted.
func TestCorpusPlaceholderExpansion(t *testing.T) {
	groups := map[string][]string{
		"PersistenceFiles":  PersistenceFiles,
		"SearchDirs":        SearchDirs,
		"DiscoveryRoots":    DiscoveryRoots,
		"ExcludePaths":      ExcludePaths,
		"CredentialTargets": CredentialTargets,
		"BrowserHistoryDBs": BrowserHistoryDBs,
	}
	for name, group := range groups {
		for _, s := range group {
			// Any "{...}" placeholder must be exactly "{HOME}". We
			// only call ReplaceAll(s, "{HOME}", home) — any other
			// placeholder would pass through unexpanded.
			for i := 0; i < len(s); i++ {
				if s[i] != '{' {
					continue
				}
				end := strings.Index(s[i:], "}")
				if end == -1 {
					t.Errorf("%s contains an unclosed `{` in %q", name, s)
					break
				}
				ph := s[i : i+end+1]
				if ph != "{HOME}" {
					t.Errorf("%s contains unrecognized placeholder %q in %q (only {HOME} is supported)", name, ph, s)
				}
				i += end
			}
		}
	}
}

// TestCoverageDescriptionNonEmpty — the report header dumbly inserts
// this; an empty string would render a "Coverage |  |" row.
func TestCoverageDescriptionNonEmpty(t *testing.T) {
	if CoverageDescription == "" {
		t.Fatal("CoverageDescription must not be empty")
	}
}

// TestAllDomainsUnion — AllDomains() must return the concatenation of
// every domain set. Walker init() builds the network regex from this;
// a missing set would silently drop those C2s from detection.
func TestAllDomainsUnion(t *testing.T) {
	got := AllDomains()
	want := len(DomainsV1) + len(DomainsMini) + len(DomainsDurabletask)
	if len(got) != want {
		t.Errorf("AllDomains() returned %d entries, want %d", len(got), want)
	}
	// Every original entry must appear in the union.
	seen := make(map[string]bool, len(got))
	for _, d := range got {
		seen[d] = true
	}
	for _, set := range [][]string{DomainsV1, DomainsMini, DomainsDurabletask} {
		for _, d := range set {
			if !seen[d] {
				t.Errorf("AllDomains() missing %q", d)
			}
		}
	}
}

// TestRequirementsMapsCovered — walker uses these to classify Python
// dep files. A missing entry would cause a real corpus addition to
// silently not get scanned for the durabletask versions.
func TestRequirementsMapsCovered(t *testing.T) {
	if len(RequirementsFileNames) == 0 {
		t.Error("RequirementsFileNames map is empty")
	}
	if len(RequirementsFilePrefixes) == 0 {
		t.Error("RequirementsFilePrefixes is empty")
	}
	// pyproject.toml is the modern canonical pin location; it must
	// always be in the map.
	if !RequirementsFileNames["pyproject.toml"] {
		t.Error("RequirementsFileNames must include pyproject.toml")
	}
}

// TestPayloadFileNamesCoverage — the walker queues a file for hashing
// when its basename is in this map. The three canonical Shai-Hulud /
// Sha1-Hulud payload filenames must all be present; otherwise that
// wave's payloads are never hashed against AllPayloadHashes().
func TestPayloadFileNamesCoverage(t *testing.T) {
	required := []string{"bundle.js", "setup_bun.js", "bun_environment.js"}
	for _, name := range required {
		if !PayloadFileNames[name] {
			t.Errorf("PayloadFileNames missing required entry %q", name)
		}
	}
}

// TestSha1HuludLiteralPresent — the canonical repo-description string
// the Nov 2025 worm publishes is "Sha1-Hulud: The Second Coming" (digit
// 1, not letter i). Every reputable IoC list pivots on this exact
// spelling; missing it would let a real Sha1-Hulud infection past the
// high-signal grep.
func TestSha1HuludLiteralPresent(t *testing.T) {
	const canonical = "Sha1-Hulud: The Second Coming"
	for _, s := range HighSignalStrings {
		if s == canonical {
			return
		}
	}
	t.Errorf("HighSignalStrings missing canonical Sha1-Hulud V2 description %q", canonical)
}
