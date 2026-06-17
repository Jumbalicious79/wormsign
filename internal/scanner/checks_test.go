package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestExtractMetadataVersion covers the LF, CRLF, leading-header, and
// missing-version paths of the dist-info METADATA / egg-info PKG-INFO
// `Version:` parser. It's the fallback signal source for "which
// durabletask is installed?", so silent breakage here causes false
// negatives.
func TestExtractMetadataVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"normal LF", "Name: durabletask\nVersion: 1.4.2\nSummary: x\n", "1.4.2"},
		{"CRLF", "Name: durabletask\r\nVersion: 1.4.1\r\nSummary: x\r\n", "1.4.1"},
		{"leading Metadata-Version header", "Metadata-Version: 2.1\nName: durabletask\nVersion: 1.4.3\n", "1.4.3"},
		{"empty output", "", ""},
		{"no Version line", "Name: durabletask\nSummary: nothing\n", ""},
		{"trailing whitespace on value", "Version: 1.4.2   \n", "1.4.2"},
		{"version with local segment", "Version: 1.4.2+local\n", "1.4.2+local"},
		{"multiple Version lines — first wins", "Version: 1.4.2\nVersion: 9.9.9\n", "1.4.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractMetadataVersion([]byte(tc.in)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsDurabletaskDistDir — the walker flags a durabletask install by
// its metadata directory name. It must match the durabletask project's
// dist-info/egg-info and parse the version, without false-matching
// sibling projects like durabletask-azure (which pip normalizes to
// `durabletask_azure-...`).
func TestIsDurabletaskDistDir(t *testing.T) {
	cases := []struct {
		name      string
		wantMatch bool
		wantVer   string // expected version capture ("" if not a dist-info name)
	}{
		{"durabletask-1.4.2.dist-info", true, "1.4.2"},
		{"durabletask-1.4.1.egg-info", true, "1.4.1"},
		{"durabletask.egg-info", true, ""}, // legacy unversioned
		{"durabletask_azure-1.0.0.dist-info", false, ""},
		{"durabletask-azure-1.0.0.dist-info", true, "azure-1.0.0"}, // hyphen form: matched, but version capture is non-numeric → not in bad set
		{"requests-2.31.0.dist-info", false, ""},
		{"durabletask", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDurabletaskDistDir(tc.name); got != tc.wantMatch {
				t.Errorf("isDurabletaskDistDir(%q) = %v, want %v", tc.name, got, tc.wantMatch)
			}
			if m := durabletaskDistRE.FindStringSubmatch(tc.name); m != nil {
				if m[1] != tc.wantVer {
					t.Errorf("version capture for %q = %q, want %q", tc.name, m[1], tc.wantVer)
				}
			} else if tc.wantVer != "" {
				t.Errorf("expected version capture %q for %q, got no match", tc.wantVer, tc.name)
			}
		})
	}
}

// TestDurabletaskInstalledVersion — version comes from the dir name when
// present (no I/O), else from METADATA/PKG-INFO. Confirms both paths so
// a malicious version is detected whichever layout is on disk.
func TestDurabletaskInstalledVersion(t *testing.T) {
	root := t.TempDir()

	// dist-info: version embedded in the directory name, no METADATA read.
	distInfo := filepath.Join(root, "durabletask-1.4.2.dist-info")
	mustMkdir(t, distInfo)
	if got := durabletaskInstalledVersion(distInfo); got != "1.4.2" {
		t.Errorf("dist-info name parse: got %q, want 1.4.2", got)
	}

	// egg-info without a version in the name → read PKG-INFO.
	eggInfo := filepath.Join(root, "durabletask.egg-info")
	mustWrite(t, filepath.Join(eggInfo, "PKG-INFO"), "Metadata-Version: 2.1\nName: durabletask\nVersion: 1.4.3\n")
	if got := durabletaskInstalledVersion(eggInfo); got != "1.4.3" {
		t.Errorf("egg-info PKG-INFO parse: got %q, want 1.4.3", got)
	}
}

// TestDurabletaskNameRegex — the name regex must match
// `durabletask` only as a whole word, so it doesn't false-positive on
// e.g. `durabletask-azure` or `mydurabletask`.
func TestDurabletaskNameRegex(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"durabletask==1.4.2", true},
		{"durabletask = \"1.4.2\"", true},
		{"# comment about durabletask", true},
		{"durabletask-azure==1.0", false},
		{"mydurabletask>=1", false},
		{"durabletaskfoo", false},
	}
	for _, tc := range cases {
		got := durabletaskNameRE.MatchString(tc.in)
		if got != tc.want {
			t.Errorf("durabletaskNameRE on %q: got %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestDurabletaskPinRegex — the pin regex captures the malicious
// version literal across pip operators.
func TestDurabletaskPinRegex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // captured group or "" for no match
	}{
		{"pip ==", "durabletask==1.4.2", "1.4.2"},
		{"poetry =", "durabletask = \"1.4.1\"", "1.4.1"},
		{"pip >=", "durabletask>=1.4.3", "1.4.3"},
		{"benign 1.5.0", "durabletask==1.5.0", ""}, // not in BadDurabletaskVersions
		{"benign 1.4.0", "durabletask==1.4.0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loc := durabletaskPinRE.FindStringSubmatch(tc.in)
			var got string
			if len(loc) >= 2 {
				got = loc[1]
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildURLWhereClause — escaping single quotes is the only
// non-trivial transformation here; verify it.
func TestBuildURLWhereClause(t *testing.T) {
	got := buildURLWhereClause([]string{"foo.com", "bar's"})
	want := "url LIKE '%foo.com%' OR url LIKE '%bar''s%'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestHashOneBundleDetectsBad seeds a file with arbitrary content,
// computes its SHA-256, and tells hashOneBundle that exact hash is the
// known-bad value. A regression in the comparison logic (uppercase
// drift, accidental hex.EncodeToUpper, etc.) would let a real V1 or V2
// payload pass undetected, so we lock the bit-for-bit behavior here.
func TestHashOneBundleDetectsBad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.js")
	content := []byte("// pretend this is malicious\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256(content)
	knownHash := hex.EncodeToString(sum[:])

	res := hashOneBundle(context.Background(), path, map[string]bool{knownHash: true})
	if res.skip != "" {
		t.Fatalf("expected hash success, got skip=%q", res.skip)
	}
	if res.hash != knownHash {
		t.Errorf("hash mismatch: got %s, want %s", res.hash, knownHash)
	}
	if !res.bad {
		t.Errorf("known-bad hash not flagged as malicious")
	}
}

// TestHashOneBundleCleanWhenUnknown — counterpart to the bad-detection
// test: a hash that isn't in the known set must NOT flag.
func TestHashOneBundleCleanWhenUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(path, []byte("// harmless\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := hashOneBundle(context.Background(), path, map[string]bool{
		"0000000000000000000000000000000000000000000000000000000000000000": true,
	})
	if res.skip != "" {
		t.Fatalf("expected hash success, got skip=%q", res.skip)
	}
	if res.bad {
		t.Errorf("clean file incorrectly flagged as malicious; hash=%s", res.hash)
	}
}
