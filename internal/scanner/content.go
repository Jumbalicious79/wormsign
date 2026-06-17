package scanner

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Jumbalicious79/wormsign/internal/fsutil"
	"github.com/Jumbalicious79/wormsign/internal/ioc"
)

// ContentMatch describes a single per-file scan result. Either StringMatches
// or TokenMatches will be non-empty; both can be set if the file matches
// in multiple categories.
type ContentMatch struct {
	Path          string
	StringMatches []StringHit // high+low signal IoC strings that matched
	TokenMatches  []string    // distinct GitHub-token-like strings found
}

// StringHit identifies one IoC-string match within a file.
type StringHit struct {
	IoC       string // the matching IoC literal
	Line      string // the matching line (trimmed)
	LowSignal bool   // true if matched against the low-signal (case-insensitive) corpus
}

// contentScanner holds the precompiled regexes used for content scans.
// Compile once, reuse across all files in the queue.
type contentScanner struct {
	highSigRE *regexp.Regexp
	lowSigRE  *regexp.Regexp
	tokenRE   *regexp.Regexp

	// Maps to identify which IoC literal a regex match corresponds to.
	highSigSet []string // exact literals; used to identify the matching IoC
	lowSigSet  []string

	maxFileSize int64
}

// newContentScanner builds a scanner with the default IoC corpus and
// limits. maxFileSize defaults to 4 MiB; files larger than that are
// skipped (Shai-Hulud bundle.js is ~kilobytes, framework strings live
// in source, no benefit to scanning huge media or binary blobs).
func newContentScanner() *contentScanner {
	highRE := regexp.MustCompile(buildAlternation(ioc.HighSignalStrings, false))
	lowRE := regexp.MustCompile(buildAlternation(ioc.LowSignalStrings, true))
	// Word boundary at both ends matches the bash script's `\b(...)_[A-Za-z0-9]{20,}\b`
	// and avoids false positives where a token-like substring is embedded
	// in a larger alphanumeric identifier (e.g. `xghp_AAAAA…` in minified JS).
	tokenRE := regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`)
	return &contentScanner{
		highSigRE:   highRE,
		lowSigRE:    lowRE,
		tokenRE:     tokenRE,
		highSigSet:  append([]string(nil), ioc.HighSignalStrings...),
		lowSigSet:   append([]string(nil), ioc.LowSignalStrings...),
		maxFileSize: 4 * 1024 * 1024,
	}
}

// buildAlternation produces an alternation regex source from a list of
// literal IoC strings. Each token is regexp.QuoteMeta'd so dots and
// punctuation are safe. If insensitive is true, an inline (?i) flag is
// prepended.
func buildAlternation(tokens []string, insensitive bool) string {
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = regexp.QuoteMeta(t)
	}
	pattern := strings.Join(parts, "|")
	if insensitive {
		return "(?i)" + pattern
	}
	return pattern
}

// ScanFiles concurrently scans every path in `paths` for IoC content.
// When d is non-nil, ContentScanned and ContentMatches counters are
// updated so a Progress display can show live throughput.
func (cs *contentScanner) ScanFiles(ctx context.Context, d *Discovery, paths []string, concurrency int) []ContentMatch {
	if concurrency <= 0 {
		concurrency = max(4, runtime.NumCPU())
	}
	if len(paths) == 0 {
		return nil
	}

	in := make(chan string, concurrency*4)
	out := make(chan ContentMatch, concurrency*4)
	var wg sync.WaitGroup

	// Workers drain `in` until it's closed. On ctx cancel they keep
	// draining (skipping work) so the producer never blocks on a send.
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range in {
				if ctx.Err() != nil {
					continue
				}
				m, matched, scanned := cs.scanOne(p)
				if d != nil {
					if scanned {
						d.ContentScanned.Add(1)
					}
					if matched {
						d.ContentMatches.Add(1)
					}
				}
				if matched {
					out <- m
				}
			}
		}()
	}

	// Producer: select on ctx.Done() AND the channel send so cancellation
	// while the buffer is full doesn't deadlock.
	go func() {
		defer close(in)
		for _, p := range paths {
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

	var results []ContentMatch
	for m := range out {
		results = append(results, m)
	}
	return results
}

// scanOne opens a single file (only if it has content on disk and is
// under the size cap), reads it, and applies all IoC regexes. Returns
// three values:
//
//	match    — the ContentMatch if any IoC fired (zero value otherwise)
//	matched  — true iff `match` is meaningful
//	scanned  — true iff the file was actually opened and regex-tested
//	           (false for dataless / oversize / binary / unreadable skips)
//
// The caller uses `scanned` to update the throughput counter so the
// summary's "Content scanned" reflects real work, not queue size.
func (cs *contentScanner) scanOne(path string) (match ContentMatch, matched, scanned bool) {
	if fsutil.IsDataless(path) {
		return ContentMatch{}, false, false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ContentMatch{}, false, false
	}
	if info.Size() == 0 || info.Size() > cs.maxFileSize {
		return ContentMatch{}, false, false
	}

	// os.ReadFile handles partial reads, short-read retries, and close
	// in one call. Saves us tracking f.Read's `n` and a manual close.
	buf, err := os.ReadFile(path) // #nosec G304 -- scanner reads arbitrary discovered files
	if err != nil {
		return ContentMatch{}, false, false
	}
	if int64(len(buf)) > cs.maxFileSize {
		// File grew between Lstat and ReadFile; cap it.
		buf = buf[:cs.maxFileSize]
	}

	// Binary heuristic: NUL byte in the first 512 bytes -> skip.
	head := buf
	if len(head) > 512 {
		head = head[:512]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return ContentMatch{}, false, false
	}

	scanned = true

	res := ContentMatch{Path: path}

	if locs := cs.highSigRE.FindAllIndex(buf, -1); locs != nil {
		seen := make(map[string]bool)
		for _, loc := range locs {
			matched := string(buf[loc[0]:loc[1]])
			label := identifyMatch(matched, cs.highSigSet, false)
			line := extractLine(buf, loc[0])
			key := label + "|" + line
			if seen[key] {
				continue
			}
			seen[key] = true
			res.StringMatches = append(res.StringMatches, StringHit{IoC: label, Line: line})
		}
	}

	if locs := cs.lowSigRE.FindAllIndex(buf, -1); locs != nil {
		seen := make(map[string]bool)
		for _, loc := range locs {
			matched := string(buf[loc[0]:loc[1]])
			label := identifyMatch(matched, cs.lowSigSet, true)
			line := extractLine(buf, loc[0])
			key := label + "|" + line
			if seen[key] {
				continue
			}
			seen[key] = true
			res.StringMatches = append(res.StringMatches, StringHit{IoC: label, Line: line, LowSignal: true})
		}
	}

	if locs := cs.tokenRE.FindAllIndex(buf, -1); locs != nil {
		seen := make(map[string]bool)
		for _, loc := range locs {
			tok := string(buf[loc[0]:loc[1]])
			// Redact tail to avoid embedding the actual token in the report.
			if len(tok) > 8 {
				tok = tok[:8] + "…(redacted)"
			}
			if seen[tok] {
				continue
			}
			seen[tok] = true
			res.TokenMatches = append(res.TokenMatches, tok)
		}
	}

	if len(res.StringMatches) == 0 && len(res.TokenMatches) == 0 {
		return ContentMatch{}, false, scanned
	}
	return res, true, scanned
}

// identifyMatch finds which IoC literal a matched substring corresponds
// to. For case-sensitive sets, this is direct equality; for the
// low-signal case-insensitive set, lower-case both sides.
func identifyMatch(matched string, set []string, insensitive bool) string {
	if insensitive {
		m := strings.ToLower(matched)
		for _, s := range set {
			if strings.ToLower(s) == m {
				return s
			}
		}
	} else {
		for _, s := range set {
			if s == matched {
				return s
			}
		}
	}
	return matched
}

// extractLine pulls the line containing the byte at offset, trimming
// surrounding whitespace and capping length so the report stays
// readable.
func extractLine(buf []byte, offset int) string {
	start := offset
	for start > 0 && buf[start-1] != '\n' {
		start--
	}
	end := offset
	for end < len(buf) && buf[end] != '\n' {
		end++
	}
	line := strings.TrimSpace(string(buf[start:end]))
	const maxRunes = 240
	if utf8.RuneCountInString(line) > maxRunes {
		// Rune-safe truncate so we don't slice in the middle of a
		// multi-byte glyph (BOMs, UTF-8 comments in source, etc.).
		runes := []rune(line)
		line = string(runes[:maxRunes]) + "…"
	}
	return line
}
