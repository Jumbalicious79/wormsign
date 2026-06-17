package scanner

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// progress draws a single-line live status to out (typically stderr).
// out == nil disables the display. Counters are read from Discovery
// atomically while the walk and downstream checks are running.
type progress struct {
	d        *Discovery
	out      io.Writer
	startAt  time.Time
	interval time.Duration
	phase    atomic.Pointer[string]

	stopCh chan struct{}
	doneCh chan struct{}
}

func newProgress(d *Discovery, out io.Writer) *progress {
	p := &progress{
		d:        d,
		out:      out,
		startAt:  time.Now(),
		interval: 200 * time.Millisecond,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	initial := "walking"
	p.phase.Store(&initial)
	return p
}

func (p *progress) setPhase(phase string) {
	p.phase.Store(&phase)
}

func (p *progress) start() {
	if p.out == nil {
		close(p.doneCh)
		return
	}
	go func() {
		defer close(p.doneCh)
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for {
			select {
			case <-p.stopCh:
				p.draw()
				// Newline so the final summary that follows is on its own line.
				_, _ = io.WriteString(p.out, "\n")
				return
			case <-t.C:
				p.draw()
			}
		}
	}()
}

func (p *progress) stop() {
	if p.out == nil {
		return
	}
	close(p.stopCh)
	<-p.doneCh
}

// draw emits one progress line, overwriting the previous one with \r
// and erase-to-end-of-line. Counter slots are skipped when zero so the
// line stays readable during the early walk phase.
func (p *progress) draw() {
	elapsed := time.Since(p.startAt)
	phase := *p.phase.Load()

	dirs := p.d.DirsVisited.Load()
	files := p.d.FilesVisited.Load()
	repos := p.d.ReposCount()
	nm := p.d.NodeModulesCount()
	scanned := p.d.ContentScanned.Load()
	matches := p.d.ContentMatches.Load()
	queued := p.d.ContentQueueCount()
	hashed := p.d.BundlesHashed.Load()

	// Writes are TTY redraws; we don't care about transient write errors
	// (broken pipe, terminal disconnect). Discard error to satisfy
	// errcheck.
	var b strings.Builder
	// \r + CSI 2K = carriage return + clear entire line, so the next
	// write fully replaces the previous line regardless of length delta.
	fmt.Fprintf(&b, "\r\x1b[2K%s… %s · %s files · %s dirs · %d repos · %d nm",
		phase, fmtElapsed(elapsed),
		humanInt(files), humanInt(dirs), repos, nm)
	if scanned > 0 || queued > 0 {
		if queued > 0 {
			fmt.Fprintf(&b, " · %s/%s scanned", humanInt(scanned), humanInt(int64(queued)))
		} else {
			fmt.Fprintf(&b, " · %s scanned", humanInt(scanned))
		}
		if matches > 0 {
			fmt.Fprintf(&b, " · %d matches", matches)
		}
	}
	if hashed > 0 {
		fmt.Fprintf(&b, " · %d hashed", hashed)
	}
	_, _ = p.out.Write([]byte(b.String()))
}

func fmtElapsed(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%4.1fs", d.Seconds())
	}
	m := int(d / time.Minute)
	s := int(d/time.Second) % 60
	return fmt.Sprintf("%dm%02ds", m, s)
}

// humanInt formats a count with k/M suffixes for readability.
func humanInt(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 10_000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	case n < 1_000_000:
		return fmt.Sprintf("%dk", n/1000)
	case n < 10_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%dM", n/1_000_000)
	}
}
