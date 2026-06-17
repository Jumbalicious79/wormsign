package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Jumbalicious79/wormsign/internal/ioc"
	"github.com/Jumbalicious79/wormsign/internal/report"
	"github.com/Jumbalicious79/wormsign/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	flagOutput         string
	flagExtraRoots     []string
	flagConcurrency    int
	flagMaxFileSize    int64
	flagExitOnHit      bool
	flagNoDefaultRoots bool
	flagProgress       string // "auto", "on", "off"
)

func addScanFlags(c *cobra.Command) {
	c.Flags().StringVarP(&flagOutput, "output", "o", "",
		"Markdown report path (default: wormsign-<host>-<timestamp>.md in cwd)")
	c.Flags().StringSliceVar(&flagExtraRoots, "extra-root", nil,
		"Additional root to scan (repeatable)")
	c.Flags().IntVar(&flagConcurrency, "concurrency", 0,
		"Worker pool size (default: NumCPU)")
	c.Flags().Int64Var(&flagMaxFileSize, "max-file-size", 4*1024*1024,
		"Per-file size cap for content scanning (bytes)")
	c.Flags().BoolVar(&flagExitOnHit, "exit-on-hit", true,
		"Exit with non-zero status if any HIT is recorded")
	c.Flags().BoolVar(&flagNoDefaultRoots, "no-default-roots", false,
		"Skip the built-in discovery roots; only walk --extra-root paths. Useful for testing.")
	c.Flags().StringVar(&flagProgress, "progress", "auto",
		"Live progress display: auto (on if stderr is a TTY), on, off")
}

func runScan(_ *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not resolve home dir: %w", err)
	}

	host, err := os.Hostname()
	if err != nil {
		slog.Warn("could not resolve hostname; falling back", "err", err)
		host = "unknown-host"
	}
	hostShort := strings.SplitN(host, ".", 2)[0]
	if hostShort == "" {
		hostShort = "unknown-host"
	}
	// Capture a single time.Now() so the filename timestamp matches the
	// CaptureUTC / CaptureLocal entries in the report header.
	now := time.Now()
	ts := now.Format("20060102-150405")

	// Resolve the output path into a local rather than mutating the
	// package-level flag var — the flag holds the user's input; the
	// derived default belongs in a local.
	outputPath := flagOutput
	if outputPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("could not resolve cwd: %w", err)
		}
		outputPath = filepath.Join(cwd, fmt.Sprintf("wormsign-%s-%s.md", hostShort, ts))
	}

	progressOut := resolveProgressOut(flagProgress, logQuiet)
	logger := slog.Default().With("host", hostShort)
	logger.Debug("wormsign starting",
		"output", outputPath,
		"concurrency", coalesceConcurrency(flagConcurrency),
		"home", homeDir)

	result, err := scanner.Run(ctx, scanner.Options{
		HomeDir:        homeDir,
		ExtraRoots:     flagExtraRoots,
		Concurrency:    flagConcurrency,
		MaxFileSize:    flagMaxFileSize,
		NoDefaultRoots: flagNoDefaultRoots,
		OutputPath:     outputPath,
		ProgressOut:    progressOut,
		Logger:         logger,
	})
	if err != nil {
		return err
	}

	currentUser := "unknown-user"
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}

	meta := report.Meta{
		Hostname:       host,
		MacOSVersion:   macOSVersion(ctx),
		User:           currentUser,
		CaptureUTC:     now.UTC().Format("2006-01-02 15:04:05"),
		CaptureLocal:   now.Format("2006-01-02 15:04:05 MST"),
		OutputPath:     outputPath,
		WormsignVer:    Version(),
		RepoCount:      result.Discovery.ReposCount(),
		NMCount:        result.Discovery.NodeModulesCount(),
		DiscoveryRoots: result.Roots,
		ExcludePaths:   result.Excludes,
		Coverage:       ioc.CoverageDescription,
	}

	f, err := os.Create(outputPath) // #nosec G304 -- user-supplied --output path is the report destination by design
	if err != nil {
		return fmt.Errorf("could not create report file: %w", err)
	}
	if err := result.Report.Write(f, meta); err != nil {
		_ = f.Close()
		return fmt.Errorf("could not write report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("could not close report: %w", err)
	}

	writeSummary(os.Stderr, result, outputPath)

	_, hit, _ := result.Report.Counts()
	if hit > 0 && flagExitOnHit {
		return fmt.Errorf("%d IoC hit(s) recorded — see %s", hit, outputPath)
	}
	return nil
}

// writeSummary prints a multi-line scan summary suitable for an
// interactive terminal. Numbers are pulled from the atomic counters on
// Discovery so what you see at the end matches what the progress display
// was showing while the scan ran.
func writeSummary(w io.Writer, result *scanner.Result, outputPath string) {
	d := result.Discovery
	clean, hit, skipped := result.Report.Counts()

	dirs := d.DirsVisited.Load()
	files := d.FilesVisited.Load()
	scanned := d.ContentScanned.Load()
	matches := d.ContentMatches.Load()
	hashed := d.BundlesHashed.Load()
	bad := d.BundlesBad.Load()
	repos := d.ReposCount()
	nm := d.NodeModulesCount()

	// Build the summary into a buffer and write once. Keeps errcheck
	// quiet (one ignored write vs. ten) and avoids any chance of an
	// interleaved partial summary on terminals that fight with the
	// progress redraw.
	var b strings.Builder
	b.WriteString("\n─── wormsign complete ─────────────────────────────────────\n")
	fmt.Fprintf(&b, "Duration:           %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(&b, "Filesystem walked:  %s files / %s dirs\n",
		commaInt(files), commaInt(dirs))
	fmt.Fprintf(&b, "Repos discovered:   %d (containing %d node_modules tree%s)\n",
		repos, nm, plural(nm))
	fmt.Fprintf(&b, "Content scanned:    %s files (%d matched IoC strings)\n",
		commaInt(scanned), matches)
	fmt.Fprintf(&b, "bundle.js hashed:   %d (%d matched known-malicious V1 hashes)\n",
		hashed, bad)
	fmt.Fprintf(&b, "\nResult:  %d clean · %d HIT · %d skipped\n", clean, hit, skipped)
	if hit > 0 {
		fmt.Fprintf(&b, "⚠ %d HIT(s) — review %s\n", hit, outputPath)
	} else {
		fmt.Fprintf(&b, "✓ No IoCs detected — report saved to %s\n", outputPath)
	}
	_, _ = io.WriteString(w, b.String())
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// commaInt renders a count with thousands separators. Stays out of
// scientific notation so the summary lines up nicely.
func commaInt(n int64) string {
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	out := make([]byte, 0, len(s)+len(s)/3)
	rem := len(s) % 3
	if rem > 0 {
		out = append(out, s[:rem]...)
		if len(s) > rem {
			out = append(out, ',')
		}
	}
	for i := rem; i < len(s); i += 3 {
		out = append(out, s[i:i+3]...)
		if i+3 < len(s) {
			out = append(out, ',')
		}
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// resolveProgressOut returns the writer the scanner should send live
// progress to. "auto" (the default) enables progress only when stderr
// is a real TTY and --quiet wasn't set; "on"/"off" force the choice.
func resolveProgressOut(mode string, quiet bool) io.Writer {
	if quiet {
		return nil
	}
	switch strings.ToLower(mode) {
	case "off", "false", "no", "0":
		return nil
	case "on", "true", "yes", "1":
		return os.Stderr
	default: // "auto"
		if isTerminal(os.Stderr) {
			return os.Stderr
		}
		return nil
	}
}

// isTerminal returns true if f is a character device (real TTY).
// Uses only stdlib — no third-party dep on golang.org/x/term.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func coalesceConcurrency(n int) int {
	if n <= 0 {
		return runtime.NumCPU()
	}
	return n
}

func macOSVersion(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
