package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	logVerbose bool
	logQuiet   bool
	logFormat  string
)

var rootCmd = &cobra.Command{
	Use:   "wormsign",
	Short: "Fast Shai-Hulud / TeamPCP / megalodon IoC hunter for macOS",
	Long: "wormsign is a read-only macOS host-triage scanner for the Shai-Hulud\n" +
		"malware family (V1 npm wave, V2 framework, V2.1 TeamPCP/durabletask).\n" +
		"It walks the filesystem once, scans content in parallel, and writes a\n" +
		"Markdown triage report. Dataless cloud placeholders are skipped — the\n" +
		"scan will never trigger an iCloud / Dropbox / OneDrive download.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level := slog.LevelInfo
		if logVerbose {
			level = slog.LevelDebug
		} else if logQuiet {
			level = slog.LevelWarn
		}
		opts := &slog.HandlerOptions{Level: level}
		var handler slog.Handler
		switch logFormat {
		case "json":
			handler = slog.NewJSONHandler(os.Stderr, opts)
		case "text":
			handler = slog.NewTextHandler(os.Stderr, opts)
		default:
			return fmt.Errorf("invalid --log-format %q: must be text or json", logFormat)
		}
		slog.SetDefault(slog.New(handler))
		return nil
	},
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&logVerbose, "verbose", "v", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&logQuiet, "quiet", "q", false, "Only show warnings and errors")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "Log format: text or json")

	addScanFlags(rootCmd)
	rootCmd.AddCommand(versionCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
