package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set via -ldflags at release build time (see .goreleaser.yaml). When
// unset (e.g. `go install` or `go build` without ldflags), buildInfo
// fills them in from the binary's embedded build metadata.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// buildInfo resolves the version, commit, and build date. Values injected
// at build time via ldflags take precedence; anything still at its default
// is recovered from runtime/debug.ReadBuildInfo (which Go populates with
// the module version for `go install`, and from VCS for local builds).
func buildInfo() (ver, cmt, built string) {
	ver, cmt, built = version, commit, date
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ver, cmt, built
	}
	if ver == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		ver = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if cmt == "unknown" && s.Value != "" {
				cmt = s.Value
			}
		case "vcs.time":
			if built == "unknown" && s.Value != "" {
				built = s.Value
			}
		}
	}
	return ver, cmt, built
}

// Version returns the resolved version string for use in report metadata.
func Version() string {
	v, _, _ := buildInfo()
	return v
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		ver, cmt, built := buildInfo()
		fmt.Printf("wormsign %s\n", ver)
		fmt.Printf("  commit: %s\n", cmt)
		fmt.Printf("  built:  %s\n", built)
		return nil
	},
}
