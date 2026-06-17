package main

import (
	"fmt"
	"os"

	"github.com/Jumbalicious79/wormsign/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// cobra runs with SilenceErrors, so the error surfaces here.
		// Print it — a triage tool that exits non-zero with no message
		// reads as "clean" to an operator and hides real failures.
		fmt.Fprintln(os.Stderr, "wormsign:", err)
		os.Exit(1)
	}
}
