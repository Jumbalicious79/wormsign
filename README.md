# wormsign

[![CI](https://github.com/Jumbalicious79/wormsign/actions/workflows/ci.yml/badge.svg)](https://github.com/Jumbalicious79/wormsign/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Jumbalicious79/wormsign.svg)](https://pkg.go.dev/github.com/Jumbalicious79/wormsign)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jumbalicious79/wormsign)](https://goreportcard.com/report/github.com/Jumbalicious79/wormsign)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Jumbalicious79/wormsign)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Fast Shai-Hulud / TeamPCP / megalodon IoC hunter for macOS.

A pure-Go host-triage scanner for the Shai-Hulud malware family. It performs a
single filesystem walk with parallel content scanning and is dataless-aware —
it never triggers iCloud / Dropbox / OneDrive / Google Drive / Box downloads.

The scan is **read-only**: no file is modified, no command escalates, and no
secret value is captured.

## Coverage

- **Shai-Hulud V1** (Sep 2025 npm wave) — `bundle.js` hash check, workflow file
  presence, content-string grep, exfil domain detection
- **Shai-Hulud V2 / framework** (Nov 2025 + May 2026 open-source release) —
  LaunchAgent persistence, IDE persistence (`tasks.json`, `~/.claude`), C2
  domain detection, framework string IoCs
- **TeamPCP / V2.1** (May 2026) — compromised `durabletask` PyPI versions,
  `rope.pyz` second-stage, C2 domains, FIRESCALE markers
- **Ambient indicators** — plaintext GitHub tokens (`ghp_`/`gho_`/`ghu_`/
  `ghs_`/`ghr_`), credential-file presence

## Install

```sh
go install github.com/Jumbalicious79/wormsign@latest
```

Or build from source (requires Go 1.26+):

```sh
git clone https://github.com/Jumbalicious79/wormsign.git
cd wormsign
go build -o wormsign .
```

## Usage

```sh
wormsign                       # scan with defaults, write report to cwd
wormsign --output report.md    # custom report path
wormsign --extra-root /Volumes/Backup   # add scan root (repeatable)
wormsign --concurrency 16      # tune worker pool
```

Run `wormsign --help` for the full flag list.

## Output

A Markdown report named `wormsign-<host>-<timestamp>.md` in the working
directory, summarizing every check as ✅ clean, ❌ HIT, or ⚠️ skipped.

The exit code is non-zero if any HIT was recorded, so `wormsign` can gate a
CI step or a fleet-management check.

## License

[MIT](LICENSE) © 2026 Buzz Hillestad
