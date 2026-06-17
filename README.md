# wormsign

Fast Shai-Hulud / TeamPCP / megalodon IoC hunter for macOS.

A pure-Go port of the `triage-shai-hulud-iocs.sh` host triage script. Single
filesystem walk, parallel content scanning, dataless-aware (never triggers
iCloud / Dropbox / OneDrive / Google Drive / Box downloads).

## Coverage

- Shai-Hulud V1 (Sep 2025 npm wave) — bundle.js hash check, workflow file
  presence, content-string grep, exfil domain detection
- Shai-Hulud V2 / framework (Nov 2025 + May 2026 open-source release) —
  LaunchAgent persistence, IDE persistence (tasks.json, ~/.claude), C2
  domain detection, framework string IoCs
- TeamPCP / V2.1 (May 2026) — compromised durabletask PyPI versions,
  rope.pyz second-stage, C2 domains, FIRESCALE markers
- Ambient indicators — plaintext GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_),
  credential-file presence

## Usage

```
wormsign                       # scan with defaults, write report to cwd
wormsign --output report.md    # custom report path
wormsign --extra-root /mnt/x   # add scan root (repeatable)
wormsign --concurrency 16      # tune worker pool
```

The scan is read-only. No file is modified, no command escalates, no
secret value is captured.

## Output

A Markdown report named `wormsign-<host>-<timestamp>.md` in the working
directory, summarizing every check as ✅ clean, ❌ HIT, or ⚠️ skipped.

Exit code is non-zero if any HIT was recorded.
