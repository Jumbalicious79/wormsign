// Package ioc holds the indicator-of-compromise corpus for the Shai-Hulud /
// Sha1-Hulud / TeamPCP family. Sources are Wiz, Datadog Security Labs,
// Checkmarx, Microsoft Security Blog, Phoenix Security, Unit 42, Tenable,
// SentinelOne, Sumologic, Semgrep, The Hacker News, SafeDep, Aikido,
// StepSecurity, Hunt.io, Endor Labs, ReversingLabs, JFrog, Orca, Snyk.
//
// Wave taxonomy (matches the consensus naming in published writeups):
//
//	V1                  Sep 14-16 2025  Shai-Hulud V1 npm worm (webhook.site exfil)
//	V2 / Sha1-Hulud     Nov 21-26 2025  "Sha1-Hulud: The Second Coming" npm worm
//	                                    (preinstall + setup_bun.js + bun_environment.js)
//	Mini Shai-Hulud     May 11-12 2026  TeamPCP TanStack/Mistral/Cemu wave
//	                                    (git-tanstack.com C2, FIRESCALE fallback)
//	Durabletask         May 19-20 2026  TeamPCP PyPI hijack of `durabletask`
//	                                    (rope.pyz from check.git-service.com)
package ioc

// CoverageDescription is a one-line description of what this corpus
// covers. Embedded in the report header so any future corpus addition
// must update this string in the same file.
const CoverageDescription = "Shai-Hulud V1 (Sep 2025 npm wave) + Sha1-Hulud V2 / \"The Second Coming\" (Nov 2025) + Mini Shai-Hulud / TeamPCP TanStack wave (May 11-12 2026, incl. `.claude/`+`.vscode/` IDE persistence) + TeamPCP durabletask PyPI wave (2026-05-19) + ambient `ghp_/gho_` token scan"

// --- Domain IoCs grouped by wave ----------------------------------------

// DomainsV1 — Shai-Hulud V1 webhook.site exfil URL (Sep 2025 npm wave).
var DomainsV1 = []string{
	"webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
}

// DomainsMini — Mini Shai-Hulud / TeamPCP TanStack wave (May 11-12, 2026).
// Hits TanStack, Mistral AI, OpenSearch, Cemu, et al. C2 on 443 with path
// `/router`; FIRESCALE GitHub-commit-msg-based fallback. Previously
// mislabelled "V2 framework" — there is no public framework; this is a
// self-propagating worm attributed by Wiz/Snyk/Akamai/Hunt.io to TeamPCP.
var DomainsMini = []string{
	"git-tanstack.com",
	"api.masscan.cloud",
	"filev2.getsession.org",
	"seed1.getsession.org",
}

// DomainsDurabletask — TeamPCP durabletask PyPI wave (May 19-20, 2026).
// Primary + fallback C2 for the rope.pyz second-stage payload, per Wiz,
// Phoenix, StepSecurity, Aikido, The Hacker News.
var DomainsDurabletask = []string{
	"check.git-service.com",
	"t.m-kosche.com",
}

// IPs — known C2 IPs. 83.142.209.194 / 83.142.209.0/24 is attributed to
// the Mini Shai-Hulud TanStack-wave infrastructure (Wiz, Hunt.io, Orca,
// Datadog, Rescana, ThreatLocker), not V1.
var IPs = []string{
	"83.142.209.194",
}

// AllDomains returns the union of every wave's domain IoCs.
func AllDomains() []string {
	out := make([]string, 0, len(DomainsV1)+len(DomainsMini)+len(DomainsDurabletask))
	out = append(out, DomainsV1...)
	out = append(out, DomainsMini...)
	out = append(out, DomainsDurabletask...)
	return out
}

// --- Content-string IoCs ------------------------------------------------

// HighSignalStrings — only legitimately appear in malware source or in
// security-research material. A hit on a user host is meaningful.
var HighSignalStrings = []string{
	// V1 (Sep 2025)
	"Shai-Hulud Migration",
	"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
	"shai-hulud-workflow.yml",
	// V2 / Sha1-Hulud (Nov 2025) — the canonical repo-description string
	// the worm publishes is "Sha1-Hulud" with the digit 1, per Datadog,
	// Tenable, Semgrep, SentinelOne, Sumologic, Unit 42. The "Shai-Hulud"
	// spelling appears in some prose writeups; keep both.
	"Sha1-Hulud: The Second Coming",
	"Shai-Hulud: The Second Coming",
	"setup_bun.js",
	"bun_environment.js",
	// Mini Shai-Hulud / TeamPCP TanStack (May 2026)
	"IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
	"thebeautifulmarchoftime",
	"TheBeautifulSandsOfTime",
	"h=megalodon",
	"Shai-Hulud: Here We Go Again",
	"kitty-monitor",
	// Durabletask / TeamPCP (May 19-20, 2026)
	"FIRESCALE",
	"rope.pyz",
	"xploitrsturtle2",
}

// LowSignalStrings — case-insensitive; can appear in legitimate research
// or awareness materials. A hit is a flag for human review.
var LowSignalStrings = []string{
	"shai-hulud",
	"sha1-hulud",
	"megalodon",
	"teampcp",
}

// --- Persistence-file IoCs ----------------------------------------------

// PersistenceFiles — exact paths the malware writes for persistence.
// Caller must expand the {HOME} placeholder.
var PersistenceFiles = []string{
	// V1 staging scripts (Sep 2025)
	"/tmp/processor.sh",
	"/tmp/migrate-repos.sh",
	"/tmp/github-migration",
	"/private/tmp/processor.sh",
	"/private/tmp/migrate-repos.sh",
	"/private/tmp/github-migration",
	// Mini Shai-Hulud / TeamPCP TanStack (May 2026)
	// LaunchAgent for the gh-token-monitor daemon — exact filename
	// originated in our bash-script corpus and has not been independently
	// confirmed by a public IoC list; keep for now, flag for re-validation
	// when authoritative IoC lists land.
	"{HOME}/Library/LaunchAgents/com.user.gh-token-monitor.plist",
	// The Mini Shai-Hulud IDE-persistence drop (`.claude/setup.mjs`,
	// `.claude/execution.js`, `.vscode/setup.mjs`) is NOT an exact home
	// path — the worm commits these into per-project `.claude/` and
	// `.vscode/` directories (Phoenix Security, StepSecurity, Picus,
	// Microsoft). That drop site is detected by §2 IDE-based persistence
	// via IDELoaderFileNames, which scans every walked repo, not just
	// `{HOME}/.claude/`.
	// /tmp/managed.pyz is the initial Mini-wave payload drop per Hunt.io
	// FIRESCALE writeup; .sys-update-check is the propagation marker
	// (kill-switch file).
	"/tmp/managed.pyz",
	"/private/tmp/managed.pyz",
	"{HOME}/.cache/.sys-update-check",
}

// --- Hash IoCs ----------------------------------------------------------

// HashesV1 — known-malicious SHA-256 hashes of V1 bundle.js payloads.
// Canonical hash confirmed by Wiz, Socket, StepSecurity, Checkmarx,
// Phoenix.
var HashesV1 = []string{
	"46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
}

// HashesV2 — known-malicious SHA-256 hashes of Sha1-Hulud (Nov 2025)
// payloads (bun_environment.js / setup_bun.js variants). Published by
// Datadog Security Labs in
// github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0.
var HashesV2 = []string{
	"62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
	"cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
	"f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
}

// AllPayloadHashes returns the union of every wave's payload hash IoCs.
// Used by the hash-check pass to test bundle.js / setup_bun.js /
// bun_environment.js candidates against every known-bad SHA-256 at once.
func AllPayloadHashes() []string {
	out := make([]string, 0, len(HashesV1)+len(HashesV2))
	out = append(out, HashesV1...)
	out = append(out, HashesV2...)
	return out
}

// --- Search / discovery configuration -----------------------------------

// SearchDirs — directories the malware drops files in. Content greps
// look here in addition to every discovered repo. Caller expands {HOME}.
var SearchDirs = []string{
	"{HOME}/.claude",
	"{HOME}/.cursor",
	"{HOME}/.vscode",
	"{HOME}/.kiro",
	"{HOME}/.config",
	"{HOME}/.npm",
	"{HOME}/.local",
	"{HOME}/.cache",
	"{HOME}/Library/LaunchAgents",
	"/tmp",
	"/var/tmp",
	"/private/tmp",
	"/private/var/tmp",
}

// DiscoveryRoots — where to look for git repos + node_modules. Caller
// expands {HOME}.
var DiscoveryRoots = []string{
	"{HOME}",
	"{HOME}/Library/Mobile Documents",
	"{HOME}/Library/CloudStorage",
	"{HOME}/Dropbox",
	"{HOME}/OneDrive",
	"{HOME}/Google Drive",
	"/Volumes",
	"/opt",
	"/usr/local/lib/node_modules",
	"/Users/Shared",
}

// ExcludePaths — pruned during the walk to keep runtime bounded.
var ExcludePaths = []string{
	"/System",
	"/Library",
	"{HOME}/Library/Caches",
	"{HOME}/Library/Containers",
	"{HOME}/Library/Group Containers",
}

// CredentialTargets — files the malware's FileSystemService reads. We
// record presence + mtime + size, never content.
var CredentialTargets = []string{
	"{HOME}/.npmrc",
	"{HOME}/.pypirc",
	"{HOME}/.yarnrc",
	"{HOME}/.yarnrc.yml",
	"{HOME}/.claude.json",
	"{HOME}/.claude/mcp.json",
	"{HOME}/.kiro/settings/mcp.json",
	"{HOME}/.config/gh/hosts.yml",
	"{HOME}/.config/gh/config.yml",
	"{HOME}/.config/git/credentials",
	"{HOME}/.git-credentials",
	"{HOME}/.aws/credentials",
	"{HOME}/.azure/accessTokens.json",
	"{HOME}/.kube/config",
	"{HOME}/.docker/config.json",
	"{HOME}/.ssh/id_ed25519",
	"{HOME}/.ssh/id_rsa",
	"{HOME}/.ssh/config",
	"{HOME}/Library/Application Support/Code/User/globalStorage/vscode.github-authentication",
	"{HOME}/Library/Application Support/Cursor/User/globalStorage/vscode.github-authentication",
}

// BrowserHistoryDBs — Chromium-family browsers' history sqlite databases.
// Safari uses a different schema and is handled separately. Caller expands
// {HOME}.
var BrowserHistoryDBs = []string{
	"{HOME}/Library/Application Support/Google/Chrome/Default/History",
	"{HOME}/Library/Application Support/Microsoft Edge/Default/History",
	"{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
	"{HOME}/Library/Application Support/Arc/User Data/Default/History",
}

// SafariHistoryDB path (different schema).
const SafariHistoryDB = "{HOME}/Library/Safari/History.db"

// FirefoxProfilesGlob — glob pattern under each profile.
const FirefoxProfilesGlob = "{HOME}/Library/Application Support/Firefox/Profiles/*/places.sqlite"

// --- PyPI / Python dep-file matching ------------------------------------

// BadDurabletaskVersions — TeamPCP-compromised PyPI durabletask versions
// (1.4.1, 1.4.2, 1.4.3 pushed in a 35-minute window on 2026-05-19).
var BadDurabletaskVersions = []string{
	"1.4.1",
	"1.4.2",
	"1.4.3",
}

// RequirementsFileNames — filenames we inspect for malicious durabletask pins.
var RequirementsFileNames = map[string]bool{
	"pyproject.toml": true,
	"poetry.lock":    true,
	"uv.lock":        true,
	"Pipfile":        true,
	"Pipfile.lock":   true,
}

// RequirementsFilePrefixes — filename prefixes we inspect.
// (requirements*.txt and constraints*.txt match this way.)
var RequirementsFilePrefixes = []string{
	"requirements",
	"constraints",
}

// --- Filenames the walker flags ----------------------------------------

// PayloadFileNames — filenames the walker queues for SHA-256 hashing
// against AllPayloadHashes(). bundle.js is the V1 payload; setup_bun.js
// and bun_environment.js are the Sha1-Hulud / V2 worm files injected via
// a `preinstall` script.
var PayloadFileNames = map[string]bool{
	"bundle.js":          true,
	"setup_bun.js":       true,
	"bun_environment.js": true,
}

// IDELoaderFileNames — the loader / payload filenames the Mini Shai-Hulud
// worm (May 2026 TeamPCP wave) commits into a project's `.claude/` and
// `.vscode/` directories and re-executes via a Claude `SessionStart` hook
// (`.claude/settings.json`) and a VS Code `folderOpen` task
// (`.vscode/tasks.json`). `setup.mjs` is the ~4.5 KB Bun loader that
// downloads Bun 1.3.13 and launches `execution.js`, the ~11.6 MB
// obfuscated infostealer payload. `setup_bun.js` / `bun_environment.js`
// are the Sha1-Hulud V2 equivalents. The §2 IDE-persistence check treats
// any of these names *inside a `.claude/` or `.vscode/` directory* as a
// hit — far more precise than flagging every `.mjs` under `~/.claude/`,
// which false-positives on legitimate Claude Code plugin code. Sources:
// Phoenix Security, StepSecurity, SafeDep, Picus, Microsoft Security Blog
// (Mini Shai-Hulud writeups, May 2026).
var IDELoaderFileNames = map[string]bool{
	"setup.mjs":          true,
	"execution.js":       true,
	"setup_bun.js":       true,
	"bun_environment.js": true,
}
