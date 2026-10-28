# cvewatch

Exposure and fix tracking for software factories. It watches the feeds that matter to your stack, tracks **open / fixed / ignored per project and environment**, and keeps the evidence local.

It complements scanners (Trivy, Grype, OSV-Scanner) and SBOM platforms (Dependency-Track); it does not replace them and does not scan anything. Its job is the one they leave open: which of your projects and environments are still exposed to which known issue, who owns it, and what happened so far.

```
Open findings: 3

CRITICAL (2)
  NEW CVE-2026-109618    shop: dev,int,staging,prod  [affected]  (+1 ids)
      PHP Group PHP: PHP Memory Corruption Vulnerability
      published 6d 9h ago · 2 articles · KEV, CISA due 2026-10-29 · EPSS 100% · official fix: action
      https://thehackernews.com/...
```

## What it does

- **Sources:** CISA KEV, NVD, GitHub advisories, Hacker News, any RSS or Atom feed. Built in; add more with a few lines of YAML.
- **Inventory:** declared techs with per-environment versions, plus lockfiles and SBOMs: composer, npm, Go, pip, poetry, Pipfile, Gradle, Maven, CycloneDX, SPDX.
- **Version-aware:** NVD product data and advisory ranges are compared with what each environment runs: `affected`, `not affected` or `unchecked`, using each ecosystem's own version rules.
- **One record per issue:** reports about the same flaw are merged, with age, article count, articles in order, fix evidence, KEV listing and EPSS.
- **Per-environment tracking:** status, owner, due date, ticket and evidence per project and environment, with a history of every change.
- **Priority and policy:** KEV first, then severity, open in prod, EPSS, age; policy rules report missed deadlines.
- **Alerts:** Slack, signed webhook and email, each tracked separately, plus a daily digest.
- **Evidence and exports:** an evidence pack per issue, and `export` as JSON (versioned schema), CSV or Markdown.
- **Agents and IDEs:** JSON and an MCP server (read-only by default). **Audit trail:** tamper-evident log of detections, alerts and changes.

## Quick start

```bash
go install github.com/b070nd/cvewatch/app/src/cmd/cvewatch@latest     # or a release binary, or Docker (compose.yaml)

mkdir cvewatch-home && cd cvewatch-home
cvewatch init -repo /path/to/your/repo     # writes config, detects lockfiles and runtime versions
cvewatch doctor                            # checks everything; -online also checks CPE names and feeds
cvewatch update                            # fetch now, then list
cvewatch daemon                            # or keep it running
```

One binary is enough; the technology list and feeds are built in. Slack is optional: set `SLACK_WEBHOOK_URL`, never put it in a file. Other channels, digest, policy, SQLite and EPSS are in [docs/overview.md](docs/overview.md).

## Everyday commands

| Command | Purpose |
|---|---|
| `update`, `list [-min S] [-project P] [-env E] [-all] [-json]` | refresh and list open findings, most urgent first |
| `show ID`, `why ID`, `evidence ID` | description and plan; why it matched; evidence pack with timeline |
| `fix`, `ignore`, `not-affected`, `reopen ID -project P [-env E] -note N` | record what was done (`not-affected` needs a reason) |
| `assign ID -project P [-env E] -owner O -due DATE -ticket T` | who handles it and by when |
| `evidence add ID -project P -note N -url U` | attach a note and link as evidence |
| `export -format json\|csv\|md`, `policy`, `digest [-send]`, `calendar` | reports |
| `inventory`, `rescan [-apply]` | what runs where; look back with today's config |
| `init`, `doctor`, `check`, `audit`, `version`, `daemon`, `mcp` | setup, health, operations |

`-root DIR` points at the configuration folder (default: the current one).

## Know the limits

- **Versions are checked only where feeds give ranges, and only for what you tell it runs.** NVD product data and GitHub advisories do; news and Hacker News do not, so those findings stay `unchecked` and a person confirms. Check the CPE names in `techs.yaml` against the NVD CPE dictionary: a wrong name hides real advisories.
- **First runs are noisy.** Public feeds mention platforms in passing ("a WordPress plugin written in PHP"). CPE names, `excludes`, `match_structured` and `match_title_only` per source, and `min_severity` tune it. Config edits apply to items first seen afterwards; `rescan` looks back on purpose.
- **Fixes are what feeds say.** The tool does not query package or container registries, and does not scan images. Image references are recorded, not verified.
- **State is a JSON file by default** (one process at a time) or SQLite (several processes, stale writes refused). Optional per-actor access rules are authorization on a local identity, not authentication.
- **Linux, macOS, Windows.** On Windows owner-only file modes are not enforced by the OS; see the docs.

## Security and privacy

It makes outbound requests only to the feeds you configure and to your Slack webhook, sends no telemetry, stores state with owner-only permissions, and treats all feed text as untrusted. Details, a threat model and deployment advice are in [docs/security.md](docs/security.md). How it helps with NIS2 vulnerability-handling duties and with GDPR is in [docs/compliance.md](docs/compliance.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## More

- [docs/overview.md](docs/overview.md): how it works, inventory, matching, tracking, policy, channels, storage
- [docs/architecture.md](docs/architecture.md): modules and seams
- [docs/agents.md](docs/agents.md): MCP, JSON output, a snippet for your `CLAUDE.md`
- [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 Botond Biro
