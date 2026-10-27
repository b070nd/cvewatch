# cvewatch

A small vulnerability monitor. It reads public security feeds every few hours, keeps what matters to your projects, tells Slack about new findings, and tracks whether each environment (dev, int, staging, prod) has been fixed.

```
Open findings: 3

CRITICAL (1)
  NEW CVE-2026-109618    shop: dev,int,staging,prod  (+3 related)
      PHP Group PHP: PHP Memory Corruption Vulnerability
      https://nvd.nist.gov/vuln/detail/CVE-2026-109618

HIGH (2)
  ...
```

## What it does

- **Sources:** CISA KEV, NVD, GitHub advisories, Hacker News, any RSS or Atom feed. Add a source with a few lines of YAML.
- **Version-aware:** NVD product data and GitHub advisory ranges are compared with the versions you run: `affected`, `not affected` or `unchecked`.
- **Fix evidence:** patched versions, vendor advisories and required actions from the feeds, marked official when a vendor or authority says so.
- **Your tech matrix:** a list of supported technologies (`php`, `elasticsearch`, `gitlab` ...) plus, per project, the packages in its `composer.lock` or `package-lock.json`, read fresh on every run.
- **Projects and environments:** each project has its own environments. A middleware can have only `prod`.
- **One record per issue:** reports that share a CVE id, or describe the same flaw, are merged. Age since publication, the number of articles and the articles in chronological order are kept per issue.
- **Calendar:** a month overview with severity colors, technology tags and a legend.
- **Fix tracking:** status per issue, project and environment (`open`, `fixed`, `ignored`) with a rollout plan in a markdown report.
- **Alerts:** Slack for new findings, and a list of everything still open after every run. Works without Slack.
- **Agents and IDEs:** JSON output and an MCP server (read-only by default).
- **Audit trail:** tamper-evident log of detections, alerts and status changes.

## Quick start

You need Go (see `app/go.mod`) or Docker.

```bash
cd app
go build -o ../cvewatch ./src/cmd/cvewatch

cp config/projects/shop.yaml.example config/projects/myproject.yaml   # edit it
../cvewatch check
../cvewatch update         # fetch now, then list
../cvewatch daemon         # or keep it running
```

Or install the binary with Go (it still needs the `config/` and `sources/` folders from this repository; point `-root` at them):

```bash
go install github.com/b070nd/cvewatch/app/src/cmd/cvewatch@latest
```

With Docker, see `compose.yaml`: mount your project configs read-only, keep the data in a volume.

Slack is optional. Set the webhook in the environment, never in a file:

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## Everyday commands

| Command | Purpose |
|---|---|
| `update [-min S] [-project P]` | refresh all sources, then list open findings |
| `list [-min S] [-project P] [-json]` | open findings, most severe first |
| `show ID [-json]` | description, fix, articles in order, status and plan for one issue |
| `why ID` | why it matched, and what today's config says |
| `rescan [-apply]` | look back at old items with today's config (dry run unless `-apply`) |
| `calendar [-month YYYY-MM] [-text]` | month overview page or terminal grid |
| `fix` / `ignore` / `reopen ID -project P [-env E] [-note N]` | record what was done |
| `daemon` | refresh every `interval` (default 4h) |
| `mcp [-allow-write]` | MCP server on stdio |
| `check`, `audit`, `version` | validate config, verify the audit chain, print version |

`-root DIR` points at the app directory that holds `config/` and `sources/` (default: current directory).

## Know the limits

- **Versions are checked only where feeds give ranges.** NVD product data and GitHub advisories do; news and Hacker News do not, so those findings stay `unchecked` and a person confirms. Check the CPE names in `techs.yaml` against the NVD CPE dictionary: a wrong name hides real advisories.
- **First runs are noisy.** Public feeds mention platforms in passing ("a WordPress plugin written in PHP"). CPE names, `excludes`, `match_structured` and `match_title_only` per source, and `min_severity` tune it. Config edits apply to items first seen afterwards; `rescan` looks back on purpose.
- **Fixes are what feeds say.** The tool does not query package registries or container image registries.
- **One writer at a time.** State is one JSON file with a lock, behind a storage seam. Several people can use one install through optional per-actor access rules; that is authorization on a local identity, not authentication.
- **Linux, macOS, Windows.** On Windows owner-only file modes are not enforced by the OS; see the docs.

## Security and privacy

It makes outbound requests only to the feeds you configure and to your Slack webhook, sends no telemetry, stores state with owner-only permissions, and treats all feed text as untrusted. Details, a threat model and deployment advice are in [docs/security.md](docs/security.md). How it helps with NIS2 vulnerability-handling duties and with GDPR is in [docs/compliance.md](docs/compliance.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## More

- [docs/overview.md](docs/overview.md): how a cycle works, matching and versions, configuration, tracking fixes
- [docs/architecture.md](docs/architecture.md): modules and seams
- [docs/agents.md](docs/agents.md): MCP, JSON output, a snippet for your `CLAUDE.md`
- [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 Botond Biro
