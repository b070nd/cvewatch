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
- **Your tech matrix:** a list of supported technologies (`php`, `elasticsearch`, `gitlab` ...) plus, per project, the packages in its `composer.lock` or `package-lock.json`, read fresh on every run.
- **Projects and environments:** each project has its own environments. A middleware can have only `prod`.
- **One record per issue:** reports that share a CVE id, or describe the same flaw, are merged with every link kept.
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
| `show ID [-json]` | description, links, status and plan for one issue |
| `fix` / `ignore` / `reopen ID -project P [-env E] [-note N]` | record what was done |
| `daemon` | refresh every `interval` (default 4h) |
| `mcp [-allow-write]` | MCP server on stdio |
| `check`, `audit`, `version` | validate config, verify the audit chain, print version |

`-root DIR` points at the app directory that holds `config/` and `sources/` (default: current directory).

## Know the limits

- **Matching is by text, not by version.** An item matches when it names one of your technologies as a whole word, or a package from your lockfile. The tool does not check whether your installed version falls in the affected range; the plan asks a person to confirm.
- **First runs are noisy.** Public feeds mention platforms in passing ("a WordPress plugin written in PHP"). Use `excludes` per technology, `match_title_only` per source, and `min_severity` to tune. Config edits apply to items first seen afterwards; earlier decisions are never rewritten.
- **One writer at a time.** State is one JSON file with a lock. Fine for thousands of records; not a multi-user service.
- **Unix only** (file locking).

## Security and privacy

It makes outbound requests only to the feeds you configure and to your Slack webhook, sends no telemetry, stores state with owner-only permissions, and treats all feed text as untrusted. Details, a threat model and deployment advice are in [docs/security.md](docs/security.md). How it helps with NIS2 vulnerability-handling duties and with GDPR is in [docs/compliance.md](docs/compliance.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## More

- [docs/overview.md](docs/overview.md): how a cycle works, configuration, tracking fixes
- [docs/agents.md](docs/agents.md): MCP, JSON output, a snippet for your `CLAUDE.md`
- [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 Botond Biro
