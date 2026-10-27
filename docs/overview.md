# cvewatch

Polls public vulnerability feeds every few hours, keeps what matters to our projects, tells Slack about new findings, and tracks whether each environment has been fixed.

## How a cycle works

1. Load config again from disk (edits apply from this cycle on).
2. Read each project's lockfiles to build the tech matrix.
3. Fetch all sources. Per-host rate limits, retries, `Retry-After` and 429 cooldowns apply. Unchanged feeds answer `304` and cost nothing.
4. For every item, build its ids (CVE, GHSA, or a hash of the URL). Known ids are skipped; new ones are judged once.
5. A new item is relevant if it mentions a tech from `techs.yaml`, or names a package from a project's lockfile. Each project that declares the tech or owns the package gets one finding per environment.
6. Write `alerts/YYYY/yyyy-mm-dd-tech-slug.md`, save state, then alert Slack.
7. Print the list of all open findings, so nothing is forgotten between alerts.

A failed source keeps its cursor and is retried next cycle. A failed Slack send is retried next cycle too, because a finding counts as alerted only after Slack accepted it.

## Layout

| Path | Purpose |
|---|---|
| `app/config/config.yaml` | interval, HTTP limits, Slack |
| `app/config/techs.yaml` | supported technologies and their aliases |
| `app/config/projects/*.yaml` | one file per project: environments, techs, lockfiles |
| `app/sources/*.yaml` | feeds to poll (`match_title_only` per source) |
| `app/src/` | Go code, one package per concern |
| `data/state.json` | all state: seen vulnerabilities, fix status, feed cursors |
| `data/audit.log` | append-only, hash-chained record of detections, alerts and status changes |
| `alerts/` | generated markdown reports |

Examples to copy: `app/config/projects/*.yaml.example`.

## Same issue, one record

Reports are merged when they share an advisory id (a news story quoting a CVE joins that CVE). Relevant reports without a shared id are merged when their titles share at least 60% of their distinctive words and are dated within 14 days. The merged record keeps every id and link, and the report lists them as "Also reported as" and "More reports". Different bugs in the same product usually stay separate because their titles differ.

## Tech filter and history

`techs.yaml` can change at any time. A change affects items first seen from the next cycle on. Items already judged are never re-judged and their findings are never touched. Items that matched nothing stay in the state as "seen", so they are skipped too.

Matching is by whole word, case-insensitive. Use explicit aliases for ambiguous names (`go` would hit many headlines, `golang` will not).

Advisories that only name a tech as a platform ("plugin for WordPress ... PHP") are the main source of noise. Give a tech `excludes`: if any exclude word or phrase also appears, the item is skipped for that tech. When a noisy finding shows up, add the word that gave it away to the tech's `excludes`.

Firehose feeds like NVD describe products by their platform ("... written in PHP"). Set `match_title_only: true` on such a source so tech matching reads only the title; the first sentence of an NVD entry names the product, so real PHP advisories still match. Lockfile package matching still reads the full text.

Lockfile packages match on the exact package name when the feed gives structured packages (GHSA). In free text only scoped names such as `symfony/http-kernel` match; bare names like `express` are too common.

Versions are recorded but not compared to advisory ranges. The plan tells people to confirm the version is affected.

## Environments

Projects list their own environments from `dev`, `int`, `staging`, `prod`; leave the list out for all four. A project such as a middleware can have just `prod`. Plans promote in that order.

## Tracking fixes

Status lives per vulnerability, project and environment: `open`, `fixed` or `ignored`. The report's checkboxes show it.

```bash
cvewatch fix CVE-2026-1234 -project shop -env dev -note "php 8.2.30"
cvewatch fix CVE-2026-1234 -project shop          # all environments
cvewatch ignore CVE-2026-1234 -project shop -note "feature disabled"
cvewatch reopen CVE-2026-1234 -project shop -env prod
```

## Running

```bash
cd app
go build -o ../cvewatch ./src/cmd/cvewatch
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...   # optional
../cvewatch check                 # validate config
../cvewatch update                # refresh all sources now, then list (run is the same)
../cvewatch update -min high      # same, but only high and critical
../cvewatch list                  # open findings, most severe first, no fetching
../cvewatch list -min medium -project shop
../cvewatch show CVE-2026-1234    # description, links, status, plan (add -json)
../cvewatch list -json             # machine-readable
../cvewatch daemon                # refresh every `interval`
../cvewatch mcp                   # MCP server for agents, see agents.md
../cvewatch audit                 # verify the audit log chain
../cvewatch version
```

The list groups open findings by severity (critical first, unrated last) and puts the newest last within each group. Items that arrived in the latest `update` are marked `NEW`. Each entry shows projects and environments, the title and the link to the original article.

Only one process may use `data/` at a time. A second one stops with an error instead of corrupting state, so run `fix` between cycles, not during.

## Limits and next steps

- State is one JSON file. Move to SQLite when it needs several writers or many years of history.
- Agents and IDEs: see `agents.md` (MCP server and JSON output).
- Slack is the only notifier. Add another by implementing `notify.Notifier`.
- Adding a feed type is one parser file in `app/src/feeds`, registered by name.
- Unix only (file locking).
- Security and privacy: see `security.md` and `compliance.md`.
