# cvewatch

Polls public vulnerability feeds every few hours, keeps what matters to your projects, tells Slack about new findings, and tracks whether each environment has been fixed.

## How a cycle works

1. Load config again from disk (edits apply from this cycle on) and read each project's lockfiles.
2. Fetch all sources. Per-host rate limits, retries, `Retry-After` and 429 cooldowns apply. Unchanged feeds answer `304`.
3. Judge each item once (module `relevance`): which technologies it is about, which projects run them, and whether the installed version falls in the affected range.
4. Fold it into the ledger (module `ledger`): the same issue reported again, by another feed or a news site, joins the existing record instead of creating a new one.
5. Write `alerts/YYYY/yyyy-mm-dd-tech-slug.md`, save, then alert Slack.
6. Print every open finding, so nothing is forgotten between alerts.

A failed source keeps its cursor and is retried next cycle. A finding counts as alerted only after Slack accepted it.

## What you get per issue

- **Age:** time since publication ("2d 4h").
- **Articles:** how many news-style reports were found, collected in chronological order with title, source and link. Advisory databases (NVD, GitHub, CISA KEV) are listed separately.
- **Fix:** whether a remedy is known and where it comes from. Patched versions come from GitHub advisories, linked patches, vendor advisories and mitigations from NVD references, and the required action from CISA KEV. `official` means a vendor or authority source said it, not a news site. The tool reads what feeds say; it does not look for container images or packages in registries.
- **Version verdict per project:** `affected`, `not affected` or `unchecked` (see below).
- **Calendar:** `cvewatch calendar` writes a month page with severity colors, technology tags and a legend, or prints a text grid with `-text`.

## Layout

| Path | Purpose |
|---|---|
| `app/config/config.yaml` | interval, HTTP limits, Slack, optional access rules |
| `app/config/techs.yaml` | supported technologies: aliases, excludes, CPE names |
| `app/config/projects/*.yaml` | one file per project: environments, techs, lockfiles |
| `app/sources/*.yaml` | feeds to poll |
| `app/src/` | Go code, one package per concern, see [architecture.md](architecture.md) |
| `data/state.json` | state: seen vulnerabilities, fix status, feed cursors |
| `data/audit.log` | append-only, hash-chained record of detections, alerts and status changes |
| `alerts/` | generated markdown reports and calendar pages |

Examples to copy: `app/config/projects/*.yaml.example`. Relative lockfile paths are resolved against the app directory, not the working directory.

## Matching, versions and noise

An item matches a project when it is about a technology the project declares, or names a package in the project's lockfile.

- **By text:** an alias as a whole word in the title or summary (`excludes` veto it; `match_title_only` on a source limits it to the title).
- **By structured data, which wins when present:** NVD publishes affected products as CPE names. A technology with `cpe: [php:php]` then matches only when the advisory names that product, so "a Moodle plugin written in PHP" no longer matches PHP. Set `match_structured: true` on the NVD source to also wait for that data instead of falling back to words. GitHub advisories list packages with their ecosystem; a package advisory matches a lockfile package exactly, and the word "PHP" in it is ignored.
- **Versions:** when the feed gives affected ranges, the version the project runs (declared tech version or lockfile version) is compared: `affected`, `not affected`, or `unchecked` when no range or version is available, or a declared series such as `8.2` cannot be decided against a patch-level bound. Findings known to be `not affected` are kept but hidden from lists and never alerted (`list -all` shows them). If ranges arrive later (a CVE first seen in the news, then analysed by NVD), existing findings are re-checked.
- **Check the CPE names** in `techs.yaml` against the NVD CPE dictionary. A wrong name hides real advisories.

`techs.yaml` can change at any time. A change affects items first seen from the next cycle on; earlier decisions are never rewritten. To look back on purpose, run `cvewatch rescan` (a dry run) and then `cvewatch rescan -apply`. Rescan only adds findings, and for records that matched nothing it can only use the stored title. `cvewatch why ID` shows the recorded reasons next to what today's config says.

Min severity (`-min`, `slack.min_severity`) hides unrated items too: unrated ranks below every named severity.

## Same issue, one record

- Items sharing an advisory id belong to the same record.
- An advisory that names one CVE and one GHSA id unifies two records into one (they are two names for the same flaw).
- An article naming several CVEs, a roundup, never merges them: it is linked to each record instead.
- A relevant report without a shared id joins a tracked, relevant record when their titles share at least 60% of their distinctive words and are dated within 14 days. Irrelevant items never merge.

## Environments and tracking fixes

Projects list their own environments from `dev`, `int`, `staging`, `prod`; leave the list out for all four. A project such as a middleware can have just `prod`. Plans promote in that order.

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
../cvewatch check                      # validate config
../cvewatch update                     # refresh all sources now, then list (run is the same)
../cvewatch update -min high           # only high and critical
../cvewatch list -min medium -project shop
../cvewatch list -all                  # also versions known to be unaffected
../cvewatch show CVE-2026-1234         # description, fix, articles, status, plan (add -json)
../cvewatch why CVE-2026-1234          # why it matched
../cvewatch calendar                   # writes alerts/calendar-YYYY-MM.html
../cvewatch calendar -month 2026-09 -text
../cvewatch rescan                     # dry run; -apply to create findings
../cvewatch daemon                     # refresh every `interval`
../cvewatch mcp                        # MCP server for agents, see agents.md
../cvewatch audit                      # verify the audit log chain
../cvewatch version
```

The list groups open findings by severity (critical first, unrated last) and puts the newest last within each group. Items that arrived in the latest `update` are marked `NEW`.

Only one process may use `data/` at a time. A second one stops with an error instead of corrupting state, so run `fix` between cycles, not during.

## Several people

By default everyone who can run the tool may do everything. To limit that, add `access` to `config.yaml`: per actor name (`CVEWATCH_ACTOR`, else the OS user), the projects visible and whether changes are allowed. Reads are filtered, writes need write access to the project, and `update` needs write access to all projects. This is authorization on top of a local identity, not authentication; it is right for a shared server where people have their own accounts, not for exposing the tool to strangers.

## Platforms

Linux, macOS and Windows build and are tested in CI. Platform differences (file locking, owner-only files, atomic replace, stop signals) are isolated in `app/src/host`. On Windows owner-only file modes are not enforced by the OS; the files rely on the permissions of the user profile folder, so keep `data/` and `alerts/` there or restrict them with ACLs.

## Limits and next steps

- State is one JSON file behind a `store.Storage` seam. A database adapter fits there when several people write at once.
- Slack is the only notifier. Add another by implementing `notify.Notifier`.
- Adding a feed type is one parser file in `app/src/feeds`, registered by name.
- Free-text feeds (news, Hacker News) give no versions: those findings stay `unchecked`.
- Fixes are what feeds say. Registries and container images are not queried.
- Security and privacy: see `security.md` and `compliance.md`.
