# cvewatch

Exposure and fix tracking for software factories. It watches the feeds that matter to your stack, tracks open, fixed and ignored per project and environment, and keeps the evidence local.

It is a companion to scanners (Trivy, Grype, OSV-Scanner) and SBOM platforms (Dependency-Track), not a replacement: it does not scan images or hosts. Its job is the one they leave open: *which of our projects and environments are still exposed to which known issue, who owns it, and what happened so far.*

## First run

```bash
cvewatch init -repo /path/to/your/repo      # starter config; detects technologies, versions and lockfiles
cvewatch setup /path/to/your/repo            # or: guided, with the evidence for every guess
cvewatch tui                                 # full-screen findings, projects and status (runs cvewatch-tui)
cvewatch doctor                              # checks config, lockfiles, state, channels (add -online for CPE names and feeds)
cvewatch update                              # fetch now, then list
```

One binary is enough: the technology catalog and the feeds are built in. `config/techs.yaml` and `sources/*.yaml` hold only your additions and changes; they are layered over the built-in ones. `-root DIR` points at the folder with `config/` and `sources/` (default: the current folder).

## How a cycle works

1. Load the configuration again from disk and build the **inventory**: what runs in every project environment, from declared techs, per-environment versions, lockfiles and SBOMs.
2. Fetch all sources (per-host rate limits, retries, `Retry-After`, 429 cooldowns; unchanged feeds answer `304`).
3. Judge each item once (`relevance`): which technologies it is about, which environments run them, and whether the installed version falls in the affected range.
4. Fold it into the ledger (`ledger`): the same issue reported again joins the existing record.
5. Re-check findings whose inventory changed (an upgraded lockfile, a new declared version, a removed package).
6. Optionally add EPSS scores, write reports, save, then alert every channel and send the daily digest.

A failed source keeps its cursor and is retried next cycle. A finding counts as alerted per channel only after that channel accepted it.

## Technologies and discovery

The built-in catalog lists open and closed source technologies: runtimes, frameworks, databases, servers, platforms, appliances and more. Search it with `cvewatch catalog WORDS`. A technology is judged only when a project declares it, so a big catalog adds no noise. Add your own in `config/techs.yaml`: an entry with the same name replaces the built-in one, and `disabled: true` removes it. A technology can bring its vendor's advisory feed (for example CSAF), which turns on when a project declares it.

`cvewatch discover DIR` shows what a repository uses and why. It reads lockfiles and their packages, `.tool-versions`, `go.mod`, `package.json`, Dockerfiles, compose files, Kubernetes manifests, Terraform and marker files. Each proposal has evidence and a confidence (high, medium, low). Low ones are asked about, never declared silently. It only reads files, never follows symlinks, and limits depth, file count and file size.

## Setting up and changing projects

Three front ends share one setup flow, so the questions and checks are the same:

- `cvewatch setup [DIR]`: guided prompt.
- `cvewatch tui`: full-screen interface. It runs `cvewatch-tui`, a separate program shipped next to `cvewatch`, so other commands start fast.
- MCP tools and the skills in `skills/`: the same steps for an agent.

The package `projectflow` is the one place that turns a typed folder or an existing project into a setup flow, and the answers into project-file edits. The TUI, the wizard and `cvewatch init` all use it.

Project edits keep the file's comments, are checked before saving, back up the old file in `data/project-backups/` and go to the audit log. For scripts, `cvewatch project NAME -set php=8.2 -lock composer:PATH` shows the diff and `-save` writes it.

`cvewatch init -repo DIR` writes the starter files and a project file for what it finds, through the same save path. An existing project file is kept unless you pass `-force`. With `-force`, the project file is edited in place: its comments stay and the old version goes to `data/project-backups/`. The starter files are rewritten. Lockfile paths are stored relative to the config root (`-root`), so with the default `-root .` they stay relative too.

`check_projects` (MCP, read-only) lists the problems in project files, each with the edits that would fix it. See [agents.md](agents.md).

### Adding a project from a folder (TUI)

On the Projects screen, `d` opens a folder box:

- Type a path (`~` is your home folder), or pick a row with Up and Down. Enter uses the picked folder, or the typed text when no row is picked.
- Tab completes the name. With one match it adds the folder and a slash. With several it adds the part they share, if that is longer than what you typed.
- Shift+Tab goes up one folder. Tab on a picked row opens that folder.
- Each row shows the lockfiles and manifests found directly inside it, for example `composer.lock` or `go.mod`. A `project` tag marks a folder that has a lockfile or a manifest. Only the first 300 subfolders of a folder are looked into for marks, and at most 200 rows are listed.

Picking a folder reads folder and file names only. Nothing in the folder is run.

### Fixing projects (TUI)

The Projects screen has a PROBLEMS column: `-` for none, or counts such as `2 err` and `1 warn`. A project file that cannot be read is shown as `BROKEN` with its error, and the rest of the TUI keeps working.

- `p` and `P` select the next or previous problem of the selected project.
- `f` shows the first fix of the selected problem as a diff. `y` applies it, `n` or Esc cancels.
- `o` opens the project file in `$EDITOR`, then reloads.

Problems are worked out when the screen loads or refreshes (`r`), not on every key. If loading fails, the screen offers `r` to try again and `q` to quit.

## Start date per project

A project file can set `since`, the first day its items count:

```yaml
name: middleware
since: 2026-01-01              # vulnerabilities published before this day are not checked for this project
techs: [{name: php, version: "8.2"}]
```

- A vulnerability published before `since` creates no findings for that project. The day itself counts, from 00:00 UTC. Other projects are not affected.
- Items with no publish date are still checked.
- A later article about an old CVE uses the earliest publish date already known for that CVE. So a new article does not bring an old CVE into a project that starts later.
- Findings that already exist stay. To close one, use `cvewatch ignore ID -project middleware -env prod -note "before the start date"`.
- `cvewatch why ID` shows each project that skipped the item for this reason:

  ```text
    not matched: middleware: published 2025-12-31, before the project's start date 2026-01-01
  ```

- `cvewatch check` warns when `since` is in the future. Until that day, the project gets only items that have no publish date.
- `cvewatch rescan` applies the same rule.
- An item that every project skips is kept as a bare record: its title and IDs, with no summary, no findings and no report.
- A value that is not a `YYYY-MM-DD` date stops the configuration from loading.

## Is it working?

`cvewatch status` shows the daemon (running, overdue, or only manual runs), each feed (last success, failures in a row), each channel and the last cycles. It exits non-zero when something fails. `cvewatch dashboard` writes a static HTML page with the same plus open findings. Set `dashboard: {enabled: true}` in `config.yaml` and the daemon refreshes it every cycle. The page has no scripts and makes no external requests.

## Vendor records (CVE Program)

Vendors that issue their own CVE ids (Adobe, Cisco, Microsoft, Oracle and hundreds more) write the record themselves. The `cve-records` source reads these records from the official CVE Program repository (`cvelistV5`), usually before NVD has added its analysis. Vendor knowledge-base pages and bulletins are web pages without a feed, so this is the reliable way to get the same data.

How it works, in short:
- The repository's change log is read from the newest end, in small steps, until the last change already handled.
- Each newly published record is fetched, oldest first, at most 500 per cycle. The place reached is stored, so a failed or interrupted cycle repeats instead of losing records. A record that is gone (404) is skipped; any other error repeats the cycle.
- The title names the affected products, so technology matching works on it. Versions are checked only when the record has CPE names and plain version numbers; free text such as `2.4.9, 2.4.8-p5` stays `unchecked` for a person to confirm.
- The first run takes only the newest 100 records. Older ones come from NVD and the lookback. Changes older than about a week (a week-long outage) are not recovered from this source.
- Requests go to `raw.githubusercontent.com` at up to 5 a second (`host_rates`). Switch it off with `- {id: cve-records, disabled: true}` in a file in `sources/`.

## Inventory

| Source | `type:` | Notes |
|---|---|---|
| Declared techs | `techs:` | `php: "8.2.30"`; per environment under `environments:` |
| composer.lock | `composer` | `packages-dev` counts as development |
| package-lock.json | `npm` | v1, v2 and v3; `"dev": true` counts as development |
| go.mod | `go` | `replace` applied; indirect requirements included |
| requirements.txt | `pip` | only exactly pinned lines; the rest is reported as skipped |
| poetry.lock, Pipfile.lock | `poetry`, `pipfile` | |
| gradle.lockfile, pom.xml | `gradle`, `maven` | pom properties resolved; parent poms are not read |
| CycloneDX / SPDX JSON | `cyclonedx`, `spdx` | packages by purl: npm, composer, go, pypi, maven |

Lockfiles can be limited to one environment (`env: prod`, so a prod SBOM differs from dev) and read every cycle. A lockfile whose `env` is not in the project's `envs` is never read; the project editor and `check_projects` warn about it. Development-only packages count in `dev` and `int` unless the lockfile sets `dev: true`. Per environment you can also record the deployed versions and an image reference (`image:` is recorded only; no registry is queried).

```yaml
name: shop
envs: [dev, prod]
techs: [{name: php, version: "8.3"}]
lockfiles:
  - {type: composer, path: /repos/shop/composer.lock}
  - {type: cyclonedx, path: /releases/shop-prod.cdx.json, env: prod}
environments:
  prod: {techs: {php: "8.2.30"}, image: "registry.example/shop@sha256:..."}
```

`cvewatch inventory` shows what the tool believes runs where, and what could not be read. Package names and versions are compared per ecosystem: `pip` equals `PyPI`, PyPI names are normalized (PEP 503), Maven uses `group:artifact`, and each ecosystem orders versions by its own rules (PEP 440, Maven, semver for Go, npm and Composer).

## Matching, versions and noise

An item matches an environment when it is about a technology it runs, or names a package it has installed.

- **By structured data, which wins when present.** NVD names affected products as CPE names. A technology with `cpe: [php:php]` then matches only when the advisory names that product, so "a Moodle plugin written in PHP" no longer matches PHP. GitHub advisories list packages with ecosystem and ranges; those match installed packages exactly and the word "PHP" in them is ignored.
- **By text, when there is no structured data.** An alias as a whole word in the title or summary (`excludes` veto it; `match_title_only` limits a source to the title; `match_structured` on the NVD source makes technologies with CPE names wait for NVD's product data).
- **Versions.** When the feed gives affected ranges, the installed version is compared: `affected`, `not affected`, or `unchecked` when no range or version is available, or a declared series such as `8.2` cannot be decided against a patch-level bound. Findings known to be `not affected` are kept but hidden and never alerted (`-all` shows them). News and Hacker News carry no versions, so those findings stay `unchecked`.
- **Late data.** If ranges arrive later (a CVE first seen in the news, then analysed by NVD), existing findings are re-checked. If your inventory changes, open findings are re-checked too, and the finding's history says what changed.
- **Check the CPE names** in `techs.yaml`. The repository's CI compares them with an independent list of NVD product names, and `cvewatch doctor -online` asks NVD. A wrong name hides real advisories.

`techs.yaml` can change at any time. A change affects items first seen from the next cycle on; earlier decisions are never rewritten. To look back on purpose, `cvewatch rescan` (a dry run), then `cvewatch rescan -apply`. `cvewatch why ID` shows the recorded reasons next to what today's config says.

## Same issue, one record

- Items sharing an advisory id belong to the same record. An advisory naming one CVE and one GHSA id unifies two records into one.
- An article naming several CVEs (a roundup) never merges them; it is linked to each.
- A relevant report without a shared id joins a tracked, relevant record when their titles share at least 60% of their distinctive words and are dated within 14 days. Irrelevant items never merge.

Each issue keeps its age since publication, the articles in chronological order, fix evidence (patched version, patch, vendor advisory, mitigation, CISA required action; `official` means a vendor or authority said it), the CISA KEV listing with its due date, and optionally the EPSS score.

## Tracking per environment

Status lives per vulnerability, project and environment: `open`, `fixed`, `ignored`, or `not_affected` (a human VEX-style statement that needs a reason). Every change records who, when and why in the finding's history and in the audit log.

```bash
cvewatch assign CVE-2026-1234 -project shop -env prod -owner alice -due 2026-11-30 -ticket https://tickets.example/SEC-12
cvewatch evidence add CVE-2026-1234 -project shop -env prod -note "patched image deployed" -url https://ci.example/run/77
cvewatch fix CVE-2026-1234 -project shop -env dev -note "php 8.2.30"
cvewatch not-affected CVE-2026-1234 -project shop -env dev -note "feature disabled, no network exposure"
cvewatch evidence CVE-2026-1234          # timeline: detection, alerts, status, owners, evidence, per-environment matrix
```

`cvewatch show ID` opens one issue. `cvewatch search` finds issues by words, IDs and fields such as `project:shop`. See [search.md](search.md).

## Priority and policy

The default order is: known exploited (CISA KEV) first, then severity, then open in prod, then EPSS, then age. The list, alerts, digest and exports all use it; each issue carries the reasons for its position. No proprietary score is computed.

Policy rules in `config.yaml` define deadlines; `cvewatch policy` lists the findings that break them (and exits non-zero, so CI or cron can notice):

```yaml
policy:
  rules:
    - {name: kev-prod, env: prod, kev: true, owner_within: 24h, fix_within: 168h}
```

A finding's own due date is always checked.

## Notifications

Channels switch on when their secret is in the environment, so one config file is safe to share: Slack (`SLACK_WEBHOOK_URL`), a signed JSON webhook (`notify.webhook`, HMAC-SHA256 in `X-Cvewatch-Signature`; works for Teams, Jira or GitLab bridges) and email (`notify.email`, SMTP with STARTTLS). Delivery is tracked per channel, so one failing channel never repeats alerts on the others. A daily digest of what is still open (`notify.digest`, e.g. prod only) goes out in the first cycle after its time; `cvewatch digest -send` sends it now.

## Exports and the JSON contract

`cvewatch export -format json|csv|md|sarif` lists open issues with the status of every environment. JSON from `export`, `list -json` and MCP is one versioned document (`schema_version`, `generated_at`, `count`, `issues`); the schema is in [schema/export-v1.schema.json](schema/export-v1.schema.json). Feed text sits under `untrusted`. CSV cells that could be read as spreadsheet formulas are neutralized.

## Layout

| Path | Purpose |
|---|---|
| `config/config.yaml` | interval, HTTP limits, Slack, notify, policy, enrich, storage, access |
| `config/techs.yaml` | your additions to the built-in technology catalog |
| `config/projects/*.yaml` | one file per project |
| `sources/*.yaml` | your additions to the built-in feeds (same `id` replaces; `disabled: true` switches one off) |
| `data/` | state (`state.json`, or `state.db` with the SQLite backend), `audit.log`, `project-backups/` |
| `alerts/` | generated markdown reports and calendar pages |

## Storage

State is one JSON file by default (diffable; one process at a time, enforced by a lock). Set `storage: {backend: sqlite}` for a SQLite file: several processes can use it, and a stale write is refused instead of overwriting newer data. Both sit behind the same `store.Storage` interface.

## Enrichment and privacy

`enrich: {epss: true}` asks FIRST's public EPSS service for the CVE ids you track. It is off by default because the list of CVEs you care about reveals your stack. Nothing else leaves the machine except the configured feeds and channels.

## Several people

By default everyone who can run the tool may do everything. To limit that, add `access` to `config.yaml`: per actor (`CVEWATCH_ACTOR`, else the OS user), the projects visible and whether changes are allowed. Reads are filtered, writes need write access to the project, and `update` needs write access to all projects. This is authorization on top of a local identity, not authentication.

## Platforms

Linux, macOS and Windows are built and tested in CI. Platform differences (file locking, owner-only files, atomic replace, stop signals) are isolated in `src/host`. On Windows owner-only modes are not enforced by the OS; keep `data/` and `alerts/` in the user profile or restrict them with ACLs.

## Limits

- Fixes are what feeds say; no package or image registry is queried.
- Free-text feeds give no versions, so those findings stay `unchecked`.
- Images and SBOMs are inventory you provide; cvewatch does not scan them.
- Lockfile support is listed above; yarn.lock, pnpm-lock and Pipfile without a lock are not read.
- Authorization relies on the local identity; do not expose the tool to people you cannot identify otherwise.
- Security and privacy: see [security.md](security.md) and [compliance.md](compliance.md). Architecture: [architecture.md](architecture.md).
