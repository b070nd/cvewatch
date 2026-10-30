# cvewatch

Exposure and fix tracking for software factories. It watches the feeds that matter to your stack, tracks open, fixed and ignored per project and environment, and keeps the evidence local.

It is a companion to scanners (Trivy, Grype, OSV-Scanner) and SBOM platforms (Dependency-Track), not a replacement: it does not scan images or hosts. Its job is the one they leave open: *which of our projects and environments are still exposed to which known issue, who owns it, and what happened so far.*

## First run

```bash
cvewatch init -repo /path/to/your/repo      # starter config; detects technologies, versions and lockfiles
cvewatch setup /path/to/your/repo            # or: guided, with the evidence for every guess
cvewatch tui                                 # full-screen overview, findings, projects and status (runs cvewatch-tui)
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

## Terminal UI

`cvewatch tui` opens the full-screen interface. It has five screens, shown as tabs under the title: **1 Overview**, **2 Findings**, **3 Projects**, **4 Status** and **5 Settings**. Findings shows the number of open issues, and Settings shows `(!)` when a settings file has an error.

The header also shows what is going on. `refreshing...` means the data is being read. While a change is written, the header shows what runs, such as `saving...`, with `+1` when more run. Otherwise it shows the health and the time of the last read. The data reloads by itself every 30 seconds. Press `r` to reload now.

### Moving around

- **Levels.** Each screen has a root. Enter opens a level inside it: an issue, a project, a fix preview or a form. The breadcrumb line under the tabs shows the path, such as `Findings › CVE-2026-1234 › shop:prod`.
- **Back.** Left, Esc or Backspace go back one level. `q` does the same inside a level or a popup.
- **Screens.** On a root, Left and Right switch to the previous or next screen. Screens wrap around. Tab and Shift+Tab cycle through them, and 1 to 5 go to one. Tab and 1 to 5 also work inside an issue or a project.
- **Quit.** `q` quits only from a root. Ctrl+C quits from anywhere.
- **Help.** `?` shows the keys for where you are, and the rules that apply everywhere. In a text box `?` is a letter, so use F1 there.
- **Jump box.** `:` or Ctrl+G opens it from any screen or level, except forms, the fix preview and text boxes. Type part of an issue id (such as `CVE-2026-1234`) or a project name. Matches appear as you type, and names that start with your text come first. Up and Down pick a match, Tab fills in the text with it, and Enter goes there. If nothing matches but the text looks like an issue id, Enter tries it as one. That also finds an issue that is already closed. Esc cancels.
- **Messages.** A success note starts with `ok:` and goes away after 4 seconds. An error starts with `error:` and stays until your next action. Moving around (arrows, paging, switching screens) keeps the message.

### Going to another place

Some keys take you to another place. Esc (or Backspace) brings you back to where you came from, on the level you land on.

- Overview: Enter on a policy violation opens its issue.
- Status: Enter on an error that names a project goes to that project. Other errors show in full.
- Issue: `p` goes to the project of the selected environment.
- Projects: `i` (or `F`) shows that project's issues on Findings, filtered to it.

If you type a new filter after the jump, Esc clears the filter first. Changing screen ends the way back. This happens with Tab, a number key, or Left and Right on a root.

### Mouse

The mouse is optional. Every action works from the keys.

- The wheel scrolls three lines, or moves a list cursor three rows.
- A click selects a row. A second click on the selected row opens it on Findings, Projects, Overview and Status. In a form, a second click answers a choice, or ticks an option in a checklist.
- In an issue, a click selects an environment row.
- Click a screen tab to switch to it. Click a breadcrumb to go back to that level.

### Keys by screen

The footer at the bottom shows the keys for where you are. Keys in brackets also work, but the footer and the help leave them out.

Everywhere except in forms, the fix preview and text boxes: `:` jump, `r` reload, `?` help, Tab and 1 to 5 switch screens.

**Overview and Status**

| Key | What it does |
|---|---|
| Up, Down | select a row: a policy violation (Overview) or an error (Status) |
| PgUp, PgDn, Home, End | scroll the page |
| Enter | Overview: open the issue of the selected violation. Status: go to the project the error names, else show the error in full |

**Findings**

| Key | What it does |
|---|---|
| Up, Down, PgUp, PgDn, Home, End | move in the list (`k`, `j`, `g`, `G` too) |
| Enter | open the selected issue |
| `/` | filter by words or fields such as `severity:high`. The list narrows as you type. Enter keeps the filter, Esc clears it |
| `s` | cycle the minimum severity: all, low+, medium+, high+, critical+ |
| Space | mark or unmark the issue, then move down (see Triage) |
| Ctrl+A | mark every issue in the list, or clear the marks when all are marked |
| `f` `i` `n` `o` | with marks: set every marked issue fixed, ignored, not affected, or open again |
| Esc | clear the marks first; then go back to where a jump came from; then clear the filter |

**An issue** (Enter on Findings)

| Key | What it does |
|---|---|
| Up, Down | select an environment row |
| PgUp, PgDn, Home, End, Space | scroll the page |
| `f` `i` `n` `o` | set the selected environment fixed, ignored, not affected, or open again. Not affected asks for a reason |
| `F` `I` `N` `O` | the same for every environment of the project |
| `a`, `A` | owner, due date and ticket of the selected environment, or of the whole project with `A` |
| `]`, `[` | open the next or previous issue of the list (`J`, `K` too) |
| `p` | go to the project of the selected environment |
| Left, Esc, Backspace, `q` | back to the list, or to where a jump came from |

**Projects** (the list)

| Key | What it does |
|---|---|
| Up, Down | select a project |
| Enter | open the project: its problems, each with its fix |
| `e` | edit the project in the guided form: technologies, versions, lockfiles, environments |
| `a` | add a project in the guided form (`n` too) |
| `d` | add a project from a folder (see the folder box below) |
| `x` | preview the fix of the selected problem (`f` too) |
| `E` | open the project file in `$EDITOR`, then reload (`o` too) |
| `p`, `P` | next or previous problem of the selected project |
| `i` | show this project's issues on Findings (`F` too) |
| Esc, Backspace | back to where a jump came from |

**A project** (Enter on Projects)

| Key | What it does |
|---|---|
| Up, Down | select a problem. Its fix shows under it |
| Enter, Right, `x` | preview the fix of the selected problem |
| `[`, `]` | choose another fix, when the problem has several |
| `e` | edit the project in the guided form |
| `E` | open the file in `$EDITOR` at the problem's line (see below) |
| `a`, `d`, `i` | add a project, add from a folder, show this project's issues |
| Left, Esc, Backspace, `q` | back to the list of projects, or to where a jump came from |

**Settings** (screen 5)

The section list shows how many values each section of `config.yaml`, `techs.yaml` and `sources/*.yaml` sets, and the problems of the files with their line numbers. Enter opens a section, then a field. Changes are previewed as a change to the file and saved on a yes; comments in the files are kept. The daemon picks them up from its next cycle. It works even when a settings file is broken, and the other screens then show the load error as usual.

| Key | What it does |
|---|---|
| Up, Down, PgUp, PgDn, Home, End | move in the list; the mouse wheel and a click work too, a second click opens |
| Enter, Right | open a section, a list or an item; change a value (a number, text, a duration, a name of an environment variable; a choice opens a list) |
| Space | turn an on/off setting over |
| `a`, `x` | add an item to a list or map (a feed, a technology, a policy rule, an access rule), or remove the selected one |
| `u` | restore the default: the value is removed from the file |
| `/` | find a setting by label, path or value. On the section list it searches every section |
| `E` | open the file in `$EDITOR` at the line of the selected problem, then read it again |
| Left, Esc, Backspace, `q` | back one level |

In the preview, Enter or `y` saves and Esc cancels. Secrets (feed URLs and headers) are never shown: a field says `(set)` or `(not set)`, the prompt does not show or prefill the current value, and the preview says `(set, changed)`. Only an actor that may see all projects can open the screen, and only one with write access can change it; the access rules cannot be changed so that the actor loses write access.

**Fix preview**

| Key | What it does |
|---|---|
| Enter, `y` | apply the fix to the project file, then reload |
| `[`, `]`, Left, Right | another fix, when the problem has several |
| Esc, Backspace, `q` | cancel. Nothing is saved. Left also cancels when there is only one fix |
| Up, Down, PgUp, PgDn, Home, End | scroll the preview |

**Project form** (add or edit)

The form asks one question at a time. What a key does depends on the question.

| Question | Keys |
|---|---|
| Text answer | type the answer. Enter goes on. Esc goes back one step. Ctrl+D scans a folder. Letters such as `q`, `h` and `d` are typed text here |
| Choice | Up, Down pick. Enter chooses. Esc, Left, Backspace or `q` go back. `d` or Ctrl+D scans a folder |
| Several options | Up, Down move. Space or `x` ticks. `a` ticks all, or clears all when all are ticked. Enter confirms |
| Yes or no | `y` or `n`. Esc goes back. `d` or Ctrl+D scans a folder |
| Review | Enter or `y` saves the project file. `n` does not save and goes back one step. `e` changes one step: pick it from a list, and the review comes back after it |
| List of steps (after `e`) | Up, Down pick. Enter goes to the step. Esc goes back to the review |

On the first step, Esc leaves the form. If you typed something, it asks first. Nothing is saved until you save from the review.

### Triage

- `]` and `[` move through the list while the issue page stays open. Use `]` to go down the list one issue at a time. If the open issue has just left the list (you closed it), the next one takes its place.
- Mark issues with Space, which moves the cursor on, or with Ctrl+A for every issue in the list. Marks stay only on issues the list still shows.
- Press `f`, `i`, `n` or `o` to change every marked issue at once, with one note for all of them. Fixed, ignored and not affected change the open environments of each issue. `o` reopens the closed ones. Not affected needs a reason, and an empty one is refused.
- Narrow the list with `/` (for example `severity:high` or `project:shop`) and `s`. The search syntax is in [search.md](search.md).

### Prompts

A prompt opens at the bottom of the screen for a note, for an owner, due date and ticket, or for a folder.

- Enter saves. On a prompt with more than one field, Enter goes to the next field first.
- Tab or Down go to the next field. Shift+Tab or Up go to the previous one.
- Esc cancels. Nothing is written.
- A due date is `YYYY-MM-DD`. An empty field keeps its value, and `-` clears it.
- If a write is refused, the reason shows in the prompt and what you typed stays. Fix it and press Enter again.
- While a write runs, the prompt says `working...`. Esc closes it, and the change still lands.

### Editing the project file

`E` (or `o`) runs `$EDITOR` on the project file, then reloads when it closes. The file can be broken; it still opens.

Inside a project with a problem selected, the editor opens at the problem's line. The TUI knows these editors:

- `vim`, `nvim`, `vi`, `view`, `gvim`, `mvim`, `nano`, `micro`, `emacs`, `emacsclient`: opened with `+LINE`.
- `code`, `code-insiders`, `codium` (VS Code): opened with `-g FILE:LINE`.
- `subl`, `sublime_text` (Sublime Text): opened with `FILE:LINE`.

Any other editor opens the file at the top. `$EDITOR` may hold options, such as `code --wait`. If it is not set, the TUI says so and shows the file path.

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
- PgUp and PgDn page through the list. Esc cancels, and nothing is added.
- Each row shows the lockfiles and manifests found directly inside it, for example `composer.lock` or `go.mod`. A `project` tag marks a folder that has a lockfile or a manifest. Only the first 300 subfolders of a folder are looked into for marks, and at most 200 rows are listed.

Picking a folder reads folder and file names only. Nothing in the folder is run.

### Fixing projects (TUI)

The Projects screen has a PROBLEMS column: `-` for none, or counts such as `2 err` and `1 warn`. A project file that cannot be read is shown as `BROKEN` with its error, and the rest of the TUI keeps working.

- Enter opens the project. Its problems are listed, each with its fix underneath. `p` and `P` select the next or previous problem.
- Inside a project, Enter or `x` shows the fix of the selected problem as a diff. Enter or `y` applies it. Esc cancels, and nothing is saved.
- A problem with several fixes lists them. `[` and `]` choose one.
- `E` opens the project file in `$EDITOR` at the problem's line, then reloads. See [Editing the project file](#editing-the-project-file).

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
