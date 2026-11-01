# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- `cvewatch revalidate` and the judging at the start of an update are about five times faster on a large store: a technology name is looked up in the text of a stored advisory without a regular expression for plain ASCII text. The answers are the same.
- `revalidate` writes progress to stderr, so `-json` on stdout stays machine-readable: a start line with the number of stored advisories, a line every five seconds with how many are judged, and a closing line with the time it took and the counts.

## [2.0.0] - 2026-10-31

Version 2.0.0 changes things that integrations can see, so read the upgrade notes first. Each project has its own update schedule, a change to a project or to `techs.yaml` is judged against the stored advisories at once with older history fetched as needed, CVSS is read from every version the sources carry, and projects are kept apart by vendor. Environments are free and optional, you can add your own technologies, the monitor reports GREEN, YELLOW or RED, the TUI is switched by letters, and independent black-box validation led to many correctness fixes.

### Upgrading from 1.x
- Health levels are `green`, `yellow` and `red`; `ok`, `warn`, `fail` and `unknown` are gone. Update scripts that read `level` from `cvewatch status -json` (report, daemon, each feed and channel) or from MCP `get_status`. A monitor that has not read a feed yet is yellow, not `unknown`. `cvewatch status` still exits non-zero only on red, and no longer prints `warning:` or `Overall:` lines.
- The TUI screens are switched by the letters `O` `F` `P` `H` `S`, not `1` to `5`, and the Status screen is now Health. `F` (fetch) is now `u`, and a few other keys moved; the old and new keys are in the table under [Screen keys](docs/overview.md#screen-keys).
- Search terms that name a project, vendor, environment, status, owner and the like must hold on the same environment row, and an exclusion such as `-owner:ann` keeps the rows that do not match, so some queries return fewer issues. The text of `list` and `search` for an issue open in several projects now has one version verdict per project; scripts should read `-json`.
- An entry in `sources/` with the id of a shipped feed now overrides only the fields it gives and keeps the rest; before, it replaced the whole feed. If you relied on a left-out field being empty, set it explicitly (for example `match_structured: false`).
- The shipped `ghsa` source sends `GITHUB_TOKEN`, when that variable is set, as a bearer token to api.github.com. To keep it unauthenticated, add `sources: [{id: ghsa, auth_env: ""}]` to a file in `sources/`.
- `cvewatch update` and `run` exit 1 when every source failed. One failed source among several still exits 0, and `-json` is unchanged. Check CI and cron wrappers that treated exit 0 as fresh data.
- Regional production names such as `prod-eu` and `eu-prod` count as production for "open in prod", the ordering and the development-only package rule (`non-prod` and `pre-prod` do not). Development-only packages now count by default in `local`, `dev`, `int`, `development` and `test`, not only in `dev` and `int`.
- A project file with `environments:` still loads with the same meaning, and a file without `envs` still means `dev`, `int`, `staging` and `prod`. `cvewatch project NAME -migrate-envs -save` rewrites the old block as `when@<env>` blocks, and any edit of the differences does it too.
- `cvewatch rescan` is now `cvewatch revalidate`, and the old name still works. The first cycle after upgrading judges every stored advisory again, which can add findings, and fetches history back to the earliest `since` date or alert horizon of your projects, which can take minutes at NVD's request rate; an interrupted run continues where it stopped.
- A `since` date now also closes the open findings of advisories published before it, as not affected with a note. Moving the date earlier or removing it reopens them, and a status you set yourself is never changed.
- Exports and state only gain fields. The JSON export keeps `schema_version` 1 and its required fields; targets gain `vendor`, issues gain `cvss_version`, `cvss_vector` and `cvss_source`, and `env` may be any environment name instead of one of four. CSV has a `vendor` column at the end. The state and the audit log gain optional fields.
- `enrich.cvss` is on by default: tracked CVEs that no source rated are looked up at NVD, by CVE id only. Set `enrich.cvss: false` to turn it off.

### Added

#### Project files and environments
- Environments have free names (lowercase letters, digits, `-` and `_`, starting with a letter, up to 32 characters); `local`, `dev`, `int`, `staging` and `prod` are suggestions, `production` counts as prod, and a new project starts with `local`.
- A `when@<env>:` block in a project file holds only what differs there: `techs` (another version, or a technology that runs only there), `exclude` (generic technologies that do not run there) and `image`. A technology can carry `envs: [...]` to run only in some environments.
- Environment edits `add_env`, `remove_env` and `rename_env`: `-env-add`, `-env-remove` and `-env-rename OLD=NEW` on the CLI, `+`, `-` and `r` in the TUI, and the same kinds in MCP `edit_project`. A rename moves the environment's findings and says how many; a removal also drops its differences.
- Edits for the start date, lockfiles, images, versions per environment and technology scope: `-since`, `-lock TYPE:PATH[:ENV][:dev]`, `-unlock`, `-lock-dev`, `-lock-nodev`, `-image`, `-env-set`, `-env-unset`, `-env-exclude`, `-env-include` and `-tech-envs TECH=ENV,ENV` on the CLI, with matching kinds and a `lockfile` object in MCP.
- `migrate_envs` (`-migrate-envs` on the CLI, `m` on the TUI's differences list) rewrites the old `environments:` block as `when@<env>` blocks in one previewed step.
- Project lifecycle: rename, duplicate, delete, disable and enable in the TUI (`R`, `D`, `X`, `Z`, and `N` for a new project), on the CLI (`cvewatch project rename|duplicate|delete|disable|enable`, which shows the consequences until `-yes`) and in MCP (`manage_project`, until `confirm`). Delete moves the project file to the backups, and `-close-findings` marks its open findings ignored.
- Projects from one Dockerfile, compose or Kubernetes file: `cvewatch discover FILE`, `cvewatch setup FILE` and `discover_stack`. Base images, compose services, Kubernetes images and packages installed in a Dockerfile are marked as infrastructure, with their category.
- Discovery and setup skip what `.gitignore` and `.git/info/exclude` ignore. `-all` reads them anyway, a directly given file that is ignored is refused without it, and the TUI folder box hides ignored entries.
- Hints: advice about a project that is not an error, such as an unknown technology with its suggestions, a missing version, a lockfile problem, no prod environment or no start date. They show in the setup review, `cvewatch project`, `check_projects` and `preview_project_change`, and in the TUI under `w`.
- `check_projects` MCP tool: a read-only report of problems in project files, with the fixes it knows. Validation warns when a lockfile's `env` is not in the project's `envs`, since such a lockfile is never read.

#### Technologies and catalog
- Technologies the catalog lacks can be kept as your own keyword: `+term` in setup, `ctrl+o` and `K` in the TUI, or `cvewatch tech add|edit|remove|list`. The entry goes to `config/techs.yaml` after a preview, and a new project is written together with it.
- MCP `suggest_tech` (the closest names for a typed term), `preview_tech_change` and `edit_tech` (with `-allow-write`) for your own technologies. The Settings screen's Tech catalog section lists yours, with `a`, `e` and `x`.
- The Linux kernel entry takes the names people write (`ubuntu kernel`, `debian kernel`, `linux-image`, `linux image`), and the words of an unknown technology are matched one by one.

#### Updating, history and scheduling
- Per-project schedule: `update: {auto: true, every: 1h}` in a project file (`every` at least 5m, default the `interval`; `auto: false` leaves the project out of scheduled runs), `update.auto` in `config.yaml` as the main switch, `-update-every` and `-update-auto` on `cvewatch project`, `set_update` in MCP, and an Updates field in the TUI.
- The daemon wakes when the first project is due, at the latest after `interval`. A scheduled cycle fetches the feeds once, then judges, reports and alerts only the projects that are due; `cvewatch update`, `cvewatch run` and `u` in the TUI still cover every project.
- Last update and next due time per project in `cvewatch status` and on the TUI Health screen; the Projects screen shows `every 1h` with `due now`, `next 14:05`, `paused` or `manual`.
- `cvewatch doctor` and validation: an `every` under 5m is an error, one over 30 days is a warning, and a project with `auto: false` is listed.
- Revalidation: when a project, its technologies, versions, environments, lockfiles or `since` date changes, or a `techs.yaml` entry or the alert horizon does, every stored advisory is judged again, including the ones that matched nothing before. New matches become findings and nothing stored is removed. It runs at the start of every cycle, on the TUI's next read, and in the daemon within about 15 seconds of a file change.
- `cvewatch revalidate [-apply] [-fetch] [-json]` previews or applies the same re-judging, and `-fetch` also fetches the older advisories the change needs. `rescan` is the old name and still works.
- Back-fill: when a change starts earlier than what the sources have covered, NVD is asked in 119-day windows with paging, GitHub advisories are followed page by page and KEV is read in full. Vendor records, RSS and Hacker News cannot go back, and the cycle notes say so.
- `since` closes the open findings of advisories published before it, as not affected with a note saying why. Moving the date earlier, or removing it, reopens the findings cvewatch closed.
- Alert horizon: `horizon:` in `config.yaml` (`unlimited`, `hour`, `day`, `week`, `month`, `year` or `custom` with `from` and `to`). A vulnerability published outside it is not judged, alerted or put in a digest, and existing findings stay. `cvewatch check` warns when the window reaches further back than `lookback`.
- `published:` search field (`published:week`, `published:7d`, `published:2026-01-01..2026-03-01`) and `-published VALUE` on `list`, `update`, `search` and `export`.
- `cvewatch update` and the daemon log each finished chunk or page of a long fetch. Stopping or a failure part way keeps the NVD windows that finished and the next run continues from there.

#### Ratings (CVSS)
- CVSS scores are read for every version the sources carry (2.0, 3.0, 3.1 and 4.0), from NVD, CVE records, GitHub advisories, CSAF advisories and articles. An issue keeps its issuer's score first, then the newer version, and `show` and the exports carry the version, vector and source (`cvss_version`, `cvss_vector`, `cvss_source`).
- `enrich: {cvss: true}`, on by default: tracked CVEs that no source rated get a score from NVD's public API, at most 5 per cycle and once a day per CVE. Only the CVE id is sent.

#### Vendors, projects and access
- Projects can belong to a vendor: `vendor: acme` in the project file (lowercase letters, digits, `-` and `_`, at most 63 characters), set with `cvewatch project NAME -vendor acme`, MCP `set_vendor` or by hand. `project list`, `list_projects` and the project view show it, and projects without one are selected with `-`.
- Every target of an issue carries `vendor`: additive in `export-v1`, a `vendor` column at the end of the CSV, and vendor in the SARIF properties and the markdown export.
- `-vendor V` on `list`, `update`, `search`, `export` and `calendar`, `vendor` in the MCP tools `list_findings`, `search_findings`, `get_calendar`, `get_vulnerability`, `explain` and `get_evidence`, and `vendor:acme` in a search keep only the projects of that vendor.
- `cvewatch show`, `why` and `evidence` take `-vendor` and `-project`, and `get_vulnerability`, `explain` and `get_evidence` take `project` too; the targets, history and audit records of the other projects are left out.
- `access` grants accept `vendor:acme` in `projects`: every project of that vendor, resolved on each request, so a project added to the vendor later is covered.
- TUI context: the interface always works in one context, a project (`shop`, or `acme ▸ shop`), the projects of one vendor, or all projects, shown as `context: ...` on the breadcrumb line. Rows of other projects are not shown, and the same issue in two projects is two rows. `C` chooses the context from every screen, and with one project it is set by itself.

#### Health and status
- The health of the monitor is GREEN, YELLOW or RED, as for an Elasticsearch cluster, in `cvewatch status`, the dashboard, MCP `get_status` and the TUI header (`GREEN · last check 12:13 (4m ago)`, `YELLOW · 2 problems`, with the glyphs ● ▲ ✖).
- A list of problems (`problems` in `status -json` and `get_status`), each with a stable `key`, `level`, `title`, `detail`, `hint` and `since`, red before yellow, then oldest first. The causes are a failing or stale feed, a failing channel, an overdue daemon, no cycle yet, no enabled source, a project file or lockfile that cannot be used, and a broken audit chain. A problem stays until its cause is gone and cannot be dismissed; the state records when a failure streak began.
- When the monitor is not green, the TUI Overview starts with its open problems and Health with the same list; Enter opens a problem with its detail and hint. `cvewatch status` prints the problems with their hints and has a Projects section.

#### Terminal UI
- Settings screen (`S`) and `cvewatch settings list|get|set|unset|add|diff|schema`: every setting of `config.yaml`, `techs.yaml` and `sources/*.yaml` with its type and help. Changes are validated as the loader validates them, previewed, saved atomically with a backup, keep comments, and never show secrets; the audit log records the paths that changed, never the values.
- `tui` section in `config.yaml`: `refresh` (how often the TUI re-reads the state, 30s by default), `fetch` (a fixed fetch period; `0s` by default) and `auto` (without a running daemon the TUI updates the due projects on the project schedule; true by default). All are on the Settings screen.
- The TUI fetches in the background: `u` updates now, the header shows the run as `fetch 3/12`, and a click on it lists the sources that failed. A store busy with a daemon cycle is retried later without an error.
- Overview lists every open issue, not only the policy violations; `/` and `s` search and filter it with the Findings syntax, and `v` shows the violations and warnings.
- Navigation: a breadcrumb under the tabs (Left, Esc and Backspace go back one level), a jump box (`:` or Ctrl+G) to an issue by ID or a project by name, rows that link to their targets with Esc returning, and mouse support (wheel, click to select, clickable tabs and breadcrumb).
- Triage: `]` and `[` for the next and previous issue, Space and Ctrl+A to mark issues, and one status change for all marked issues.
- One issue page for the TUI, `cvewatch show` and the reports, with References, Evidence, History, installed versions and affected ranges. Keys: `l` and `L` select a link, Enter opens it, `c` copies it, `v` shows the evidence pack, `R` the report and `+` adds evidence.
- Time filter: `t` cycles the publication date (any time, past hour, day, week, month, year) on Overview and Findings, shown as a chip on the breadcrumb line, and `0` clears it. Overview and Health show the alert horizon when it is not unlimited.
- Projects screen: a problems column and the problems of the selected project; `x` previews a fix (every fix of a problem, chosen with `[` and `]`), and `E` opens the project file in the editor at the problem's line (vim, nano, emacs, VS Code, Sublime Text and more). A project file that cannot be read is shown as broken instead of stopping the TUI.
- Project field editor (`c`): environments, technologies, lockfiles with env and dev, differences per environment (versions, technologies that run only there, exclusions and images), since, updates and vendor. Each change is previewed as a diff before it is saved; `+` adds an item, `-` removes one after a question, and `e` on a technology chooses the environments it runs in. A VENDOR column shows on Projects when a project has a vendor.
- Adding projects: `+` adds one from a folder, from a Dockerfile, compose or Kubernetes file, or empty, and `-` removes the selected project after its name is typed. In the guided form, `e` on the review changes one step and returns to the review. The folder box completes with Tab, goes up with Shift+Tab, picks with Up and Down, and marks folders with lockfiles and manifests. `+` adds a lockfile by picking its file, and the type comes from the file name.
- `V` revalidates after a preview. The header shows `revalidating` and `back-fill` while it runs, and the Projects list marks with `*` the projects whose changes are not judged yet.
- `tui.editor` chooses the editor `E` opens files in, with its options (for example `code --wait`). Without it the TUI uses `$VISUAL`, then `$EDITOR`, then the first usual editor on the machine, and says which one it used.

#### MCP, CLI and exports
- MCP tools `get_settings` and `preview_settings_change` (read-only), and `edit_settings` and `manage_project` (with `-allow-write`). The CLI flags and the MCP schema for project edits are built from one table, so they cannot drift apart.
- `cvewatch show` and report files include Installed, Affected and History sections.

#### Feeds and HTTP
- Source field `auth_env`: the name of an environment variable whose value is sent as `Authorization: Bearer <value>`. An unset or empty variable sends no header and is no error. The shipped `ghsa` source uses `auth_env: GITHUB_TOKEN`, which raises GitHub's limit from 60 to 5000 requests an hour and needs no scopes for public advisories. `cvewatch doctor` says whether the variable is set.

#### Environment files
- `cvewatch` and `cvewatch-tui` read `.env` and then `.env.local` from the current folder and from `-root` at start, and `-env-file FILE` (repeatable) names the files yourself. The real environment wins over files, a later file wins over an earlier one, errors name the file and line but never a value, and a file other users can read gets a warning. See [Environment files](docs/overview.md#environment-files).
- `cvewatch-tui -version` prints the version.

### Changed
- A project file without `envs` still means `dev`, `int`, `staging` and `prod`, and the review says so with a hint. `environments:` is still read, but new files and edits write `when@<env>` blocks.
- A `when@<env>` block for an environment the project does not have is an error with a fix; a lockfile or technology that names one is a warning.
- The daemon no longer refreshes every project on every `interval`: a project is refreshed when its own period is up, which is the `interval` when it has no `update:` block. `tui.fetch` keeps its meaning, and `tui.auto` is the default way for the TUI to keep data fresh.
- Setup asks once whether an environment differs from the rest, only when there is more than one environment, instead of a version per technology and environment.
- The hint for a project without `since` says what a start date does, including closing the findings of older advisories.
- A search holds the terms that name a row on the same target and lists only those rows, a plain word included, so `project:crm env:prod` no longer matches because another project has a prod row.
- When an issue is open in prod in several projects, the reason reads `open in prod: blog, shop`.
- The text list of an issue open in several projects shows one version verdict per project, `shop (acme): prod,dev [affected]; blog: prod [not affected]`, and the vendor shows next to the project in the lists, the issue report and the plan.
- Setting a project's vendor needs write access to every project.
- The health levels `ok`, `warn`, `fail` and `unknown` are replaced by `green`, `yellow` and `red` everywhere (see Upgrading).
- TUI screens are switched by their highlighted letter: `O`, `F`, `P`, `H` and `S` for Overview, Findings, Projects, Health and Settings. The Status screen is now called Health. `0` clears the time filter only, and the project scope is the context, chosen with `C`. The footer and the help are written from the same table as the keys.
- TUI keys moved: `F` (fetch) is `u`; `F` `I` `N` `O` (status for every environment) is Ctrl+P in the note prompt of `f` `i` `n` `o`; `H` (hints) is `w`; `P` (previous problem) is `[`; `u` (restore a setting's default) is `d`.
- TUI: Enter on a project opens it, with its problems and fixes, and `e` edits it. `a` adds a project (`n` works), `x` previews a fix (`f` works), and `E` opens the editor (`o` works on Projects).
- TUI: Esc cancels a fix preview, and `n` no longer does. `q` quits only from the root of a screen; inside a level or a popup it goes back.
- TUI lists name environments only where an issue differs from what the project monitors, and the Findings column is `PROJECTS (ONLY IN)`. Overview's `by environment` line reads `all N environments alike (K open each)` when the counts are equal.

### Fixed

#### Project files, environments and technologies
- A missing or unreadable lockfile or SBOM was taken as proof that its packages were gone: the findings became `not_affected` with `no longer installed`, lost their matches and did not come back with the file. Such findings now stay as they were, and a finding damaged that way is judged again once the package is back; status, owner and notes are kept.
- Removing an environment left its open findings as current open targets. They are now set to `ignored` with the note `environment removed from project`, with their history kept; declaring the environment again reopens them, and a status a person set is not touched.
- Editing a project's technologies or `since` date did not judge advisories that were already stored, so a technology added later or an earlier `since` missed older advisories.
- A project whose file name differs from the `name:` it declares could not be deleted, disabled, renamed or edited. Projects are found by their declared name now, and the mismatch is a warning.
- `cvewatch init` saved lockfile paths as absolute paths with the default `-root .`; they stay relative now. `cvewatch init -force` edits an existing project file in place, keeping its comments and backing up the old file.
- `edit_project` and `preview_project_change` accept a `lockfile` object, so fixes from `check_projects` can be passed on as they are. `list_projects` shows a lockfile's `declared_path` next to its resolved `path`, and `remove_lockfile` and `set_lockfile_dev` accept either; two spellings of the same file are an error that names both, unless `env` tells them apart.
- An unknown technology such as `ubuntu kernel` gets a fix that renames it to the catalog name, and `Did you mean` offers only close names (`rabbitMW` finds `rabbitmq`, `algolia` finds nothing).
- Kernel version suffixes such as `6.12.86-generic` were read as pre-releases, so they ranked before a fix at `6.12.86`. A build suffix no longer orders a version.
- The `user-techs.yaml` example said `keywords`; the field is `aliases`.

#### Health, updating and feeds
- A new monitor reported `ok` before any cycle had run. It is now YELLOW with "no cycle has run yet" until a cycle has read at least one feed, and YELLOW with "no enabled sources: nothing will be fetched" when every feed is switched off.
- `cvewatch update` (and `run`) exited 0 although every source failed. It now prints the open findings as before, then exits 1 with "all N sources failed; findings shown are from earlier runs".
- The `ghsa` source got HTTP 403 once GitHub's 60 requests an hour without a token were used. A 403 or 429 with `X-RateLimit-Remaining: 0` or a `Retry-After` is now a rate limit: a wait up to `http.cooldown_429` is waited out, and a longer one fails at once with `rate limited by api.github.com until 14:05; set auth_env on the source for a higher limit`.
- A file in `sources/` with only `- {id: cve-records, disabled: true}` was rejected ("needs a unique id, a type and a url"). An entry with the id of a built-in feed now overrides only the fields it gives; a new id still needs a type and a url, and a misspelled key is still an error.
- `$EDITOR is not set` stopped the TUI from opening a project or settings file. The editor is looked up now.
- Hints and notes told you to press `F` to update; the key is `u`.

#### Audit, evidence and access
- The audit log missed findings created by a revalidation or a catch-up and the changes cvewatch makes by itself. Every new finding now writes `detected` with its project and environment, and every automatic close or reopen writes a `status` record with the actor `cvewatch`. Automatic changes show as `cvewatch (automatic)` in the markdown and the issue page.
- The evidence pack and the issue history of a renamed project lost what was recorded under its old name. A rename now records the new name in the audit event (`to`, additive; older logs are read from the note) and former names are followed, so `A` renamed to `B` renamed to `C` shows all of it. The audit log is never rewritten.
- The evidence pack of an actor limited to some projects reported `audit_intact: false` when none of the audit records was visible to them. It now lists the records of their projects and those of no project, says `no audit records visible to you` and keeps `audit_intact: true` while the chain verifies; a broken chain still gives `false`.

#### Terminal UI
- After the context was changed, the issue page of the old project stayed open under the new chip, and `a` and the status keys acted on the old project's environment. A change of context now closes the issue page and its prompts, and an action on a finding outside the context is refused with `that issue belongs to <project>; choose its project with C`.
- In a project context, an issue opened from Overview or Findings started on another project's environment row, so assign and the status keys acted on the wrong project. The issue page now holds the rows of the context's project only, and the prompts name project and environment.
- Prompts keep what was typed when a write is refused, and show the reason; a second submit of a change that is still being saved is refused.
- The Projects cursor stays on its project when the list changes, and an open issue reloads after a status, assign, bulk or editor change.

### Security
- Advisory links are listed only when they are plain http or https addresses, and long link titles are cut at 200 characters.
- On Windows, links open with `rundll32`, not through `cmd`, so `&` and `^` in an address are not read as shell syntax.
- For `auth_env`, only the variable's name is ever shown or logged, and a value that is not a variable name is refused without being echoed.

## [1.2.0] - 2026-10-29

### Added
- `cve-records` source (type `cve`): the CVE Program's own records, so vendor-published CVEs (Adobe, Cisco, Microsoft and more) arrive before NVD's analysis. A cursor keeps interrupted runs from losing records.

### Fixed
- `list` and `update` exited with an error when open findings existed and `-fail-on` was not used.

## [1.1.0] - 2026-10-28

### Added
- Project `since` date in a project file: vulnerabilities published before that day create no findings for that project. Other projects are not affected.
- `cvewatch search`, the `search_findings` MCP tool and the `/` filter in the TUI: find issues by ID, words, phrases and fields such as `severity:high+`. `cvewatch show` suggests close IDs for an unknown one.

## [1.0.0] - 2026-10-28

First stable release. The JSON export contract (`schema_version` 1) and the project and config file formats are stable from here on.

### Added
- Technology catalog of open and closed source technologies (category, vendor, detection hints, vendor feeds), layered with the user's `config/techs.yaml`; only declared technologies are judged. `cvewatch catalog` searches it.
- Stack discovery (`cvewatch discover`, `init -repo`, setup): technologies, versions and lockfiles with evidence and confidence from lockfiles, version files, Dockerfiles, compose, Kubernetes, Terraform, `.tool-versions` and marker files, across monorepos.
- Comment-preserving project editor with validation, diff, backup and audit (`cvewatch project`); setup flow behind a prompt wizard (`cvewatch setup`), a full-screen TUI (`cvewatch tui`) and MCP tools (`search_catalog`, `discover_stack`, `list_projects`, `preview_project_change`, `edit_project`, `get_status`); agent skills in `skills/`.
- Health of the monitor: `cvewatch status`, daemon heartbeat, per-feed and per-channel outcomes, cycle history; static `cvewatch dashboard` page refreshed by the daemon.
- Read-only sessions read a lock-free snapshot, so viewers never block the daemon; writes retry once on a conflict.
- Vendor advisory feeds in CSAF format, attached to catalog technologies.
- SARIF export and `-fail-on SEVERITY` for CI gates.

### Changed
- `config/techs.yaml` and `sources/*.yaml` now hold only your additions; they no longer replace the built-in lists (a user feed no longer drops the shipped ones). `init` writes commented templates and relative lockfile paths.
- `doctor` checks CPE names online only for declared technologies.
- MCP read tools use read-only sessions; `set_status` describes `not_affected`.

- Market-ready foundations: `cvewatch init` (detects lockfiles and runtime versions from a repository) and `cvewatch doctor` (config, CPE names, lockfiles, state, channels; `-online` checks NVD and feeds); technologies and feeds are built into the binary.
- Inventory per project environment: per-environment runtime versions and image references; lockfiles per environment; Go, pip, poetry, Pipfile, Gradle, Maven, CycloneDX and SPDX inputs; development packages counted in dev and int by default; open findings are re-checked when the inventory changes.
- Ecosystem-aware names and version ordering: PyPI (PEP 440, PEP 503), Maven, Go and semver.
- Per-finding owner, due date, ticket, evidence and history; `not_affected` as a human statement with a required reason; `assign`, `evidence add`, `evidence ID` (timeline pack).
- KEV as a first-class fact (listing date, CISA due date, ransomware flag) kept even when NVD reported the same CVE first; optional EPSS (`enrich.epss`); default order KEV, severity, prod, EPSS, age; policy rules and `cvewatch policy`.
- Notification channels: signed webhook and email next to Slack, per-channel delivery tracking, daily digest.
- `cvewatch export` (JSON, CSV, Markdown) and one versioned JSON contract (`docs/schema/export-v1.schema.json`) shared by the CLI and MCP.
- SQLite storage backend with revision checks, state schema versioning and migration.
- Golden replay tests over the shipped configuration; CPE names in `techs.yaml` are checked against an independent list in CI.
- Version-aware matching: NVD CPE product data and GitHub advisory ranges are compared with the versions in use (`affected`, `not affected`, `unchecked`); late ranges re-check existing findings; unaffected findings are recorded but hidden and never alerted.
- `cpe` names per technology and `match_structured` per source: structured product data replaces word matching, which removes most "mentioned in passing" noise. `cvewatch why` and `cvewatch rescan` explain and re-judge.
- Per issue: age since publication, article count, articles in chronological order, and fix evidence (patched version, patch, vendor advisory, mitigation, CISA required action) marked official or not.
- `cvewatch calendar`: month overview page with severity colors, technology tags and legend, or a text grid.
- Optional per-actor access rules; one operations module behind the CLI and the MCP server.
- Storage seam with file and memory adapters; ledger module owning identity (GHSA and CVE aliases unify, roundup articles only link).
- Linux, macOS and Windows support through a host module; three-OS CI matrix.
- Security hardening: https-only feeds, refusal of private and loopback addresses (SSRF guard), secrets and tokens kept out of logs and errors, owner-only file permissions, sanitized feed text in reports, terminal output and Slack.
- Hash-chained audit log with actor, and `cvewatch audit` to verify it.
- `retention` setting that forgets old items which matched nothing.
- Dockerfile, Compose example, release workflow with provenance and SBOM.
- Documentation on security (`docs/security.md`) and on supporting NIS2 and GDPR duties (`docs/compliance.md`).

- Feed sources: CISA KEV, NVD, GitHub advisories, Hacker News, and RSS/Atom.
- Per-environment fix tracking.
- Tech matrix built from composer and npm lockfiles.
- Merge of reports about the same issue.
- Slack alerts.
- Severity-sorted listing with JSON output.
- MCP server, read-only by default.
- Audit log.
- Markdown reports.
