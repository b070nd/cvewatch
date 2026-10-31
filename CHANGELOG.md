# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Source field `auth_env`: the name of an environment variable whose value is sent as `Authorization: Bearer <value>`. An unset or empty variable sends no header and is no error. The shipped `ghsa` source uses `auth_env: GITHUB_TOKEN`, which raises GitHub's limit from 60 to 5000 requests an hour and needs no scopes for public advisories. Only the name is ever shown or logged, and a value that is not a variable name is refused without being echoed; `cvewatch doctor` says whether the variable is set.
- Projects can belong to a vendor: `vendor: acme` in the project file (lowercase letters, digits, `-` and `_`, at most 63 characters), set with `cvewatch project NAME -vendor acme`, the MCP op `set_vendor` or by hand. Every target of an issue carries `vendor` (additive in `export-v1`, a `vendor` column at the end of the CSV, vendor in SARIF properties and the markdown export), and `project list`, `list_projects` and the project view show it. Projects without a vendor are selected with `-`.
- `-vendor V` on `list`, `update`, `search`, `export` and `calendar`, `vendor` in the MCP tools `list_findings`, `search_findings`, `get_calendar`, `get_vulnerability`, `explain` and `get_evidence`, and `vendor:acme` in a search keep only the projects of that vendor. `get_vulnerability`, `explain` and `get_evidence` also take `project`.
- `access` grants accept `vendor:acme` in `projects`: every project of that vendor, resolved on each request, so a project added to the vendor later is covered.
- `cvewatch update` and the daemon log each finished chunk or page of a long fetch, and say when a source fetches history. Stopping (Ctrl-C) or a failure part way keeps the NVD windows that finished and the next run goes on from where it broke off, instead of starting the back-fill again.
- Folder box in the TUI for new projects: Tab completes, Shift+Tab goes up one folder, Up and Down pick a folder. Rows show the lockfiles and manifests in each folder and a `project` tag.
- TUI Projects screen shows a problems column and the problems of the selected project. `f` previews and applies a fix, `o` opens the file in the editor (`tui.editor`, else `$VISUAL` or `$EDITOR`). A project file that cannot be read is shown as broken instead of stopping the TUI.
- `check_projects` MCP tool: read-only report of problems in project files, with the fixes it knows.
- Validation warns when a lockfile's `env` is not in the project's `envs`, since such a lockfile is never read.
- TUI breadcrumb under the screen tabs. Left, Esc and Backspace go back one level.
- TUI jump box (`:` or Ctrl+G) to an issue by ID or a project by name. Overview, Status, issue and project rows link to their targets, and Esc returns to where you came from.
- TUI triage: `]` and `[` for the next and previous issue, Space and Ctrl+A to mark issues, and one status change for all marked issues.
- TUI mouse support: wheel, click to select, clickable tabs and breadcrumb.
- TUI `E` opens the project file at the problem's line in vim, nano, emacs, VS Code, Sublime Text and more.
- TUI fix preview lists every fix of a problem; `[` and `]` choose one.
- TUI project field editor: `c` on Projects (or inside a project) opens the project's fields for direct editing: environments, technologies, lockfiles with env and dev, differences per environment (versions, technologies that run only there, exclusions and images) and since. Each change is previewed as a diff before it is saved.
- Project lifecycle in the TUI (`N` new, `R` rename, `D` duplicate, `X` delete, `Z` disable or enable), in the CLI (`cvewatch project rename|duplicate|delete|disable|enable`, which shows the consequences until `-yes`) and in MCP (`manage_project`, which shows them until `confirm`). Delete moves the project file to the backups, asks for the typed name in the TUI, and can mark its open findings ignored with `-close-findings`.
- Settings screen in the TUI (screen 5) and `cvewatch settings list|get|set|unset|add|diff|schema`: every setting of `config.yaml`, `techs.yaml` and `sources/*.yaml`, with its type and help. Changes are previewed before they are saved, comments are kept, and secrets are never shown.
- Configuration documents module (`confdoc`): edits by field path, validated the way the loader validates them, saved atomically with a backup.
- One issue page for the TUI, `cvewatch show` and the reports, with References, Evidence, History, installed versions and affected ranges. TUI keys: `l` and `L` select a link, Enter opens it, `c` copies it, `v` shows the evidence pack, `R` shows the report and `+` adds evidence.
- Project `since` and lockfile dev flag in edits: `-since`, `-lock TYPE:PATH[:ENV][:dev]`, `-unlock`, `-lock-dev`, `-lock-nodev`, `-image`, `-env-set` and `-env-unset` on the CLI; the `since` input and a `lockfile` object (`type`, `path`, `env`, `dev`) in MCP.
- MCP tools `get_settings` and `preview_settings_change` (read-only), and `edit_settings` and `manage_project` (with `-allow-write`).
- Project edit operations are defined once, in `projectfile.OpTable`. The CLI flags, the MCP schema and the parity tests are built from that table.
- TUI project form: `e` on the review changes one step and returns to the review.
- `tui` section in `config.yaml`: `refresh` (how often the TUI re-reads the state, 30s by default, at least 1s) and `fetch` (how often it fetches the feeds itself; `0s` by default, which means only on request). Both are on the Settings screen. A running daemon already fetches every `interval`.
- TUI fetches the feeds in the background: `F` fetches now, the header shows the run as `fetch 3/12`, and a click on it lists the sources that failed. A store busy with a daemon cycle is retried later without an error.
- TUI Overview lists every open issue, not only the policy violations. `/` and `s` search and filter it with the Findings syntax; `v` shows the violations and warnings.
- TUI context: the interface always works in one context, a project (`shop`, or `acme ▸ shop` when a project has a vendor), the projects of one vendor, or all projects, shown as `context: ...` in the breadcrumb line. Overview, Findings, the issue page, the prompts, the search, the jump box and the counts hold the rows of the context only; rows of other projects are not shown, and the same issue in two projects is two rows. In a vendor or all-projects context Overview lists one section per project, with its counts and top three issues. `C` chooses the context from every screen and Enter on a project does too; with one project it is set by itself.
- TUI `+` adds a project from a folder, from a Dockerfile, compose or Kubernetes file, or empty. `-` removes the selected project after its name is typed, and removes a lockfile, technology, version or image after a question.
- TUI lockfiles: `+` adds one by picking its file with Tab completion; the type comes from the file name.
- Projects from a Dockerfile, compose or Kubernetes file: `cvewatch discover FILE` and `cvewatch setup FILE` read one file, and the `discover_stack` MCP tool accepts one. Base images, compose services, Kubernetes images and packages installed in a Dockerfile are marked as infrastructure, with their category.
- Environments have free names: lowercase letters, digits, `-` and `_`, starting with a letter, up to 32 characters. `local`, `dev`, `int`, `staging` and `prod` are suggested, not required, and `production` counts as prod. A new project starts with `local`.
- Environment edits `add_env`, `remove_env` and `rename_env`: `-env-add`, `-env-remove` and `-env-rename OLD=NEW` on the CLI, `+`, `-` and `r` in the TUI field editor, and the same kinds in MCP `edit_project`. A rename moves the environment's findings and says how many; a removal also drops its differences.
- Project files keep the generic technologies at the top. A `when@<env>:` block holds only what differs in that environment: `techs` (another version, or a technology that runs only there), `exclude` (generic technologies that do not run there) and `image`. A technology can carry `envs: [...]` to run only in some environments.
- `migrate_envs` (`-migrate-envs` on the CLI, `m` on the TUI's differences list) rewrites the old `environments:` block as `when@<env>` blocks in one previewed step. The old spelling still loads and keeps its meaning.
- Scope and exclusion edits for a project: `-tech-envs TECH=ENV,ENV`, `-env-exclude ENV:TECH` and `-env-include ENV:TECH` on the CLI, and the matching `set_tech_envs`, `exclude_env_tech` and `include_env_tech` kinds in MCP.
- TUI differences per environment: `+` adds a version, an extra technology, an exclusion or an image for one environment, `-` removes one after a question, and `e` on a technology chooses the environments it runs in.
- Discovery skips what `.gitignore` ignores, and `.git/info/exclude` too. `cvewatch discover` and `cvewatch setup` take `-all` to read them anyway, and the TUI folder box hides ignored entries. A file given directly (`discover FILE`) that is ignored is refused unless `-all` is given.
- Technologies the catalog does not have can be kept as your own keyword: `+term` in the setup technology step, `ctrl+o` in the TUI add-technologies step, `K` on the Technologies field, or `cvewatch tech add|edit|remove|list`. The entry goes to `config/techs.yaml`, after a preview, and a new project is written together with it.
- MCP `suggest_tech` (the closest names for a typed term), `preview_tech_change` and `edit_tech` (with `-allow-write`) for your own technologies. The Settings screen's Tech catalog section lists yours, with `a`, `e` and `x`.
- Hints: advice about a project that is not an error, such as an unknown technology with its suggestions or the keyword to add, a missing version, a lockfile problem, no prod environment, or no start date. They show in the setup review, `cvewatch project`, `check_projects` and `preview_project_change`. The TUI lists them under `H`, and the Projects screen counts them.
- Alert horizon: `horizon:` in `config.yaml` with `window` (`unlimited`, `hour`, `day`, `week`, `month`, `year` or `custom` with `from` and `to`). A vulnerability published outside it is not judged, alerted or put in a digest; findings that exist stay. The default is `unlimited`, and `cvewatch check` warns when the window reaches further back than `lookback`.
- `published:` search field (`published:week`, `published:7d`, `published:2026-01-01..2026-03-01`, `published:..2026-03-01`) and `-published VALUE` on `list`, `update`, `search` and `export`.
- TUI `t` cycles a time filter on the publication date (any time, past hour, day, week, month, year) on Overview and Findings, shown as a chip on the breadcrumb line; `0` clears it. Overview and Status show the alert horizon when it is not unlimited.

- Revalidation: when a project, its technologies, versions per environment, environments, lockfiles or `since` date changes, or a `techs.yaml` entry or the alert horizon does, every stored advisory is judged again, including the ones that matched nothing before. New matches become findings, and nothing stored is removed. It runs at the start of every cycle, on the TUI's next read, and in the daemon within about 15 seconds of a configuration file changing.
- `cvewatch revalidate [-apply] [-fetch] [-json]` previews or applies the same re-judging on the command line. `-fetch` also fetches the older advisories the change needs.
- Back-fill: when a change starts earlier than what the sources have covered, NVD is asked in 119-day windows with paging, GitHub advisories are followed page by page, and KEV is read in full, so the older advisories arrive on the next fetch. Vendor records, RSS and Hacker News cannot go back, and the cycle notes say so.
- TUI `V` revalidates after showing a preview (`y` or Enter applies). The header shows `revalidating` and `back-fill` while it runs, and the Projects list marks with `*` the projects whose changes are not judged yet.
- `since` closes the open findings of advisories published before it, as not affected, with a note saying why. Moving the date earlier, or removing it, reopens the findings cvewatch closed. A status you set yourself is never changed.
- `tui.editor` setting: the editor `E` opens files in, with its options (for example `code --wait`). Without it the TUI uses `$VISUAL`, then `$EDITOR`, then the first usual editor on the machine, and says which one it used.
- The Linux kernel catalog entry takes the names people write: `ubuntu kernel`, `debian kernel`, `linux-image` and `linux image` are aliases of `linux-kernel`. The words of an unknown technology are matched one by one, so `ubuntu kernel` suggests `linux-kernel`.
- CVSS scores are read for every version the sources carry (2.0, 3.0, 3.1 and 4.0), from NVD, CVE records, GitHub advisories, CSAF advisories and articles. An issue keeps its issuer's score first, then the newer version. `show` and the exports carry the version, vector and source (`cvss_version`, `cvss_vector` and `cvss_source`, added to the export schema).
- `enrich: {cvss: true}`, on by default: tracked CVEs that no source rated get a score from NVD's public API, at most 5 per cycle and once a day per CVE. Only the CVE id is sent. Set `enrich.cvss: false` to turn it off.
- Auto-update with settings per project. A project file can hold `update: {auto: true, every: 1h}`: `every` is how often the project is refreshed (at least 5m, default the `interval` of `config.yaml`) and `auto: false` takes it out of scheduled runs. `update.auto` in `config.yaml` (true by default) turns scheduled refreshes off for all projects. Edit it with `-update-every` and `-update-auto` on `cvewatch project`, the `set_update` kind in MCP `edit_project`, and the Updates field in the TUI.
- The daemon wakes when the first project is due, at the latest after `interval`. A scheduled cycle fetches the feeds once, then judges, reports and alerts only the projects that are due; the findings of the others stay as they are until their turn. `cvewatch update`, `cvewatch run` and `F` in the TUI still cover every project.
- Per-project last update and next due time in `cvewatch status` and on the TUI Status screen. The TUI Projects screen shows `every 1h` and `due now`, `next 14:05`, `paused` or `manual` for each project.
- `tui.auto` setting (true by default, on the Settings screen): without a running daemon the TUI updates the due projects in the background on the same schedule. With a live daemon it does not fetch. A `tui.fetch` period above zero still fetches everything on its own period.
- `cvewatch doctor` and project validation: an `every` under 5m is an error, an `every` over 30 days is a warning, and a project with `auto: false` is listed.
- TUI health: the header shows `GREEN · last check 12:13 (4m ago)`, or `YELLOW · 2 problems` and `RED · 1 problem` with the glyphs ● ▲ ✖. When the monitor is not green, Overview starts with its open problems, red before yellow, each with its level, title and age; Enter opens Health on the problem. Health starts with the same list, with detail and hint. A problem cannot be dismissed or hidden.
- TUI Projects: a VENDOR column when a project has a vendor, and a Vendor field in the project editor (`set_vendor`).
- Problems in the health report: `Report.Problems` (MCP `get_status` and `cvewatch status -json` as `problems`) lists each cause with a stable `key`, `level`, `title`, `detail`, `hint` and `since`, red first, then yellow, then oldest first. The causes are a failing or stale feed, a failing channel, an overdue daemon, no cycle yet, no enabled source, a project file or lockfile that cannot be used (`project:NAME`) and a broken audit chain. A problem is listed until its cause is gone and cannot be dismissed. The overall level is the worst problem. The state records when a failure streak began (`failing_since`).

### Changed
- TUI screens are switched by their highlighted letter, not by `1` to `5`: Shift+O, F, P, H and S for Overview, Findings, Projects, Health and Settings. The tab bar draws the letter bold and underlined (`[O]verview` without colour, with `▸` on the screen shown), and the small letter works too where the screen has no key on it. The Status screen is now called Health. Keys that moved: `F` (fetch) is `u` (update), `F` `I` `N` `O` (status for every environment of the project) is Ctrl+P in the note prompt of `f` `i` `n` `o`, `H` (hints) is `w`, `P` (previous problem) is `[`, and `u` (restore a setting's default) is `d`. `0` clears the time filter only; the project scope is now the context, chosen with `C`. The footer and the help are written from the same table as the keys.
- A search holds the terms that name a project, vendor, environment, status, applies, owner, ticket or overdue on the same target row, and lists only those rows. `project:crm env:prod` no longer matches an issue because another project has a prod row, and an exclusion such as `-owner:ann` keeps the rows Ann does not own. A plain word is matched against one row too.
- When an issue is open in prod in several projects, the reason reads `open in prod: blog, shop` instead of `open in prod`.
- Setting a project's vendor needs write access to every project.
- The text list of an issue open in several projects (`list`, `search`) shows one version verdict per project, `shop (acme): prod,dev [affected]; blog: prod [not affected]`, instead of one verdict over all of them. The vendor shows next to the project in the lists, the issue report and the plan.
- The health of the monitor is GREEN, YELLOW or RED, as for an Elasticsearch cluster, in `cvewatch status`, the dashboard and MCP `get_status`. The levels `ok`, `warn`, `fail` and `unknown` are gone: in JSON, `level` of the report, the daemon, each feed and each channel is now `green`, `yellow` or `red`. A monitor that has not yet read a feed is YELLOW with the problem "no cycle has run yet", no longer `unknown`. `cvewatch status` still exits non-zero only on RED.
- `cvewatch status` no longer prints `warning:` lines or `Overall:`. It prints the colour line (`GREEN · last check 12:13 (4m ago)`, `YELLOW · 2 problems`) and the problems with their hints.
- TUI has five screens, Overview, Findings, Projects, Status and Settings, on keys 1 to 5.
- `cvewatch show` and report files now include Installed, Affected and History sections.
- Advisory links are listed only when they are plain http or https addresses, and long link titles are cut at 200 characters.
- On Windows, links open with `rundll32`, not through `cmd`, so `&` and `^` in an address are not read as shell syntax.
- TUI: Enter on a project opens it, with its problems and fixes. `e` edits the project.
- TUI: `a` adds a project (`n` still works). `x` previews a fix (`f` still works). `E` opens the editor (`o` still works on Projects).
- TUI: Esc cancels a fix preview. `n` no longer cancels it.
- TUI: `q` quits only from the root of a screen. Inside a level or a popup it goes back.
- TUI: `F` fetches the feeds now. It showed the project's issues before; `i` still does.
- TUI: the re-read period is the `tui.refresh` setting, no longer fixed at 30 seconds in the code.
- The daemon no longer refreshes every project on every `interval`: a project is refreshed when its own period is up. With no `update:` block that is the `interval`, as before.
- `cvewatch status` has a Projects section. Before, it showed every feed as "never succeeded" when no daemon ran.
- `tui.fetch` keeps its meaning (a fixed period for fetching everything); `tui.auto` is the default way for the TUI to keep data fresh.
- Lists (Overview, Findings and a project's issues) name environments only where an issue differs from what the project monitors. A project the issue is open in everywhere shows its name alone. The Findings column is `PROJECTS (ONLY IN)`.
- Overview's `by environment` line reads `all N environments alike (K open each)` when the counts are equal, and shows bars only when they differ.
- Setup asks once whether an environment differs from the rest, instead of a version per technology and environment. The question comes only when there is more than one environment.
- A project file without `envs` still means `dev`, `int`, `staging` and `prod`, and the review says so with a hint to list its environments. `environments:` is still read, but new files and edits write `when@<env>` blocks.
- Development-only packages count by default in `local`, `dev`, `int`, `development` and `test`, not only in `dev` and `int`.
- A `when@<env>` block for an environment the project does not have is an error with a fix. A lockfile or technology that names one is a warning.
- Configuration edits apply to stored advisories, not only to items first seen afterwards: a `techs.yaml` or project change re-judges what is stored (see Added). `rescan` is now `revalidate`, and `rescan` still works.
- The hint for a project without `since` says what a start date does now, including closing the findings of older advisories.

### Fixed
- TUI: after the context was changed (Projects, `C` or the jump box), the issue page of the old project stayed open under the new chip, and `a` and the status keys acted on the old project's environment. A change of the context now closes the issue page, its evidence and report views, the prompts about a finding and the way back of the old context, and starting an action on a finding outside the context is refused with `that issue belongs to <project>; choose its project with C`. A read still running for the old context no longer fills the new page. The note about automatic updates said `F` fetches; the key is `u`.
- The evidence pack and the issue history of a renamed project lost the detections recorded under its old name, and a reader whose access rule was rewritten to the new name did not see them. A rename now records the new name in the audit event (`to`, additive; older logs are read from the note) and the former names of a project are followed through the log, so `A` renamed to `B` renamed to `C` shows all of it. A project later created under an old name does not inherit that history, and a reader scoped to the old name sees nothing recorded under the new one. The audit log itself is never rewritten.
- `list_projects` shows a lockfile's `declared_path` (the spelling in the project file) next to its resolved `path`, and `remove_lockfile` and `set_lockfile_dev` accept either one. Two different spellings of the same file are an error that names both, unless `env` tells them apart.
- The `ghsa` source got HTTP 403 from api.github.com once the 60 requests an hour without a token were used. A 403 or 429 with `X-RateLimit-Remaining: 0` or a `Retry-After` is now a rate limit: a wait up to `http.cooldown_429` is waited out, a longer one fails at once (and later requests to that host in the cycle fail without asking again) with `rate limited by api.github.com until 14:05; set auth_env on the source for a higher limit`. Other 403 answers keep their message.
- The hints said `press F` to update; the key is `u` in the TUI (`doctor` and the project hint for `update.auto: false`).
- The issue page, `get_evidence` and `explain` can be narrowed to a project or vendor (`IssueDetailIn`, `EvidenceIn`, `ExplainIn`): the targets, matrix, history and audit records of other projects are left out, and an audit record of several projects names only those in view.
- The evidence pack of an actor limited to some projects reported `audit_intact: false` when none of the audit records was visible to them. It now lists only the records of their projects and the records that belong to no project, says `no audit records visible to you` and keeps `audit_intact: true` while the chain verifies. A broken chain, or no audit record at all, still gives `false`, with a plainer note. Automatic changes show as `cvewatch (automatic)` in the markdown and the issue page.
- In a project context, an issue opened from the Overview or the Findings started on another project's environment row, so assign and the status keys acted on the wrong project. The issue page now holds the rows of the context's project only, and the prompts name project and environment. Long project names in the rows keep their tail.
- A missing or unreadable lockfile or SBOM was taken as proof that its packages were gone: the findings became `not_affected` with `no longer installed` and lost their matches, and they did not come back when the file did. A lockfile that cannot be read now leaves its findings as they were. A finding already damaged that way, or whose package was removed and installed again, is judged against the advisory again once the package is back; status, owner and notes are kept.
- Removing an environment from a project left its open findings as current open targets. They are now set to `ignored` with the note `environment removed from project`, marked as set by cvewatch, with their history kept; declaring the environment again reopens them. A status a person set is not touched, and a project without `envs` keeps its four default environments.
- The audit log missed findings created by a revalidation or a catch-up (a project added after the advisory was stored) and the changes cvewatch makes by itself. Every new finding now writes `detected` with its project and environment, and every automatic close or reopen (by `since`, by a removed environment) writes a `status` record with the actor `cvewatch`, whichever path made it.
- Editing a project's technologies or `since` date did not judge advisories that were already stored: only new sightings were judged, so a technology added later or an earlier `since` missed the older advisories.
- `$EDITOR is not set` stopped the TUI from opening a project or settings file. The editor is looked up now (see `tui.editor`).
- An unknown technology name such as `ubuntu kernel` gets a fix that renames it to the catalog name, not only a warning.
- Kernel version suffixes such as `6.12.86-generic` were read as pre-releases, so they ranked before a fix at `6.12.86`. The build suffix no longer orders a version (`6.12.85+` is `6.12.85`).
- `edit_project` and `preview_project_change` accept a `lockfile` object, so fixes from `check_projects` can be passed on as they are.
- `cvewatch init` saved lockfile paths as absolute paths with the default `-root .`; they stay relative to the root now.
- `cvewatch init -force` now edits an existing project file in place: its comments stay, and the old file is backed up.
- TUI prompts keep what was typed when a write is refused, and show the reason.
- TUI Projects cursor stays on its project when the list changes.
- TUI open issue reloads after a status, assign, bulk or editor change.
- TUI refuses a second submit of a change that is still being saved, so it is not written twice.
- The `user-techs.yaml` example said `keywords`; the field is `aliases`.
- A project whose file name differs from the `name:` it declares (`magento2-shop.yaml` declaring `shop`) could not be deleted, disabled, renamed or edited: `cvewatch project delete shop` said unknown project. Projects are found by their declared name now, and the mismatch is a warning.
- `Did you mean` for an unknown technology offers only close names: `algolia` gets no suggestion, while a typo such as `rabbitMW` finds `rabbitmq`.
- A file in `sources/` with only `- {id: cve-records, disabled: true}` was rejected ("needs a unique id, a type and a url"), although the documentation told you to write it. An entry whose `id` is a built-in feed (or a feed of a technology, or one from an earlier file) now overrides only the fields it gives and keeps the rest; a new id still needs a type and a url, and a misspelled key is still an error.
- A new monitor reported `ok` before any cycle had run, with the daemon and the feeds unknown. The overall level is now `unknown` (`cvewatch status`, the dashboard, the TUI and `get_status`) until a cycle has read at least one feed, and `warn` with "no enabled sources: nothing will be fetched" when every feed is switched off. `cvewatch status` still exits non-zero only on `fail`.
- `cvewatch update` (and `run`) exited 0 although every source failed. It now prints the open findings as before, then exits 1 with "all N sources failed; findings shown are from earlier runs". One failed source among several still exits 0, and `-json` is unchanged.
- Regional production names were not production: `prod-eu`, `prod-us`, `production-apac`, `eu-prod` and the like now count like `prod` for "open in prod", the ordering and the development-only package rule (a name that starts or ends with `prod` or `production` after `-` or `_`; `non-prod` and `pre-prod` do not count). The hint to add `prod` no longer shows when such an environment exists.

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
