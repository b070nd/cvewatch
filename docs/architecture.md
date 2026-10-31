# Architecture

One package per concern under `app/src`. The arrows show who depends on whom; the seams are where behaviour can change without editing in place.

| Module | Owns | Seam |
|---|---|---|
| `ops` | every operation (list, show, search, why, revalidate (`rescan` is its old name; `revalidate.go`), calendar, status, assign, evidence, export, policy, digest, inventory, refresh; `RefreshWith` reports the phases of a refresh), the issue page (`IssueDetail`), project files (`ProjectFile`: a project is found by the name its file declares), project edits and problems, project hints (`hints.go`), your own technologies (`techs.go`, previewed and written to `techs.yaml`), project lifecycle (`lifecycle.go`: rename, duplicate, delete, disable and enable; previewed, then applied with undo), settings (`settings.go`: previewed, then saved), validation, access rules, audit order | CLI, TUI and MCP are its adapters; read-only sessions read a lock-free snapshot |
| `pipeline` | one refresh cycle: revalidate when the judging inputs changed, fetch (back-filling what a change needs), judge, record, reconcile, enrich, report, alert, digest; `revalidate.go` re-judges the stored advisories and applies the `since` rule; alerts and digests skip items outside the alert horizon; `Progress` names the phase and, while fetching, the source that finished | `feeds.Getter`, `notify.Channel`, `Runner.Progress` (optional: nil changes nothing) |
| `inventory` | what runs in each project environment; `judging.go` fingerprints the judging inputs (projects, techs per environment, lockfile packages, catalog terms, `since`, horizon) and `Compare` says what changed and how far back the sources must reach | `matrix` adapters |
| `matrix` | reading lockfiles and SBOMs | one adapter per type (ten today) |
| `ecosystem` | package names, aliases, normalization | none: pure |
| `relevance` | what an item is about, which environments run it, version verdict, reasons; skips items published before a project's `since` date or outside the alert horizon (`Window`) | none: pure rules |
| `version` | comparing versions and ranges per ecosystem (semver, PEP 440, Maven, Go); kernel build suffixes such as `6.8.0-45-generic` or `+deb12u1` do not order | schemes per ecosystem |
| `ledger` | domain state and identity: known issues, aliases, merging, findings, status, history, the judging record and each source's back-fill marks | none: in memory |
| `store` | persisting the ledger's `State`, optimistic revisions, lock-free `Reader` snapshots | `store.Storage`: file, memory, SQLite |
| `priority` | ordering and policy deadlines | none: pure |
| `feeds` | each source type into items with ranges, fixes, KEV data and CVSS ratings; `paged.go` follows NVD windows and pages and GitHub's `Link` header for a back-fill; `rating.go` picks the best rating of a record | `parsers` map: one adapter per type |
| `epss` | exploit probability lookup | `Getter` |
| `cvss` | CVSS lookup at NVD for tracked CVEs no feed rated | `Getter` |
| `httpx` | polite, guarded HTTP GET | `feeds.Getter` |
| `query` | read model: issues, age, chronological articles, fix info, targets; `Detail` (the issue page: targets with installed versions and evidence, links, affected ranges, why it ranks, history); the search syntax and its matching (`search.go`); the time filter (`timerange.go`: `TimeRange`, its presets and `ParseTimeRange`, used by `published:`, `-published` and the TUI's `t`) | |
| `export` | the versioned data contract and its writers | JSON, CSV, Markdown adapters; MCP |
| `evidence` | evidence pack and timeline for one issue | |
| `report`, `calendar`, `notify` | markdown, calendar page, channel messages | `notify.Channel`: Slack, webhook, email |
| `audit` | hash-chained audit log, readable by issue | |
| `doctor` | configuration and environment checks, `init` (saves through `projectflow` and `ops`) | |
| `catalog` | the technology catalog (open and closed source): lookup by name, image, package, file or word; validation; `Suggest` ranks the close names of a typed term (exact, prefix, containment, then edit distance, then the words a multi-word term shares) and never returns unrelated ones; `Slug` and `CheckName` for your own keywords (`name.go`) | shipped entries layered with the user's `techs.yaml` |
| `discovery` | what a repository uses, with evidence and confidence (lockfiles, version files, Dockerfiles, compose, Kubernetes, Terraform, `.tool-versions`); `ScanFile` reads one Dockerfile, compose or manifest file, and marks what only container files show as `Infra`; `Suggest` and `Complete` for the TUI folder box: child folders with project marks, and tab completion; `gitignore.go` (`NewIgnore`) is a git-compatible matcher for `.gitignore` and `.git/info/exclude`, with no git binary; `Options.IncludeIgnored` (`-all`) turns it off | one detector per source; reads files only |
| `projectfile` | comment-preserving edits of a project file: validate, diff, backup, atomic write; `OpTable` (`opspec.go`) is the one list of edit kinds, with their inputs, CLI flags and an example each; `when.go` holds the `when@<env>` blocks and the migration of `environments:`; `envs.go` the environment list edits, rename and `EnvHints`; `hints.go` `Hints` and `HintsFor`, the advice every front end shows; `CheckFiles` finds lockfiles that are missing or of the wrong type, with fixes (`Issue`, `Fix`) | none: pure plus one file write |
| `confdoc` | the configuration documents: `config.yaml`, `techs.yaml` and `sources/*.yaml`. `doc.go` reads them and keeps their YAML trees; `schema.go` describes every setting (path, type, section, allowed values, default, secret); `edit.go` applies set, unset, append and replace by path; `check.go` validates the result the way `config.Load` does; `write.go` saves atomically with a backup; `view.go` shows values, with secrets as `(set)` | none: pure, plus one file write |
| `mcpserver`, `cmd/cvewatch` | the MCP server and the CLI: parse input, call `ops`, print or return the result. The setup tools are in `setup.go`, the settings and whole-project tools in `manage.go`; the project input schema is built from `OpTable` (`schema.go`) | `ops` |
| `setup` | the setup flow: steps as data, defaults, validation, answers turned into project-file edits; `differ.go` holds the per-environment question and the difference lines; `custom.go` holds your own keyword technologies (`Lookup`, `AddCustom`, `Hints`) | `wizard`, `tui` and MCP are its adapters |
| `projectflow` | the one place that turns a typed folder or file (`ResolveSource`, scanned by `ScanSource`) or an existing project into a setup flow (`Open`), and the flow into project-file edits (`Edits`); `Change` adds the staged own technologies (`NewTechs`) so they are written with the project; lockfile paths made relative to the root | `ops.Session`; used by `tui`, `wizard` and `doctor` (`init`). Imports `ops`, `setup`, `discovery`, `projectfile`, `model` |
| `wizard`, `tui` | plain prompt and full-screen front ends of the setup flow. The TUI has five screens (Overview, Findings, Projects, Status and Settings), the project forms, the field editor, the lifecycle prompts, prompts and the folder box; see [The TUI](#the-tui). `tui` is its own program (`cvewatch-tui`) because Bubble Tea queries the terminal at start-up | `ops.Session` and `ops.SettingsSession`, through the `Backend` seam (`Read`, `Write`, `Settings`, `Fetch` and `TUISettings`) |
| `status` | health of the tool: daemon, feeds, channels, cycles | none: pure |
| `dashboard` | static HTML status and findings page, no scripts | none: pure |
| `daemon` | the refresh loop: heartbeat, dashboard, short sessions; `watch.go` looks at the configuration files every 15 seconds and reloads (revalidates and back-fills) when one changes | |
| `defaults` | built-in catalog, feeds and starter files | embedded; the user's folder is layered over it |
| `host` | everything that differs per operating system | Unix and Windows adapters |
| `config`, `model` | configuration and shared types; `model/cvss.go` holds a CVSS `Rating` (score, version, vector, source) and the precedence between ratings (`Rank`, `Better`, `BestRating`); `model.Env` is a free slug, ordered by `SortEnvs` (suggested names first) and named by `IsProd` and `IsDevLike`; `Project.TechsIn(env)` is what runs in one environment; `config/horizon.go` holds the alert horizon (`Horizon.Range`, `Contains`, `Problems`); `LoadLenient` lists broken project files under `Broken` instead of failing the load (repair sessions, `ops.OpenRepair`); `LoadTUI` reads only the `tui` periods, so the interface starts when the rest is broken | |
| `testkit`, `golden` | shared test rig; replay of fixtures through the shipped configuration | |

## The TUI

The TUI is a Bubble Tea program in `app/src/tui`. Its state is the `app` model in `ui.go`. The keys, the footer and the help are built from data:

| File | Owns |
|---|---|
| `modes.go` | a **mode** is one layer on screen: a screen, a level inside it, a form, or a popup. Each mode has its bindings, its moving keys and its help title. `stack` derives the open layers from the state, so they cannot drift. `dispatch` runs a key on the top mode. The footer (`footerLine`) and the help (`helpLines`) are written from the same table |
| `keymap.go` | the binding table of every mode, built in `init`. A binding has its keys, a label for the help, a short label for the footer, an optional alias, a priority that decides what the footer drops first, and an optional `when` condition. The keys of the field editor and the lifecycle prompts are in `editkeys.go`, and those of the Settings screen in `settings.go`; they are built the same way |
| `screens.go` | the screens, one row each: name, number key, whether it works without the snapshot, and the modes, body, layout, breadcrumb and tab badge. The tabs, Left and Right, the number keys and the help all read this table |
| `fields.go` | the project field editor (`c`): the fields of a project file (environments, technologies, lockfiles, differences per environment, since), their rows, and the edits they build (`OpKinds`) |
| `envsummary.go` | the pure helpers behind the lists: the `PROJECTS (ONLY IN)` cell (a project's name alone when it is open everywhere it runs) and the Overview's `by environment` line |
| `timefilter.go` | the time filter: `t` cycles `query.TimeRange`, `0` clears it, the `published:` chip on the breadcrumb line, and the alert horizon text on Overview and Status |
| `hints.go` | the Hints section of a project and of the review, the hints picker (`H`) and what each hint does (apply its fix, offer the keyword prompt or the closest names) |
| `techassist.go`, `usertechs.go` | the add-technologies step: the closest-name rows under the text and `ctrl+o`; your own technologies in Settings and their add and edit forms |
| `sethorizon.go` | the alert horizon fields in Settings: Google-style window labels, the custom dates shown as inactive unless the window is custom |
| `lifecycle.go` | a whole-project change on its way: the consequences from `ops.ProjectLifecycle`, the typed name for a delete, the apply and the message when it fails |
| `settings.go`, `setmodel.go`, `setedit.go` | the Settings screen. `settings.go` holds the screen and its levels; `setmodel.go` arranges the documents from `ops` into sections, records and fields, with no drawing; `setedit.go` holds the editors, and each one ends in a list of `confdoc` edits that `ops` previews |
| `detail.go`, `docview.go` | the issue page: its layout (environments, references, evidence, history) and the report and evidence-pack views |
| `desktop.go` | what the machine does for the TUI: show a link (`open`, `xdg-open` or `rundll32`) and copy text (`pbcopy`, `clip`, `wl-copy`, `xclip`, `xsel` or `clip.exe`). Commands run without a shell; tests replace the whole thing with a fake |
| `viewport.go` | the cursor and visible window of every list and scrolling text. The shared movement keys (up, down, paging, home, end) are handled here once, not in the tables |
| `crumbs.go` | the breadcrumb: the levels the user is in, each with the action that goes back to it |
| `mouse.go` | the pointer: the wheel, a click on a row, the screen tabs and the breadcrumb |
| `pending.go` | the writes and scans in flight. A count, not a flag, with one key per operation: a second operation with the same key is refused. When one ends, its reloads run and its result is reported (`opDone`) |
| `goto.go` | go-to targets (a screen, an issue, a project, a findings filter), `goTo` that moves to one, and the return point that Esc uses to come back |
| `jump.go` | the jump box: matching issues and projects as the user types |
| `overview.go` | the Overview: the summary above the list of every open issue, and the policy violations page (`v`) |
| `findings.go` | `issueList`, the searchable list that Findings and Overview share: rows, cursor, severity floor and search text. Each screen has its own, so a search on one does not narrow the other |
| `scope.go` | the project scope: `m.scope` narrows the issues (`narrow`, `dataIssues`), the policy violations and the counts to one project, and is dropped when its project is gone or disabled |
| `fetch.go` | the background fetch: one run at a time (`fetchJob`), the progress cell in the header, progress messages throttled per phase, the failed sources, and the timers of `tui.refresh` and `tui.fetch`. The run holds the store only inside `Backend.Fetch`; the screens keep reading the ledger meanwhile, and quitting cancels the run |
| `revalidate.go` | the revalidation job in the TUI: the quiet run when a read finds the findings out of date, the words of its note, and the `V` preview with its yes prompt |
| `editor.go` | which editor `E` runs: `resolveEditor` takes `tui.editor`, then `$VISUAL`, then `$EDITOR`, then the usual editors on the path, with the environment and the lookup injected for tests |
| `fix.go`, `form.go`, `prompt.go`, `folder.go` | the flows that use the modes: fix previews, the project form, the prompts and the folder box |

Rule for keys: a key is one binding in its mode's table (`keymap.go`, `editkeys.go` or `settings.go`). The footer and the help pick it up by themselves. Do not add a key in a second place.

### Screens

| Key | Screen | Shows |
|---|---|---|
| 1 | Overview | the health line, the list of every open issue (searchable, narrowed by the project scope) and the policy violations (`v`), each opening its issue |
| 2 | Findings | the issue list, the issue page, triage and the filter |
| 3 | Projects | the project list, each project's problems and fixes, its security issues, the field editor, the add chooser (`+`), the folder box and the lifecycle keys; Enter on a project sets the scope |
| 4 | Status | the daemon, the feeds, the channels and the last cycles |
| 5 | Settings | the configuration files as sections and fields. It is the only screen that works without the snapshot of the others, so it opens when a file is broken |

Settings reads the documents through `ops.OpenSettings`, which loads nothing. Nothing is written before the yes on a preview: every editor builds a list of `confdoc.Edit` values, and `ops` checks and previews them. A list of edits is one change; it saves all of them or none.

Rules of thumb kept by the structure:

- A rule lives in one place. Relevance and versions in `relevance` and `version`, identity and merging in `ledger`, validation and access in `ops`.
- A new setting is one row in `confdoc/schema.go`. `TestSchemaCoversEveryKey` fails when a key of `config.Settings`, `model.Tech` or `model.Source` has no row.
- Environments are free names. Compare them with `model.IsProd` and `model.IsDevLike`, order them with `model.SortEnvs`, and never write a fixed list of four. `Project.EffectiveEnvs()` gives the old default only for a file without `envs`.
- The alert horizon is one function, `config.Horizon.Range` and `Contains`. Judging (`Inventory.Within`), alerts, digests (through `query.InHorizon`) and the time filter all use it.
- A new project edit kind is one row in `projectfile.OpTable` and its case in `apply`. The parity tests then check its CLI flag (`TestEveryOpKindHasACLIFlag`) and the MCP schema (`TestProjectSchemaCoversTheOpTable`). `setup/opkinds.go` must also list the kind in `OpKinds` or `NotYet`, which a test enforces. The TUI editor's own `OpKinds` list in `fields.go` is kept by hand.
- A new screen is one row in the screens table (`screens.go`).
- Front ends hold no behaviour. `cmd/cvewatch`, `mcpserver`, `wizard` and `tui` parse input and draw output; setup rules live in `setup`, operations in `ops`, and the folder-to-flow and flow-to-edits steps in `projectflow`.
- Viewers never block the daemon: reads use a snapshot without the lock, and every write is one short session that retries once if another process saved first.
- Long work reports through callbacks and never blocks a key. `Runner.Progress` and `RefreshWith` only report; the TUI turns the reports into messages, and a fetch that finds the store busy is retried later instead of failing.
- Stored advisories are judged again only by `pipeline.Revalidate`, on request or at the start of a cycle when `inventory.Compare` finds the judging inputs changed. A new judging input goes into `inventory.Judging`, not into a front end.
- Only technologies a project declares are judged, so a large catalog costs nothing in noise.
- Persistence is replaceable (three adapters share one contract test). `ledger` never touches files; `store` never makes domain decisions.
- Feed text is untrusted at every step: cleaned on the way in, escaped on the way out.
