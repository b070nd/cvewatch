# Architecture

One package per concern under `app/src`. The arrows show who depends on whom; the seams are where behaviour can change without editing in place.

| Module | Owns | Seam |
|---|---|---|
| `ops` | every operation (list, show, search, why, rescan, calendar, status, assign, evidence, export, policy, digest, inventory, project edits, project problems, refresh), validation, access rules, audit order | CLI, TUI and MCP are its adapters; read-only sessions read a lock-free snapshot |
| `pipeline` | one refresh cycle: fetch, judge, record, reconcile, enrich, report, alert, digest | `feeds.Getter`, `notify.Channel` |
| `inventory` | what runs in each project environment | `matrix` adapters |
| `matrix` | reading lockfiles and SBOMs | one adapter per type (ten today) |
| `ecosystem` | package names, aliases, normalization | none: pure |
| `relevance` | what an item is about, which environments run it, version verdict, reasons; skips items published before a project's `since` date | none: pure rules |
| `version` | comparing versions and ranges per ecosystem (semver, PEP 440, Maven, Go) | schemes per ecosystem |
| `ledger` | domain state and identity: known issues, aliases, merging, findings, status, history | none: in memory |
| `store` | persisting the ledger's `State`, optimistic revisions, lock-free `Reader` snapshots | `store.Storage`: file, memory, SQLite |
| `priority` | ordering and policy deadlines | none: pure |
| `feeds` | each source type into items with ranges, fixes and KEV data | `parsers` map: one adapter per type |
| `epss` | exploit probability lookup | `Getter` |
| `httpx` | polite, guarded HTTP GET | `feeds.Getter` |
| `query` | read model: issues, age, chronological articles, fix info, targets; the search syntax and its matching (`search.go`) | |
| `export` | the versioned data contract and its writers | JSON, CSV, Markdown adapters; MCP |
| `evidence` | evidence pack and timeline for one issue | |
| `report`, `calendar`, `notify` | markdown, calendar page, channel messages | `notify.Channel`: Slack, webhook, email |
| `audit` | hash-chained audit log, readable by issue | |
| `doctor` | configuration and environment checks, `init` (saves through `projectflow` and `ops`) | |
| `catalog` | the technology catalog (open and closed source): lookup by name, image, package, file or word; validation | shipped entries layered with the user's `techs.yaml` |
| `discovery` | what a repository uses, with evidence and confidence (lockfiles, version files, Dockerfiles, compose, Kubernetes, Terraform, `.tool-versions`); `Suggest` and `Complete` for the TUI folder box: child folders with project marks, and tab completion | one detector per source; reads files only |
| `projectfile` | comment-preserving edits of a project file: validate, diff, backup, atomic write; `CheckFiles` finds lockfiles that are missing or of the wrong type, with fixes (`Issue`, `Fix`) | none: pure plus one file write |
| `setup` | the setup flow: steps as data, defaults, validation, answers turned into project-file edits | `wizard`, `tui` and MCP are its adapters |
| `projectflow` | the one place that turns a typed folder (`ResolveFolder`) or an existing project into a setup flow (`Open`), and the flow into project-file edits (`Edits`); lockfile paths made relative to the root | `ops.Session`; used by `tui`, `wizard` and `doctor` (`init`). Imports `ops`, `setup`, `discovery`, `projectfile`, `model` |
| `wizard`, `tui` | plain prompt and full-screen front ends of the setup flow. The TUI has the Overview, Findings, Projects and Status screens, the project forms, prompts and folder box; see [The TUI](#the-tui). `tui` is its own program (`cvewatch-tui`) because Bubble Tea queries the terminal at start-up | `ops.Session`, through the `Backend` seam (`Read` and `Write`) |
| `status` | health of the tool: daemon, feeds, channels, cycles | none: pure |
| `dashboard` | static HTML status and findings page, no scripts | none: pure |
| `daemon` | the refresh loop: heartbeat, dashboard, short sessions | |
| `defaults` | built-in catalog, feeds and starter files | embedded; the user's folder is layered over it |
| `host` | everything that differs per operating system | Unix and Windows adapters |
| `config`, `model` | configuration and shared types; `LoadLenient` lists broken project files under `Broken` instead of failing the load (repair sessions, `ops.OpenRepair`) | |
| `testkit`, `golden` | shared test rig; replay of fixtures through the shipped configuration | |

## The TUI

The TUI is a Bubble Tea program in `app/src/tui`. Its state is the `app` model in `ui.go`. The keys, the footer and the help are built from data:

| File | Owns |
|---|---|
| `modes.go` | a **mode** is one layer on screen: a screen, a level inside it, a form, or a popup. Each mode has its bindings, its moving keys and its help title. `stack` derives the open layers from the state, so they cannot drift. `dispatch` runs a key on the top mode. The footer (`footerLine`) and the help (`helpLines`) are written from the same table |
| `keymap.go` | the binding table of every mode, built in `init`. A binding has its keys, a label for the help, a short label for the footer, an optional alias, a priority that decides what the footer drops first, and an optional `when` condition |
| `viewport.go` | the cursor and visible window of every list and scrolling text. The shared movement keys (up, down, paging, home, end) are handled here once, not in the tables |
| `crumbs.go` | the breadcrumb: the levels the user is in, each with the action that goes back to it |
| `mouse.go` | the pointer: the wheel, a click on a row, the screen tabs and the breadcrumb |
| `pending.go` | the writes and scans in flight. A count, not a flag, with one key per operation: a second operation with the same key is refused. When one ends, its reloads run and its result is reported (`opDone`) |
| `goto.go` | go-to targets (a screen, an issue, a project, a findings filter), `goTo` that moves to one, and the return point that Esc uses to come back |
| `jump.go` | the jump box: matching issues and projects as the user types |
| `fix.go`, `form.go`, `prompt.go`, `folder.go` | the flows that use the modes: fix previews, the project form, the prompts and the folder box |

Rule for keys: a key is one binding in `keymap.go`. The footer and the help pick it up by themselves. Do not add a key in a second place.

Rules of thumb kept by the structure:

- A rule lives in one place. Relevance and versions in `relevance` and `version`, identity and merging in `ledger`, validation and access in `ops`.
- Front ends hold no behaviour. `cmd/cvewatch`, `mcpserver`, `wizard` and `tui` parse input and draw output; setup rules live in `setup`, operations in `ops`, and the folder-to-flow and flow-to-edits steps in `projectflow`.
- Viewers never block the daemon: reads use a snapshot without the lock, and every write is one short session that retries once if another process saved first.
- Only technologies a project declares are judged, so a large catalog costs nothing in noise.
- Persistence is replaceable (three adapters share one contract test). `ledger` never touches files; `store` never makes domain decisions.
- Feed text is untrusted at every step: cleaned on the way in, escaped on the way out.
