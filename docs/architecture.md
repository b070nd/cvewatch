# Architecture

One package per concern under `app/src`. The arrows show who depends on whom; the seams are where behaviour can change without editing in place.

| Module | Owns | Seam |
|---|---|---|
| `ops` | every operation (list, show, why, rescan, calendar, status, assign, evidence, export, policy, digest, inventory, refresh), validation, access rules, audit order | CLI and MCP are its two adapters |
| `pipeline` | one refresh cycle: fetch, judge, record, reconcile, enrich, report, alert, digest | `feeds.Getter`, `notify.Channel` |
| `inventory` | what runs in each project environment | `matrix` adapters |
| `matrix` | reading lockfiles and SBOMs | one adapter per type (ten today) |
| `ecosystem` | package names, aliases, normalization | none: pure |
| `relevance` | what an item is about, which environments run it, version verdict, reasons | none: pure rules |
| `version` | comparing versions and ranges per ecosystem (semver, PEP 440, Maven, Go) | schemes per ecosystem |
| `ledger` | domain state and identity: known issues, aliases, merging, findings, status, history | none: in memory |
| `store` | persisting the ledger's `State`, optimistic revisions | `store.Storage`: file, memory, SQLite |
| `priority` | ordering and policy deadlines | none: pure |
| `feeds` | each source type into items with ranges, fixes and KEV data | `parsers` map: one adapter per type |
| `epss` | exploit probability lookup | `Getter` |
| `httpx` | polite, guarded HTTP GET | `feeds.Getter` |
| `query` | read model: issues, age, chronological articles, fix info, targets | |
| `export` | the versioned data contract and its writers | JSON, CSV, Markdown adapters; MCP |
| `evidence` | evidence pack and timeline for one issue | |
| `report`, `calendar`, `notify` | markdown, calendar page, channel messages | `notify.Channel`: Slack, webhook, email |
| `audit` | hash-chained audit log, readable by issue | |
| `doctor` | configuration and environment checks, `init` | |
| `defaults` | built-in techs, feeds and starter files | embedded and user's folder |
| `host` | everything that differs per operating system | Unix and Windows adapters |
| `config`, `model` | configuration and shared types | |
| `testkit`, `golden` | shared test rig; replay of fixtures through the shipped configuration | |

Rules of thumb kept by the structure:

- A rule lives in one place. Relevance and versions in `relevance` and `version`, identity and merging in `ledger`, validation and access in `ops`.
- Front ends hold no behaviour. `cmd/cvewatch` and `mcpserver` parse input and print output.
- Persistence is replaceable (three adapters share one contract test). `ledger` never touches files; `store` never makes domain decisions.
- Feed text is untrusted at every step: cleaned on the way in, escaped on the way out.
