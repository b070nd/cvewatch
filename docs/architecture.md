# Architecture

One package per concern under `app/src`. The arrows show who depends on whom; the seams are where behaviour can change without editing in place.

| Module | Owns | Seam |
|---|---|---|
| `ops` | every operation (list, show, why, rescan, calendar, resolve, refresh), validation, access rules, audit order | CLI and MCP are its two adapters |
| `pipeline` | one refresh cycle: fetch, judge, record, report, alert | `feeds.Getter`, `notify.Notifier` |
| `relevance` | what an item is about, which projects run it, version verdict, reasons | none: pure rules |
| `version` | comparing versions and ranges, with partial versions (series) | none: pure |
| `ledger` | domain state and identity: known issues, aliases, merging, findings, status | none: in memory |
| `store` | persisting the ledger's `State` | `store.Storage`: JSON file and memory adapters |
| `feeds` | turning each source type into items with ranges and fixes | `parsers` map: one adapter per type |
| `httpx` | polite, guarded HTTP GET | `feeds.Getter` |
| `matrix` | reading lockfiles | one adapter per lockfile type |
| `query` | read model: issues, age, chronological articles, fix info | |
| `report`, `calendar`, `notify` | markdown, calendar page, Slack text | |
| `audit` | hash-chained audit log | |
| `host` | everything that differs per operating system | Unix and Windows adapters |
| `config`, `model` | configuration and shared types | |

Rules of thumb kept by the structure:

- A rule lives in one place. Relevance and versions in `relevance` and `version`, identity and merging in `ledger`, validation and access in `ops`.
- Front ends hold no behaviour. `cmd/cvewatch` and `mcpserver` parse input and print output.
- Persistence is replaceable. `ledger` never touches files; `store` never makes domain decisions.
- Feed text is untrusted at every step: cleaned on the way in, escaped on the way out.
