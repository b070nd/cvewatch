# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Folder box in the TUI for new projects: Tab completes, Shift+Tab goes up one folder, Up and Down pick a folder. Rows show the lockfiles and manifests in each folder and a `project` tag.
- TUI Projects screen shows a problems column and the problems of the selected project. `f` previews and applies a fix, `o` opens the file in `$EDITOR`. A project file that cannot be read is shown as broken instead of stopping the TUI.
- `check_projects` MCP tool: read-only report of problems in project files, with the fixes it knows.
- Validation warns when a lockfile's `env` is not in the project's `envs`, since such a lockfile is never read.
- TUI breadcrumb under the screen tabs. Left, Esc and Backspace go back one level.
- TUI jump box (`:` or Ctrl+G) to an issue by ID or a project by name. Overview, Status, issue and project rows link to their targets, and Esc returns to where you came from.
- TUI triage: `]` and `[` for the next and previous issue, Space and Ctrl+A to mark issues, and one status change for all marked issues.
- TUI mouse support: wheel, click to select, clickable tabs and breadcrumb.
- TUI `E` opens the project file at the problem's line in vim, nano, emacs, VS Code, Sublime Text and more.
- TUI fix preview lists every fix of a problem; `[` and `]` choose one.
- TUI project form: `e` on the review changes one step and returns to the review.

### Changed
- TUI: Enter on a project opens it, with its problems and fixes. `e` edits the project.
- TUI: `a` adds a project (`n` still works). `x` previews a fix (`f` still works). `E` opens the editor (`o` still works on Projects).
- TUI: Esc cancels a fix preview. `n` no longer cancels it.
- TUI: `q` quits only from the root of a screen. Inside a level or a popup it goes back.

### Fixed
- `edit_project` and `preview_project_change` accept a `lockfile` object, so fixes from `check_projects` can be passed on as they are.
- `cvewatch init` saved lockfile paths as absolute paths with the default `-root .`; they stay relative to the root now.
- `cvewatch init -force` now edits an existing project file in place: its comments stay, and the old file is backed up.
- TUI prompts keep what was typed when a write is refused, and show the reason.
- TUI Projects cursor stays on its project when the list changes.
- TUI open issue reloads after a status, assign, bulk or editor change.
- TUI refuses a second submit of a change that is still being saved, so it is not written twice.

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
