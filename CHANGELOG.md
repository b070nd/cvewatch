# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
