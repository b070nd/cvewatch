# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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
