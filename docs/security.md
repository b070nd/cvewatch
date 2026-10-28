# Security

What the tool defends against, how, and how to deploy it.

## Trust model

| Input | Trusted? | Why it matters |
|---|---|---|
| Config files (`config/`, `sources/`) | yes, operator-controlled | whoever edits them decides which URLs are fetched and which files are read |
| Feed content (titles, summaries, links) | **no** | it comes from public sites and ends up in reports, Slack, the terminal and agents |
| Lockfiles | mostly | parsed as data, size-capped |
| Slack webhook URL | secret | anyone holding it can post to the channel |
| MCP client | acts as the local user | stdio only, no network listener |

## Built-in protections

- **Network egress**
  - https only. Plain http and internal targets need `http.allow_private: true`.
  - Loopback, private, link-local, multicast and carrier-grade NAT addresses are refused after DNS resolution, so a public name cannot be pointed at an internal service. Redirects get the same check, and a redirect from https to http is refused.
  - Credentials in URLs are rejected; use `headers`. A cross-host redirect drops custom headers.
  - Timeouts, a response size cap (16 MiB default), per-host rate limits, retries with backoff and a cooldown after repeated 429s.
  - Behind an internal proxy the guard sees the proxy's address; set `allow_private: true` and restrict egress at the proxy.
- **Channels**
  - Webhooks are https only (http only with `allow_private`), signed with HMAC-SHA256 in `X-Cvewatch-Signature` when a secret is set, retried with backoff, and the URL and secret never appear in errors.
  - Email uses STARTTLS when the server offers it, validates sender and recipients, and strips line breaks and control characters from every header value, so feed text cannot inject headers or recipients.
  - Each channel is tracked separately; a failing one does not cause repeats on the others.
- **Exports and input**
  - CSV cells that spreadsheets could read as formulas (starting with `=`, `+`, `-`, `@`, tab or CR) are prefixed with a quote; markdown and evidence output escape feed and user text.
  - Notes, owners, tickets and evidence links typed by people or agents are cleaned (control characters and line breaks removed, length bounded); evidence links must be plain http(s).
- **Outside lookups**
  - The only optional lookup is EPSS (`enrich.epss`), off by default. It sends CVE ids of issues you track, nothing else, to FIRST's public API over https.
  - `doctor -online` contacts NVD and the configured feeds; it never prints secrets.
- **Storage**
  - The SQLite file and its sidecar files are created owner-only; writes carry a revision, so a stale writer is refused instead of overwriting newer data.
- **Secrets**
  - The Slack webhook is read from an environment variable, must be https, and is stripped from error messages. Query strings and credentials are removed from logged feed URLs.
  - Nothing secret is written to state, reports or the audit log.
- **Untrusted text**
  - Control characters and invisible direction-override characters are removed from feed text, so it cannot drive a terminal or disguise itself.
  - Markdown reports escape `<` and `>` and table separators. Slack text is escaped. Links must be plain http(s) without characters that could break markup, or the item is skipped.
  - MCP and JSON output put feed text under an `untrusted` field, and the server tells agents to treat it as data.
- **Files**
  - State, audit log and reports are created owner-only (0600, directories 0700), because they list your unpatched systems. Writes are atomic.
  - One process may write at a time (lock file).
  - Report file names are built from a fixed alphabet, so feed content cannot choose a path.
- **Access rules**
  - Optional per-actor project access and write rights are enforced in one module (`ops`) for the CLI and MCP alike. They rely on the local identity (`CVEWATCH_ACTOR` or the OS user); they are not authentication.
  - Without rules everyone who can run the tool may do everything.
- **Agents**
  - The MCP server is read-only unless started with `-allow-write`. Write tools are recorded in the audit log.
- **Accountability**
  - A hash-chained audit log records detections, alerts and every status change with an actor. `cvewatch audit` verifies it. Editing or deleting a record in the middle is detected; truncating the end or rewriting the whole file is not. Forward the log to a system you do not administer if you need that.
  - A status change is refused if it cannot be logged.

## Deploying

- Run as an unprivileged user, never as root. The container image runs as UID 65532 and works with `--read-only` and `--cap-drop ALL`; only `/data` and `/alerts` need to be writable.
- Restrict outbound traffic to the feed hosts and your Slack workspace if you can. The list is the `url` hosts in `sources/`.
- Keep the webhook in a secret store or an `.env` file outside the repository (it is git-ignored). Rotate it if it leaks.
- Mount lockfiles read-only. The tool never writes to them.
- Keep `data/` and `alerts/` out of version control and back them up like other operational records. Both are git-ignored.
- Set `CVEWATCH_ACTOR` to a team name if you do not want personal user names in the audit log.
- Pin the image by digest and verify release checksums. Release images carry build provenance and an SBOM.

## Known limits

- Matching by text can miss a vulnerability that no feed describes in the words you configured, and can raise false alarms. It is an early-warning aid, not a scanner.
- Versions are not compared with affected ranges.
- On Windows the OS does not enforce the 0600/0700 modes; owner-only access then depends on the profile folder's ACLs.
- Anyone who can read `data/` can see your exposure; anyone who can write to it can mark findings fixed. Protect the directory with file permissions.
- The audit chain has the limits described above.
- Dependencies are few (YAML parser, the MCP SDK, a pure-Go SQLite driver, `golang.org/x/sys` on Windows). CI runs `govulncheck`, and Dependabot proposes updates.

## Reporting problems

See [../SECURITY.md](../SECURITY.md).
