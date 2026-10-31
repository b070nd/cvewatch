# NIS2 and GDPR

This page explains how cvewatch can support an organisation's duties under NIS2 and the GDPR. It is not legal advice, and no tool makes an organisation compliant. Compliance depends on how you run the tool and on the rest of your programme. Have your security, privacy and legal people review your use of it.

The operator (you) is the controller of any data the tool holds. The maintainers of this project process none of it: the tool has no telemetry and contacts only the feeds and the Slack webhook you configure.

## NIS2 (Directive (EU) 2022/2555)

Article 21(2) requires essential and important entities to take proportionate risk-management measures. Two of them concern what this tool does:

| Measure | How cvewatch helps | What it does not do |
|---|---|---|
| 21(2)(e) vulnerability handling in acquisition, development and maintenance | Watches public sources including CISA KEV (actively exploited flaws), matches them to your technologies and dependencies, creates a finding per project and environment, and tracks remediation from open to fixed or ignored | Does not scan systems, confirm that you are affected, or patch anything |
| 21(2)(d) supply chain security | Reads `composer.lock` and `package-lock.json`, so advisories for your actual dependencies are matched by package name | Does not cover other ecosystems, transitive risk scoring or supplier assessments |
| 21(2)(a) risk analysis | Gives severity, CVSS and known-exploited signals as input | Does not rate business impact; people decide priorities |
| 21(2)(e) knowing what you run | The catalog, discovery and project files record which technologies, versions and lockfiles each project and environment declares, with evidence for each guess and an audited change history | Does not inventory hosts or images; people confirm what discovery proposes |
| 21(2)(f) assessing effectiveness | Open findings by severity and the audit log show how quickly issues are detected and closed | Defines no targets; set your own deadlines |

Article 20 makes management bodies responsible for oversight. The open-findings list and the per-issue reports give management a current view of known exposure.

### Evidence an auditor may ask for

`cvewatch evidence ID` assembles one issue's evidence pack: when it was published and first seen, who was alerted, every status change with actor, time and reason, owners, due dates, tickets, attached evidence, and the per-environment matrix, together with whether the audit chain verified. `cvewatch export` gives the open-items list with every environment's status as JSON, CSV or Markdown. `cvewatch policy` shows missed deadlines.

| Question | Where the answer is |
|---|---|
| When did we learn about this issue? | `detected` record in `data/audit.log`; `first_seen` in `cvewatch show ID -json` |
| Who was told, and when? | `alerted` record |
| Who marked it fixed or accepted it, when, and why? | `status` record: actor, time, environment, note (put the ticket or merge request there) |
| What is open right now? | `cvewatch list` |
| Was the log altered? | `cvewatch audit` (see the limits in [security.md](security.md)) |
| What do we monitor and since when? | `config/techs.yaml`, `config/projects/`, `sources/`, kept in version control by you |

### Not covered

- **Incident reporting (Article 23).** The early warning (24 hours), incident notification (72 hours) and final report duties are out of scope. A finding is not an incident.
- Business continuity, access control, cryptography policy, training and the other measures in 21(2).
- Your national transposition may add requirements. Check it.

### Making it work for an audit

- Run the daemon continuously and keep `interval` short (4 hours by default).
- Record a ticket or change reference in `-note` for every `fix` and `ignore`.
- Decide how long `data/audit.log` is kept and back it up. The tool never prunes it.
- Review `ignored` findings periodically; `ignore` is a risk acceptance and should have an owner.

## GDPR

### What data the tool holds

| Data | Personal data? | Notes |
|---|---|---|
| Vulnerability titles, summaries, links, severity | No, by design | Titles may mention a person by chance (for example a researcher); the tool keeps no author fields |
| Project names, technologies, package names and versions | No | Confidential rather than personal. They describe your systems |
| `-note` text, evidence notes, owner and ticket fields | Possibly | Free text and names of people who own work. Use a team name or alias as owner and ticket ids in notes if you do not want personal data in the tool |
| `actor` in the audit log | Yes | Defaults to the OS user name of whoever ran the command. Set `CVEWATCH_ACTOR` to a team name or pseudonym to avoid recording a person |
| Slack messages | Possibly | Contain vulnerability ids, project names and environments. Slack is a processor for you |
| Outbound requests | IP address | Feed providers see your server's IP address and the `user_agent` string. The default User-Agent contains no personal data |
| CVSS lookups (on by default) | No personal data | Sends CVE ids of tracked issues that no feed rated to NVD's public API. Set `enrich.cvss: false` to stop it |
| EPSS lookups (opt-in) | No personal data | Sends CVE ids of tracked issues to FIRST. This reveals which vulnerabilities you track, so it is off by default |
| Project files and their backups | Possibly | Project names and technologies are not personal. `project` entries in the audit log carry the actor like every other change |
| Webhook and email recipients | Yes, for email | Recipient addresses are in your config; messages contain vulnerability ids, project names and environments |

There are no cookies, accounts, analytics or telemetry.

### Principles

- **Minimisation:** the tool collects no personal data from feeds and asks for none. The only personal data it can hold comes from what your staff type or from their user name.
- **Storage limitation:** items that matched nothing are forgotten after `retention` (180 days by default). Findings and the audit log are kept until you delete them; set your own retention period for both.
- **Integrity and confidentiality:** owner-only files, https only, secrets kept out of logs, tamper-evident audit log. See [security.md](security.md).
- **Accountability:** the audit log records who changed what, which is also the personal data in it. Recording it is usually justified by your legitimate interest in security and accountability (Article 6(1)(f)) and by the NIS2 duties above. Document that in your records of processing and inform staff.

### Things you should do

1. Use a pseudonymous `CVEWATCH_ACTOR` (for example `team-security`) unless you need to know the individual. This avoids most personal data in the log and makes erasure requests moot.
2. Sign a data processing agreement with Slack, or leave Slack off. The tool works without it.
3. Tell users not to put personal data in `-note`.
4. If you must erase a person's name from the audit log, archive the old file, start a new log, and record the reason. Editing a line in place breaks the hash chain on purpose. Weigh this against your audit retention needs before storing personal names at all.
5. Add the tool to your record of processing activities. A data protection impact assessment is unlikely to be needed for the data described above; your data protection officer decides.
6. Keep `data/`, `alerts/` and backups on access-controlled storage.

### Data transfers

The tool itself transfers nothing outside the endpoints you configure. Feeds are fetched from the hosts in `sources/` (some are outside the EU), and Slack alerts go to Slack's servers. Check these against your transfer rules.

## What is not claimed

The project does not claim certification or conformity with NIS2, the GDPR or any standard. The Cyber Resilience Act has not been assessed.
