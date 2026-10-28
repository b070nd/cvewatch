# Search and lookup

Two commands find issues. `show` opens one issue by its exact ID. `search` finds issues by words, phrases, IDs (or part of an ID) and fields such as the severity or the project. Both read the local data only.

## Look up one CVE

```bash
cvewatch show CVE-2026-1234
```

`show` needs the exact ID. An alias works too, so the GHSA id of the same issue opens it. When the ID is unknown, `show` suggests up to five close matches:

```text
unknown vulnerability "CVE-2026-123"; did you mean: CVE-2026-1234, CVE-2026-1235
```

## Search

```bash
cvewatch search php memory
cvewatch search -min high "use after free"
cvewatch search -open -project shop severity:high+
cvewatch search -- -wordpress
```

`search` takes these flags. Put the flags before the query. Anything after the first word of the query is read as query text.

| Flag | What it keeps |
|---|---|
| `-open` | findings that are still open. Each issue shows only its open environments. |
| `-min S` | this severity and above: `low`, `medium`, `high` or `critical` |
| `-project P` | one project |
| `-env E` | one environment: `dev`, `int`, `staging` or `prod` |
| `-json` | the same JSON document that `list -json` prints |

Without `-open`, every status counts: open, fixed, ignored and not affected. Each issue lists its environments with their status.

The output starts with `Matches: N` and groups the issues by severity, as `list` does. A word that equals an ID or an alias puts that issue first. The other issues keep the order of `list`. If nothing matches, the output says `No issue matches "..."`.

### A query that starts with a dash

A word that starts with `-` is read as a flag, so `cvewatch search -wordpress` fails. Put `--` before the query. Everything after `--` is query text:

```bash
cvewatch search -- -wordpress
```

## Syntax

A query is a list of pieces separated by spaces. An issue must match every piece.

| Piece | Example | Matches issues where |
|---|---|---|
| word | `php` | the text contains the word |
| phrase | `"use after free"` | the words appear together, in this order |
| exclusion | `-wordpress` | the text does not contain the word |
| alternatives | `php OR openssl` | either side matches |
| field | `severity:high+` | the field has that value (see Fields below) |

```bash
cvewatch search php -wordpress               # php, without wordpress
cvewatch search php OR openssl status:open   # php or openssl, open in some environment
cvewatch search severity:high+ env:prod      # high or critical, in prod
cvewatch search "use after free" project:shop
```

Rules:

- Words are not case sensitive. `PHP` finds `php`.
- A word matches part of a word. `php` also finds `phpmyadmin`.
- A plain word looks in the ID, aliases, title, description, technologies, project, environment, owner, ticket and matched packages.
- The dash must come right before the word, with no space.
- `OR` must be in capitals, with a term on each side. Otherwise it is an ordinary word, so `php or openssl` looks for three words.
- `OR` binds tighter than the space. `php OR openssl status:open` means (php or openssl) and status open.
- A colon after letters starts a field. To search for text that contains a colon, put the whole word in quotes, as in `"http://example.test"`.

A mistake stops the search with a message instead of an empty list:

- `unknown field "foo"; use one of: id, severity, project, env, owner, ticket, tech, status, applies, kev, fix, overdue, after, before`
- `unknown severity "urgent"; use low, medium, high, critical or unknown, and add + for that or worse`
- `missing value after owner:`
- `bad date "2026-9-1" for after; use YYYY-MM-DD`

## Fields

Each field has a short alias where one is shown.

| Field | Matches | Values | Example |
|---|---|---|---|
| `id` (`cve`) | the ID or an alias. A `*` at the end matches a prefix. | any ID | `id:CVE-2026-1234`, `id:CVE-2026-12*` |
| `severity` (`sev`) | the severity. `+` means that severity or worse. | `low`, `medium`, `high`, `critical`, `unknown` | `severity:high+` |
| `project` | the project | the name in the project file | `project:shop` |
| `env` | the environment | `dev`, `int`, `staging`, `prod` | `env:prod` |
| `owner` | the owner set with `assign` | any name | `owner:"Jane Doe"` |
| `ticket` | the ticket set with `assign` | any text | `ticket:OPS-12` |
| `tech` | a technology of the issue | the technology name | `tech:php` |
| `status` | the status in some environment | `open`, `fixed`, `ignored`, `not_affected` | `status:open` |
| `applies` | whether the installed version is affected | `affected`, `unknown`, `not_affected` | `applies:affected` |
| `kev` | the issue is in the CISA KEV catalog | `yes`, `no` | `kev:yes` |
| `fix` | a fix is known. `official` means a vendor or authority says so. | `yes`, `no`, `official` | `fix:official` |
| `overdue` | an open finding whose due date has passed | `yes`, `no` | `overdue:yes` |
| `after` | published on or after this day | `YYYY-MM-DD` | `after:2026-09-01` |
| `before` | published before this day | `YYYY-MM-DD` | `before:2026-10-01` |

Notes:

- A value must match exactly, ignoring case. `owner:jane` does not find `Jane Doe`. The only partial match is `id:` with a `*` at the end.
- `severity:high` means high only. `severity:high+` means high and critical.
- `kev`, `overdue` and `fix` also accept `true` and `false` for `yes` and `no`.
- `after` includes its day and `before` does not. An issue with no publish date matches neither.

## Where it works

Access rules apply everywhere: you find only issues in projects you may see, as with `list`.

- **Command line:** `cvewatch search`. An unknown ID given to `cvewatch show` gets suggestions from the same search.
- **MCP:** the `search_findings` tool, for agents. Its input is `query`, with the optional `open_only`, `min_severity`, `project` and `env`. These mean the same as the flags. It returns the same JSON document as `list_findings`. See [agents.md](agents.md).
- **Terminal UI:** on the findings screen, press `/` and type. The list narrows as you type, and `esc` clears the filter. While the text is not a complete query yet, such as `severity:` without a value, the filter matches the plain words only. It checks them against the ID, title, technologies, aliases, projects, environments and owners.

## Limits

- The search uses local data only. It reads the stored state and makes no network calls. It does not query the feeds.
- Only issues with a finding in some project are searched. An issue with no finding, such as one kept as a bare record, is not found. `show` still finds it by ID.
- Commas split alternatives in field values: `env:dev,staging` finds dev or staging. In a plain word, a comma is part of the word.
- Plain words are substring matches. There is no fuzzy matching.
