# cvewatch

Exposure and fix tracking for software factories. It watches the feeds that matter to your stack, tracks open, fixed and ignored per project and environment, and keeps the evidence local.

It is a companion to scanners (Trivy, Grype, OSV-Scanner) and SBOM platforms (Dependency-Track), not a replacement: it does not scan images or hosts. Its job is the one they leave open: *which of our projects and environments are still exposed to which known issue, who owns it, and what happened so far.*

## First run

```bash
cvewatch init -repo /path/to/your/repo      # starter config; detects technologies, versions and lockfiles
cvewatch setup /path/to/your/repo            # or: guided, with the evidence for every guess
cvewatch tui                                 # full-screen overview, findings, projects and status (runs cvewatch-tui)
cvewatch doctor                              # checks config, lockfiles, state, channels (add -online for CPE names and feeds)
cvewatch update                              # fetch now, then list
```

One binary is enough: the technology catalog and the feeds are built in. `config/techs.yaml` and `sources/*.yaml` hold only your additions and changes; they are layered over the built-in ones. `-root DIR` points at the folder with `config/` and `sources/` (default: the current folder).

## How a cycle works

1. Load the configuration again from disk and build the **inventory**: what runs in every project environment, from declared techs, per-environment versions, lockfiles and SBOMs. If the inputs of the judgement changed since the last cycle, the stored advisories are judged again first (see [Changing the configuration](#changing-the-configuration)).
2. Fetch all sources (per-host rate limits, retries, `Retry-After`, 429 cooldowns; unchanged feeds answer `304`).
3. Judge each item once, when it is first seen (`relevance`): which technologies it is about, which environments run them, and whether the installed version falls in the affected range.
4. Fold it into the ledger (`ledger`): the same issue reported again joins the existing record.
5. Re-check findings whose inventory changed (an upgraded lockfile, a new declared version, a removed package).
6. Rate tracked issues that no source scored (CVSS), optionally add EPSS scores, write reports, save, then alert every channel and send the daily digest.

A failed source keeps its cursor and is retried next cycle. A finding counts as alerted per channel only after that channel accepted it.

Not every project is part of every cycle. Each project is due one period after its last refresh (see [Update schedule per project](#update-schedule-per-project)). A scheduled cycle fetches the feeds once, then judges, reconciles and alerts only the projects that are due; the findings of the others are left as they are until their turn. A manual `cvewatch update` or `cvewatch run` covers every project.

## Technologies and discovery

The built-in catalog lists open and closed source technologies: runtimes, frameworks, databases, servers, platforms, appliances and more. Search it with `cvewatch catalog WORDS`. A technology is judged only when a project declares it, so a big catalog adds no noise. Add your own in `config/techs.yaml`: an entry with the same name replaces the built-in one, and `disabled: true` removes it. A technology can bring its vendor's advisory feed (for example CSAF), which turns on when a project declares it.

`cvewatch discover DIR|FILE` shows what a repository uses and why. It reads lockfiles and their packages, `.tool-versions`, `go.mod`, `package.json`, Dockerfiles, compose files, Kubernetes manifests, Terraform and marker files. Each proposal has evidence and a confidence (high, medium, low). Low ones are asked about, never declared silently. It only reads files, never follows symlinks, and limits depth, file count and file size. Paths that `.gitignore` ignores are skipped too (see [Ignored paths](#ignored-paths)).

A single Dockerfile, Containerfile, compose file or Kubernetes manifest can be the source too (`cvewatch discover FILE`, `cvewatch setup FILE`, and the `discover_stack` MCP tool). Its base images (`FROM`, with `ARG` defaults filled in), compose services, Kubernetes images and packages installed in a Dockerfile are proposals marked as infrastructure, with their catalog category. A project proposed from such a file is named after the file's folder.

### Ignored paths

`discover` and `setup` skip the paths git would ignore: the `.gitignore` files from the repository root (the nearest folder above with a `.git`) down to each folder, and `.git/info/exclude`. The rules are git's: `!` negation, a trailing `/` for folders, anchored and unanchored patterns, `*`, `?`, `**` and character classes. The matcher is built in, so no git binary runs. A folder with no `.gitignore` is read as before. The notes of a scan say how many paths were left out.

`-all` reads the ignored paths too: `cvewatch discover DIR -all` and `cvewatch setup DIR -all`. A file given directly (`cvewatch discover FILE`) that is ignored is refused unless `-all` is given. Lockfiles follow the same rule, so a committed lockfile is proposed and one that the repository ignores is not. The TUI folder box does not list ignored entries.

### Technologies not in the catalog

A term the catalog does not know gets help instead of a silent miss:

- The catalog ranks what a term most likely means: an exact name or alias first, then names that start with it or contain it, then close spellings (a swapped or missing letter). Unrelated names are never offered. `rabbitMW` finds `rabbitmq`. The words of a longer term count one by one, so `ubuntu kernel` finds `linux-kernel` first, then `ubuntu`. `algolia` finds nothing, and the message says it is not in the catalog and offers to add it as your own keyword.
- The Linux kernel is `linux-kernel`, with the aliases `linux kernel`, `ubuntu kernel`, `debian kernel`, `linux-image` and `linux image`. A bare `linux` or `kernel` is not an alias, since it would match advisories about other kernels too. A project that names a technology the catalog clearly means something else gets a problem with a fix that renames it, labelled `use technology name "linux-kernel" instead of "ubuntu kernel"`.
- To keep it, add it as your own keyword: type `+algolia` in setup's technology step; in the TUI add-technologies step press `ctrl+o` for the word under the cursor (or the first one the catalog does not know); on the Technologies field of the project editor press `K`; or on the command line:

  ```bash
  cvewatch tech add algolia -yes                       # the name is the keyword
  cvewatch tech add grafana -cpe grafana:grafana -yes  # a CPE name adds NVD product matching and version checks
  cvewatch tech edit grafana -alias grafana -alias grafana-server -yes   # a flag that is given replaces that list
  cvewatch tech list
  cvewatch tech remove grafana -yes
  ```

- Keywords match as whole words. An advisory matches when its title or text names one of them (the default is the name). Without a CPE name the match is by text only, and a hint says so.
- Each change is previewed: without `-yes` the command shows the diff of `config/techs.yaml`. In setup and the TUI, your entries are written together with the project file, after the review.
- An entry with the same name as a shipped one replaces it; `disabled: true` removes the shipped one. In the TUI, Settings, Tech catalog lists your technologies: `a` adds one, `e` changes its keywords, category and CPE, and `x` removes it.
- Over MCP, `suggest_tech` returns the closest names for a term, `preview_tech_change` shows a change, and `edit_tech` writes it (with `-allow-write`).

### Hints

Hints are advice about a project that is not an error. They say what may not be covered or may make the monitor noisy, and give the fix when there is one:

- an unknown technology, with the closest catalog names or the keyword to add;
- nothing that can match yet: no known technology and no lockfile;
- a lockfile that is missing, unreadable, of the wrong type or outside the repository folder;
- environments: no `envs` (the old default is used), no prod environment, or the old `environments:` spelling;
- a technology without a version, so advisories naming it are reported as "version could not be checked";
- a broad technology when the catalog has more specific names (`cisco-ios` and `cisco-ios-xe`);
- your own keyword without a CPE name;
- a language, runtime or framework with no lockfile, so its packages are not checked;
- no start date (`since`).

Hints show in the setup review, in `cvewatch project NAME`, in the `hints` of `check_projects` and `preview_project_change`, and in the TUI: the Hints section of a project and of the review, and `H`, which works through them. Enter on a hint applies its fix through the usual preview. For an unknown technology it offers the keyword prompt or the closest names to replace it. The Projects screen counts the hints of each project.

## Terminal UI

`cvewatch tui` opens the full-screen interface. It has five screens, shown as tabs under the title: **1 Overview**, **2 Findings**, **3 Projects**, **4 Status** and **5 Settings**. Findings shows the number of open issues, and Settings shows `(!)` when a settings file has an error.

The header also shows what is going on. `refreshing...` means the data is being read. While a change is written, the header shows what runs, such as `saving...`, with `+1` when more run. Otherwise it shows the health and the time of the last read. Press `r` to reload now.

### Refresh and fetch

The screens re-read the state every `refresh` (`tui.refresh` in `config.yaml`, 30 seconds by default, at least 1s). Reading never waits for the daemon.

A re-read shows what is stored and fetches nothing, except that a change which needs older advisories fetches them (see [Changing the configuration](#changing-the-configuration)). The feeds are fetched when you press `F`, which covers every project.

Without a running daemon the TUI also updates by itself, on the same schedule as the daemon (see [Update schedule per project](#update-schedule-per-project)): when a read shows a project due, it starts a background update of the due projects. This is the `tui.auto` setting, true by default. It does nothing when a daemon is alive, which means a heartbeat that is not overdue, because the daemon does that work, and it stops when `update.auto` in `config.yaml` is false. After a failed or busy attempt it waits a minute before it tries again. `tui.fetch` (`0s` by default) is the older way: a number above zero makes the TUI fetch everything once at start and then every so often, whatever the schedule and the daemon say. The values are on the Settings screen, under Core, and a change applies at the next re-read.

A fetch runs in the background, one at a time, and the screens keep working. It needs write access to every project, like a daemon cycle. Its progress shows in the header as one small cell: `fetch 3/12` is three of twelve sources done, with a spinner. The matching, enriching, saving and alerting steps show their own word. When the run ends, a note says `fetched: 4 new, 2 findings`, and `, 1 source failed` when a source failed. An update on the schedule says `updated shop, blog: 4 new, 2 findings`, with the projects it covered. Click the cell at any time to see the sources that failed.

If another cvewatch holds the data, such as a daemon cycle, the fetch waits for the next period, or for `F`, and the note says so. That is not an error.

When a project, `techs.yaml` or the alert horizon changed (in the TUI, in your editor or by hand), the findings no longer match what they were judged against. The TUI notices on its next read and runs a quiet job: the header cell says `revalidating`, then `back-fill 2/9` while a source reaches back for older advisories, and a note says `revalidated shop: 4 new, 11 closed by since 2024-01-01, 2 reopened`. `V` does the same on request: it first shows what would change, and `y` or enter applies it. Until then the Projects list marks a project whose changes are not judged yet with a `*`, and its page says so. What the revalidation does is described in [Changing the configuration](#changing-the-configuration).

### Moving around

- **Levels.** Each screen has a root. Enter opens a level inside it: an issue, a project, a fix preview or a form. The breadcrumb line under the tabs shows the path, such as `Findings › CVE-2026-1234 › shop:prod`.
- **Back.** Left, Esc or Backspace go back one level. `q` does the same inside a level or a popup.
- **Screens.** On a root, Left and Right switch to the previous or next screen. Screens wrap around. Tab and Shift+Tab cycle through them, and 1 to 5 go to one. Tab and 1 to 5 also work inside an issue or a project.
- **Quit.** `q` quits only from a root. Ctrl+C quits from anywhere.
- **Help.** `?` shows the keys for where you are, and the rules that apply everywhere. In a text box `?` is a letter, so use F1 there.
- **Jump box.** `:` or Ctrl+G opens it from any screen or level, except forms, the fix preview and text boxes. Type part of an issue id (such as `CVE-2026-1234`) or a project name. Matches appear as you type, and names that start with your text come first. Up and Down pick a match, Tab fills in the text with it, and Enter goes there. If nothing matches but the text looks like an issue id, Enter tries it as one. That also finds an issue that is already closed. Esc cancels.
- **Messages.** A success note starts with `ok:` and goes away after 4 seconds. An error starts with `error:` and stays until your next action. Moving around (arrows, paging, switching screens) keeps the message.

### Going to another place

Some keys take you to another place. Esc (or Backspace) brings you back to where you came from, on the level you land on.

- Overview: Enter on an issue opens it. Enter on a policy violation (`v`) opens its issue.
- Status: Enter on an error that names a project goes to that project. Other errors show in full.
- Issue: `p` goes to the project of the selected environment.
- Projects: `i` shows that project's issues on Findings, filtered to it. Enter opens the project and sets the scope (see [Project scope](#project-scope)).

If you type a new filter after the jump, Esc clears the filter first. Changing screen ends the way back. This happens with Tab, a number key, or Left and Right on a root.

### Mouse

The mouse is optional. Every action works from the keys.

- The wheel scrolls three lines, or moves a list cursor three rows.
- A click selects a row. A second click on the selected row opens it on Findings, Projects, Overview and Status. In a form, a second click answers a choice, or ticks an option in a checklist.
- In an issue, a click selects an environment row.
- Click a screen tab to switch to it. Click a breadcrumb to go back to that level.

### Project scope

Enter on a project on the Projects screen sets the project scope. The Overview and the Findings then list only that project's issues, with only its environments, and the counts and severity bars follow them. The breadcrumb line shows the chip `scope: shop ×`. `0`, or a click on the chip, shows all projects again. The scope survives a re-read, and it is dropped when its project is deleted or disabled. Opening one of a project's security issues (`s`, then Enter) sets it too. An issue opened under a scope lists that project's rows first and starts on its prod-like environment (else its first row); the rows of the other projects follow under "other projects" and can be selected, and the prompts of assign, status and evidence then say "outside scope".

### Environments in lists

Lists name environments only where it matters. An issue that is open in every environment its project monitors shows the project's name alone. Otherwise the cell names the environments it is open in, prod first, such as `shop:prod,dev`, and `+2` counts the ones not named. The column is `PROJECTS (ONLY IN)`. On Overview, the `by environment` line reads `all 4 environments alike (18 open each)` when every environment has the same count, and draws one bar per count when they differ.

### Time filter

`t` on Overview and Findings cycles the filter on the publication date: any time, past hour, past 24 hours, past week, past month and past year. The chip `published: past week ×` on the breadcrumb line shows it; `0`, or a click on the chip, clears it. Counts and bars follow it, as they follow the project scope. A custom range is typed into the search, such as `published:2026-01-01..2026-03-01`, and the chip shows that too. The search syntax is in [search.md](search.md).

### Keys by screen

The footer at the bottom shows the keys for where you are. Keys in brackets also work, but the footer and the help leave them out.

Everywhere except in forms, the fix preview and text boxes: `:` jump, `r` reload, `F` fetch the feeds, `V` revalidate, `?` help, Tab and 1 to 5 switch screens.

**Overview**

Below the summary, the list holds every open issue. It is searched and sorted like the Findings list, and when a project scope is set, only that project's issues are listed (see [Project scope](#project-scope)).

| Key | What it does |
|---|---|
| Up, Down, PgUp, PgDn, Home, End | move in the list of open issues |
| Enter | open the selected issue |
| `/` | filter by words or fields, with the same syntax as Findings. Enter keeps the filter, Esc clears it |
| `s` | cycle the minimum severity |
| `v` | show the policy violations and the warnings, in place of the list. Enter on a violation opens its issue; Esc goes back to the list |
| `t` | cycle the time filter on the publication date (see [Time filter](#time-filter)) |
| `0` | clear the project scope when one is set, otherwise the time filter |

**Status**

| Key | What it does |
|---|---|
| Up, Down | select an error |
| PgUp, PgDn, Home, End | scroll the page |
| Enter | go to the project the error names, else show the error in full |

**Findings**

| Key | What it does |
|---|---|
| Up, Down, PgUp, PgDn, Home, End | move in the list (`k`, `j`, `g`, `G` too) |
| Enter | open the selected issue |
| `/` | filter by words or fields such as `severity:high`. The list narrows as you type. Enter keeps the filter, Esc clears it |
| `s` | cycle the minimum severity: all, low+, medium+, high+, critical+ |
| `t` | cycle the time filter on the publication date (see [Time filter](#time-filter)) |
| `0` | clear the project scope when one is set, otherwise the time filter |
| Space | mark or unmark the issue, then move down (see Triage) |
| Ctrl+A | mark every issue in the list, or clear the marks when all are marked |
| `f` `i` `n` `o` | with marks: set every marked issue fixed, ignored, not affected, or open again |
| Esc | clear the marks first; then go back to where a jump came from; then clear the filter |

**An issue** (Enter on Findings)

| Key | What it does |
|---|---|
| Up, Down | select an environment row |
| PgUp, PgDn, Home, End, Space | scroll the page |
| `f` `i` `n` `o` | set the selected environment fixed, ignored, not affected, or open again. Not affected asks for a reason |
| `F` `I` `N` `O` | the same for every environment of the project |
| `a`, `A` | owner, due date and ticket of the selected environment, or of the whole project with `A` |
| `]`, `[` | open the next or previous issue of the list (`J`, `K` too) |
| `p` | go to the project of the selected environment |
| `l`, `L` | select the next or previous link under References (the page scrolls to it) |
| Enter | open the selected link in the browser |
| `c` | copy the selected link to the clipboard |
| `v` | show the evidence pack: facts, per-environment status and the audit trail |
| `R` | show the full report, as `cvewatch show` prints it |
| `+` | add evidence (a note, a link, or both) to the selected environment |
| Left, Esc, Backspace, `q` | back to the list, or to where a jump came from. With a link selected, Esc unselects the link first |

**Projects** (the list)

| Key | What it does |
|---|---|
| Up, Down | select a project |
| Enter | open the project: its problems, each with its fix, and its security issues. It also sets the project scope (see [Project scope](#project-scope)) |
| `+` | add a project: from a folder, from a Dockerfile, compose or Kubernetes file, or an empty one (see [Adding a project](#adding-a-project-tui)) |
| `-` | remove the selected project: it shows what it affects, asks for its name, and the file moves to the backups |
| `c` | open the project's fields: environments, technologies, lockfiles, differences per environment, since, updates (see [Editing a project](#editing-a-project)) |
| `H` | work through the project's hints (see [Hints](#hints)) |
| `e` | edit the project step by step in the guided form |
| `a` | add a project in the guided form (`n` too) |
| `N` | new empty project: a name and its environments, no folder needed |
| `d` | add a project from a folder, or a Dockerfile, through the folder box (see below) |
| `x` | preview the fix of the selected problem (`f` too) |
| `E` | open the project file in your editor, then reload (`o` too) |
| `p`, `P` | next or previous problem of the selected project |
| `i` | show this project's issues on Findings |
| `R`, `D`, `X`, `Z` | rename, duplicate, delete, or disable a project (enable it when it is disabled). See [Creating, renaming, copying, disabling and deleting projects](#creating-renaming-copying-disabling-and-deleting-projects) |
| Esc, Backspace | back to where a jump came from |

**A project** (Enter on Projects)

| Key | What it does |
|---|---|
| Up, Down | select a problem. Its fix shows under it |
| Enter, Right, `x` | preview the fix of the selected problem |
| `[`, `]` | choose another fix, when the problem has several |
| `c` | open the project's fields and change them directly |
| `H` | work through the project's hints (see [Hints](#hints)) |
| `e` | edit the project step by step in the guided form |
| `E` | open the file in your editor at the problem's line (see below) |
| `s` | select among the project's security issues; Enter opens the one selected, and back returns here |
| `i` | show this project's issues on Findings |
| `+`, `-` | add a project, or remove this one (as on the list) |
| `a`, `d`, `N` | add a project in the guided form, from a folder or a Dockerfile, or a new empty project |
| `R`, `D`, `X`, `Z` | rename, duplicate, delete, or disable (enable when disabled) the project |
| Left, Esc, Backspace, `q` | back to the list of projects, or to where a jump came from |

**Settings** (screen 5)

The section list shows how many values each section of `config.yaml`, `techs.yaml` and `sources/*.yaml` sets, and the problems of the files with their line numbers. Enter opens a section, then a field. Changes are previewed as a change to the file and saved on a yes; comments in the files are kept. The daemon picks them up within about 15 seconds. It works even when a settings file is broken, and the other screens then show the load error as usual.

| Key | What it does |
|---|---|
| Up, Down, PgUp, PgDn, Home, End | move in the list; the mouse wheel and a click work too, a second click opens |
| Enter, Right | open a section, a list or an item; change a value (a number, text, a duration, a name of an environment variable; a choice opens a list) |
| Space | turn an on/off setting over |
| `a`, `x` | add an item to a list or map (a feed, a technology, a policy rule, an access rule), or remove the selected one |
| `e` on one of your technologies | change its keywords, category and CPE (Tech catalog section) |
| `u` | restore the default: the value is removed from the file |
| `/` | find a setting by label, path or value. On the section list it searches every section |
| `E` | open the file in your editor at the line of the selected problem, then read it again |
| Left, Esc, Backspace, `q` | back one level |

In the preview, Enter or `y` saves and Esc cancels. Secrets (feed URLs and headers) are never shown: a field says `(set)` or `(not set)`, the prompt does not show or prefill the current value, and the preview says `(set, changed)`. Only an actor that may see all projects can open the screen, and only one with write access can change it; the access rules cannot be changed so that the actor loses write access.

**Fix preview**

| Key | What it does |
|---|---|
| Enter, `y` | apply the fix to the project file, then reload |
| `[`, `]`, Left, Right | another fix, when the problem has several |
| Esc, Backspace, `q` | cancel. Nothing is saved. Left also cancels when there is only one fix |
| Up, Down, PgUp, PgDn, Home, End | scroll the preview |

**Project form** (add or edit)

The form asks one question at a time. What a key does depends on the question.

| Question | Keys |
|---|---|
| Text answer | type the answer. Enter goes on. Esc goes back one step. Ctrl+D scans a folder. Letters such as `q`, `h` and `d` are typed text here |
| Choice | Up, Down pick. Enter chooses. Esc, Left, Backspace or `q` go back. `d` or Ctrl+D scans a folder |
| Several options | Up, Down move. Space or `x` ticks. `a` ticks all, or clears all when all are ticked. Enter confirms |
| Yes or no | `y` or `n`. Esc goes back. `d` or Ctrl+D scans a folder |
| Review | Enter or `y` saves the project file. `n` does not save and goes back one step. `e` changes one step: pick it from a list, and the review comes back after it |
| List of steps (after `e`) | Up, Down pick. Enter goes to the step. Esc goes back to the review |

On the first step, Esc leaves the form. If you typed something, it asks first. Nothing is saved until you save from the review.

### Triage

- `]` and `[` move through the list while the issue page stays open. Use `]` to go down the list one issue at a time. If the open issue has just left the list (you closed it), the next one takes its place.
- Mark issues with Space, which moves the cursor on, or with Ctrl+A for every issue in the list. Marks stay only on issues the list still shows.
- Press `f`, `i`, `n` or `o` to change every marked issue at once, with one note for all of them. Fixed, ignored and not affected change the open environments of each issue. `o` reopens the closed ones. Not affected needs a reason, and an empty one is refused.
- Narrow the list with `/` (for example `severity:high` or `project:shop`) and `s`. The search syntax is in [search.md](search.md).

### Prompts

A prompt opens at the bottom of the screen for a note, for an owner, due date and ticket, or for a folder.

- Enter saves. On a prompt with more than one field, Enter goes to the next field first.
- Tab or Down go to the next field. Shift+Tab or Up go to the previous one.
- Esc cancels. Nothing is written.
- A due date is `YYYY-MM-DD`. An empty field keeps its value, and `-` clears it.
- If a write is refused, the reason shows in the prompt and what you typed stays. Fix it and press Enter again.
- While a write runs, the prompt says `working...`. Esc closes it, and the change still lands.

### Editing the project file

`E` (or `o`) runs your editor on the project file, then reloads when it closes. The file can be broken; it still opens.

Inside a project with a problem selected, the editor opens at the problem's line. The TUI knows these editors:

- `vim`, `nvim`, `vi`, `view`, `gvim`, `mvim`, `nano`, `micro`, `emacs`, `emacsclient`: opened with `+LINE`.
- `code`, `code-insiders`, `codium` (VS Code): opened with `-g FILE:LINE`.
- `subl`, `sublime_text` (Sublime Text): opened with `FILE:LINE`.

Any other editor opens the file at the top. The editor is the `tui.editor` setting, else `$VISUAL`, else `$EDITOR`; each may hold options, such as `code --wait`. With none of them set the TUI takes the first usual editor it finds (`sensible-editor`, `editor`, `nano`, `vim`, `vi` on Linux; `nano`, `vim`, `vi`, then TextEdit on macOS; `notepad` on Windows) and says which one it used. If there is none, it says to set `tui.editor` and shows the file path.

### Issue details

Enter on an issue in Findings opens its page. The page has these parts, in this order:

- **Header:** severity, the CVSS base score with its version, KEV, EPSS, age and "open in prod". A line below the title gives the CVSS vector and who scored it.
- **Description and priority:** the feed's text, and why the issue ranks where it does.
- **Environments:** one row per environment of the project, with its status, whether it applies, owner, due date, ticket and notes. Once the page is loaded, the installed versions found in an environment are shown under its row.
- **Fix evidence:** the fixes the feeds name (official ones are marked), the KEV action, and the reports. Five reports are listed, then the number of the rest.
- **Affected versions:** each affected range per ecosystem and package, with the first fixed version.
- **Why it matched:** the reasons per project and environment, and whether the issue is relevant under today's configuration.
- **References:** the links, numbered. Each link is listed once: advisories, fixes, articles, evidence and tickets. The report file name is shown after them.
- **Evidence:** the notes and links attached to each environment.
- **History:** what happened to the findings, oldest first, with the time in UTC and who did it. It comes from the audit log when the log's chain verifies, else from the ledger. The feeds' own events are not repeated here.

Keys on the page:

- `l` and `L` select the next or previous link. The page scrolls to it. Enter opens the selected link in the browser: `open` on macOS, `xdg-open` on Linux, `rundll32` on Windows.
- `c` copies the selected link with the first clipboard tool found: `pbcopy`, `clip`, `wl-copy`, `xclip`, `xsel` or `clip.exe`. Without one, the link is shown in the message.
- `v` shows the evidence pack and `R` shows the report. Esc goes back to the issue.
- `+` adds evidence to the selected environment: a note, a link, or both. A link must be a plain http or https address.
- `]` and `[` move to the next or previous issue of the list.

Only plain http and https addresses are listed as links. Long link titles are cut at 200 characters. The model keeps the CVSS base score with its version (2.0, 3.0, 3.1 or 4.0), its vector and who scored it (see CVSS scores below).

### Settings

The Settings screen (5) edits the configuration files: `config.yaml`, `techs.yaml` and the feeds in `sources/*.yaml`. The first level lists the sections: Core, HTTP, Notify, Policy, Sources, Tech catalog and Access. Each section shows how many values it sets, and the problems of the files with their file and line. Enter opens a section. Inside it, Enter opens a field or a list. Enter on a problem goes to the setting it names.

The field types are:

- **Number or duration:** a number, or a duration such as `30s`, `5m` or `2h`. The limits of the setting are checked.
- **On or off:** Space or Enter turns it over.
- **Choice:** the allowed values, with the current one marked.
- **Environment variable name:** the name of the variable, never its value. The daemon reads the value from its environment.
- **List or map:** `a` adds an item, Enter changes it, `x` removes it.
- **Records:** a feed, a policy rule, a technology or an access rule. Each is a list of its own. `a` asks for the fields it needs first; the rest are set row by row afterwards.

Every change is shown as a diff of the file. Enter or `y` saves it. Esc cancels, and nothing is written. A change that would add an error is refused, and the prompt keeps what you typed and shows the reason. Comments and layout in the files are kept. Each file is copied to `config-backups/` before it is written. The audit log records the paths that changed, never the values.

- **Secrets:** feed URLs and headers are never shown. A field says `(set)` or `(not set)`, the prompt does not show or prefill the current value, and the preview says `(set, changed)`.
- **Restore the default:** `u` removes the value from the file, so the default applies.
- **Broken files:** a file that is not valid YAML does not stop the screen. It shows its error, its values are not listed, and it can only be repaired in an editor. `E` opens the file at the line of the problem, then reads it again. The other screens show their load error as usual.
- **When it applies:** the daemon uses the new settings within about 15 seconds, and judges the stored findings against them (see [Changing the configuration](#changing-the-configuration)).
- **Who may edit:** the settings name every project and every actor. An actor that an access rule limits to some projects is refused the screen, with "Settings are not available to you". An actor with read access only sees the screen with a `read-only` note in its header and cannot save. A change to the access rules is refused when it would leave the person making it without write access to every project, so nobody can lock themselves out.

## Setting up and changing projects

Three front ends share one setup flow, so the questions and checks are the same:

- `cvewatch setup [DIR]`: guided prompt.
- `cvewatch tui`: full-screen interface. It runs `cvewatch-tui`, a separate program shipped next to `cvewatch`, so other commands start fast.
- MCP tools and the skills in `skills/`: the same steps for an agent.

The package `projectflow` is the one place that turns a typed folder or an existing project into a setup flow, and the answers into project-file edits. The TUI, the wizard and `cvewatch init` all use it.

Project edits keep the file's comments, are checked before saving, back up the old file in `data/project-backups/` and go to the audit log. For scripts, `cvewatch project NAME -set php=8.2 -lock composer:PATH` shows the diff and `-save` writes it.

`cvewatch init -repo DIR` writes the starter files and a project file for what it finds, through the same save path. An existing project file is kept unless you pass `-force`. With `-force`, the project file is edited in place: its comments stay and the old version goes to `data/project-backups/`. The starter files are rewritten. Lockfile paths are stored relative to the config root (`-root`), so with the default `-root .` they stay relative too.

`check_projects` (MCP, read-only) lists the problems in project files, each with the edits that would fix it. See [agents.md](agents.md).

### Adding a project (TUI)

On the Projects screen, `+` asks where the project comes from:

- **From a folder:** the folder box described below, which `d` opens too.
- **From a Dockerfile or compose file:** a path box that takes one file: a Dockerfile, Containerfile, compose file, Kubernetes manifest or Terraform file. Tab completes it. The project is proposed from that file alone. Its base images, services and packages are listed as infrastructure, and the review groups them under "Infrastructure". The project is named after the file's folder, as a folder project is.
- **Empty:** a name and its environments, as `N` asks. A new project starts with `local`.

In the lockfiles step and on the review, `+` adds a lockfile. Pick its file, with Tab completion; its type is read from the name (`package-lock.json`, `composer.lock`, `go.sum` and the other names the detector knows) and asked only when the name does not tell it. `-` leaves the selected lockfile out of the project, after a question. Nothing is written until you save from the review.

The folder box works like this:

- Type a path (`~` is your home folder), or pick a row with Up and Down. Enter uses the picked folder, or the typed text when no row is picked.
- Tab completes the name. With one match it adds the folder and a slash. With several it adds the part they share, if that is longer than what you typed.
- Shift+Tab goes up one folder. Tab on a picked row opens that folder.
- PgUp and PgDn page through the list. Esc cancels, and nothing is added.
- Each row shows the lockfiles and manifests found directly inside it, for example `composer.lock` or `go.mod`. A `project` tag marks a folder that has a lockfile or a manifest. Only the first 300 subfolders of a folder are looked into for marks, and at most 200 rows are listed.

Picking a folder reads folder and file names only. Nothing in the folder is run. Entries that `.gitignore` ignores are not listed (see [Ignored paths](#ignored-paths)).

### Fixing projects (TUI)

The Projects screen has a PROBLEMS column: `-` for none, or counts such as `2 err` and `1 warn`. A project file that cannot be read is shown as `BROKEN` with its error, and the rest of the TUI keeps working.

- Enter opens the project. Its problems are listed, each with its fix underneath. `p` and `P` select the next or previous problem.
- Inside a project, Enter or `x` shows the fix of the selected problem as a diff. Enter or `y` applies it. Esc cancels, and nothing is saved.
- A problem with several fixes lists them. `[` and `]` choose one.
- `E` opens the project file in your editor at the problem's line, then reloads. See [Editing the project file](#editing-the-project-file).

Problems are worked out when the screen loads or refreshes (`r`), not on every key. If loading fails, the screen offers `r` to try again and `q` to quit.

### Editing a project

On the Projects screen, `c` opens the fields of the selected project. Inside a project, `c` does the same. The fields are:

| Field | What it holds | Keys |
|---|---|---|
| Environments | the environments the project runs in, by name; the suggested names come first | `+` adds a name (the prompt says local is the default; names are free); `r` renames one, and the preview says how many findings move; `-` (or `x`) removes it with its differences, after a question; `f` writes the old default into a file that has no `envs`, or starts from local |
| Technologies | each generic technology and its version | Enter changes the version; `+` (or `a`) adds a technology from the catalog; `K` adds one of your own; `e` chooses where it runs, in every environment or only in the ones you pick; `-` (or `x`) removes it after a question |
| Differences per environment | only what differs in an environment, one row each: another version (`prod  php 8.2.30`), a technology that runs only there (`+varnish 7.4`), a technology it leaves out (`-xdebug`) or its image | `+` (or `a`) adds one: pick the environment, then the technology and version, the technology to leave out, or the image; Enter changes one; `-` (or `x`) removes one after a question; `m` rewrites an old `environments:` block as `when@<env>` blocks |
| Lockfiles | the type, path, environment and dev flag of each lockfile | Enter or `d` toggles dev; `+` (or `a`) adds a lockfile by picking its file with Tab completion: the type comes from the name, then the prompt asks for the environment (empty means every environment) and dev (yes or no); `-` (or `x`) removes it after a question |
| Since | the first day advisories count from | Enter opens a date prompt (`YYYY-MM-DD`); an empty value clears it |

A lockfile with dev set to yes counts its development-only packages in every environment. By default they count only in development-like environments (`local`, `dev`, `int`, `development` and `test`). The format of the differences is described in [Environments and differences](#environments-and-differences).

Every change is shown as a diff of the file, under the title "Edit project". Enter or `y` saves it. Esc cancels, and nothing is saved. A change that adds an error is refused, and the prompt keeps what you typed with the reason. An unknown technology only warns. Comments in the file are kept. The old file is copied to `data/project-backups/` before it is replaced, and the save goes to the audit log as `project`.

A disabled project, or one whose file does not load, cannot be edited in these fields. Press `E` to open its file instead.

### Creating, renaming, copying, disabling and deleting projects

These keys act on a whole project. Each one shows its consequences first, and nothing changes until you confirm.

A project is found by the `name:` its file declares, not by the file's name. A file `magento2-shop.yaml` that declares `name: shop` is the project `shop`, and rename, delete, disable, edit and the CLI commands work on it. Its problems carry a warning, `file magento2-shop.yaml declares shop`, so the mismatch is visible; making the file name and the `name:` match clears it. A new project's file is named after the project.

- **New (`N`):** a name, then the environments, separated by commas. An empty answer means `local`. No folder is needed. Creating a project needs write access to every project.
- **Rename (`R`):** a new name. The findings move to the new name, the access rules that name the project follow it, and the reports of its issues are rewritten. The old name stays in the audit log and in past evidence. The new name must be free, and the ledger must not already hold a finding under that name for the same issue and environment.
- **Duplicate (`D`):** a name, which starts as the name plus `-copy`. The copy has the same technologies and lockfiles, so it finds the same issues. It is in no access rule.
- **Delete (`X`):** the project's file moves to `data/project-backups/`. Nothing else is erased, but the access rules that name the project drop it. The findings stay in the ledger unchanged. They are no longer checked again, but open ones still show in lists and digests. You type the project's name to confirm. On the consequences, `c` also marks the project's open findings ignored, with the note "project deleted".
- **Disable (`Z`):** the file is renamed to `<name>.yaml.disabled`. A disabled project matches no new issues, and its findings are not checked again. The access rules that name it are removed, and enable does not restore them. A disabled project stays in the list, marked `disabled`, and `cvewatch project list` marks it too.
- **Enable (`Z` on a disabled project):** the file is renamed back. It must pass validation first. Its findings are checked again.

The consequences screen lists the findings by status, the access rules that change (with any actor left with no project), the files that move or change, and any warnings. Rename, delete and disable (when access rules change) are marked as destructive. Enter or `y` goes on, and Esc cancels. Delete also asks for the typed name first. Rename needs write access to both the old and the new name. Rename, delete and disable also need write access to every project when they rewrite the access rules.

Each step that succeeded is undone, newest first, when a later step fails. The message says whether everything was put back. The failure is written to the audit log as `project-failed`, and the error stays on the screen until you leave it. Nothing changes before the audit record is written.

## Command line: projects and settings

Every project edit is a flag list. Without `-save` the command only shows the diff. Several flags can be given together. They apply grouped by flag, in this order: technologies, lockfiles, environments, lockfile dev flags, since, the versions and exclusions per environment, the scope of technologies, `-migrate-envs`, then images. If one fails, nothing is written.

```bash
cvewatch project list                                   # the monitored projects; disabled ones are marked
cvewatch project shop -set php=8.3 -lock composer:shop/composer.lock:prod:dev   # diff only
cvewatch project shop -set php=8.3 -save                # write it; a backup goes to data/project-backups/
```

| Flag | What it does |
|---|---|
| `-set TECH[=VERSION]` | declare a technology, or change its version; an empty version means unknown |
| `-remove TECH` | stop declaring a technology |
| `-envs E,E` or `-envs all` | the environments the project runs in, by any names; `all` means the old default dev, int, staging, prod |
| `-env-add ENV`, `-env-remove ENV`, `-env-rename OLD=NEW` | add, remove or rename an environment. A rename moves its findings and follows into its lockfiles and scoped technologies |
| `-env-set ENV:TECH=VERSION` | the version of a technology in one environment (its `when@ENV` block), such as `prod:php=8.3` |
| `-env-unset ENV:TECH` | drop that version, so the generic one applies again |
| `-env-exclude ENV:TECH`, `-env-include ENV:TECH` | a generic technology does not run in one environment, or runs there again |
| `-tech-envs TECH=ENV,ENV` | limit a generic technology to some environments; `TECH=` lifts the limit |
| `-migrate-envs` | rewrite the old `environments:` block as `when@ENV` blocks; nothing else changes |
| `-image ENV=TAG` | the image of one environment; `ENV=` clears it |
| `-lock TYPE:PATH[:ENV][:dev]` | add a lockfile. `ENV` limits it to one environment; `dev` counts its development-only packages in every environment |
| `-unlock TYPE:PATH[:ENV]` | remove a lockfile entry |
| `-lock-dev TYPE:PATH[:ENV]` | change an existing entry to count its development-only packages in every environment |
| `-lock-nodev TYPE:PATH[:ENV]` | change an existing entry to stop counting them outside development-like environments |
| `-since DATE` | advisories count from this day (`YYYY-MM-DD`); `-since ""` clears it |
| `-update-every SPAN` | how often the project is refreshed, such as `30m`, `1h` or `2d` (at least 5m); `default` removes it (see [Update schedule per project](#update-schedule-per-project)) |
| `-update-auto BOOL` | `false` leaves the project out of scheduled runs, `true` puts it back |
| `-save` | write the change |

Only a trailing `dev` or environment name is read as one, so a path with colons, such as `C:\repo\composer.lock`, stays whole. `-lock-dev` and `-lock-nodev` change entries that exist; they do not add one.

Lifecycle changes show their consequences and do nothing until `-yes` is added:

```bash
cvewatch project rename shop shop-web          # -yes applies it
cvewatch project duplicate shop shop-copy
cvewatch project disable shop
cvewatch project enable shop
cvewatch project delete shop -close-findings   # -close-findings marks its open findings ignored, note "project deleted"
```

Add `-json` to print the preview as JSON. Project edits use `-save`; lifecycle changes use `-yes`.

The settings commands work on the configuration files without loading them, so they also work when `config.yaml` is broken. Changes apply from the next daemon cycle.

```bash
cvewatch settings list [-json] [SECTION]        # values set in config.yaml, techs.yaml and sources/*.yaml, by section
cvewatch settings get [-json] PATH              # one value, or the default when it is not set
cvewatch settings set PATH VALUE [-yes]         # change a value
cvewatch settings unset PATH [-yes]             # remove a value, so the default applies
cvewatch settings add PATH VALUE [-yes]         # append to a list, such as policy.rules
cvewatch settings diff set|unset|add PATH [VALUE]   # show what an edit would change
cvewatch settings schema [-json] [SECTION]      # every setting: path, type, allowed values, default and help
```

- Without `-yes` the command only shows the diff. `-yes` writes the change and keeps the comments in the file.
- A value that starts with `{` or `[` is read as JSON, for lists and records.
- `-doc ID` picks the file (`config`, `techs` or `sources/NAME`) when the path does not say which one.
- A dotted name in a path goes in brackets, such as `http.host_rates[services.nvd.nist.gov]`. A list item is picked with `[name=php]` or by position.
- Secret values show as `(set)`.
- A section name is case-insensitive. Quote a name with a space, such as `"Tech catalog"`.

## Environments and differences

Every project has environments, and their names are free: lowercase letters, digits, `-` and `_`, starting with a letter, up to 32 characters. `local`, `dev`, `int`, `staging` and `prod` are suggested and sorted first, but any other name works in project files, lockfiles, search (`env:qa-2`), the `-env` flags and the TUI. A name counts as production for the "open in prod" ordering when it is `prod` or `production`, or starts or ends with one of them after a `-` or `_`: `prod-eu`, `prod_us`, `production-apac` and `eu-prod` all count, while `preprod`, `pre-prod` and `non-prod` do not. `local`, `dev`, `int`, `development` and `test` count as development-like, where development-only packages count by default.

- A new project starts with `local`. Add `prod` and any others you deploy to. Setup offers the suggested names as a list, then `other...` for your own.
- A project file without an `envs` key keeps its old meaning, `dev`, `int`, `staging` and `prod`, so its findings do not change. The review says so with a hint, `envs not set: using the old default dev, int, staging, prod`, and offers to write the list.
- Adding, removing and renaming are edits: `cvewatch project shop -env-add qa -save`, `-env-remove qa -save`, `-env-rename staging=stage -save`. Removing an environment drops its `when@` block; a lockfile that names it stays in the file and is reported. The last environment cannot be removed. Renaming moves the findings of the old name, and the preview says how many. The TUI field editor does the same with `+`, `-` and `r`.

### Generic configuration and differences

The top level of a project file applies to every environment. A `when@<env>:` block holds only what differs in that environment, as Symfony's `when@prod:` blocks hold only the differences from the generic configuration:

```yaml
name: shop
envs: [local, dev, prod]
techs:                                  # generic: every environment runs these
  - {name: php, version: "8.3"}
  - {name: redis, version: "7.2"}
  - {name: phpmyadmin, version: "5.2", envs: [local, dev]}   # present only in these environments
lockfiles:
  - {type: composer, path: /repos/shop/composer.lock}
when@prod:                              # only what differs in prod
  techs: {php: "8.2.30", varnish: "7.4"}   # another version; varnish runs only in prod
  exclude: [redis]                         # a generic technology that does not run here
  image: "registry.example/shop@sha256:ab12..."   # recorded, not scanned
```

- `techs` in a block sets the version of a generic technology in that environment, or adds a technology that runs only there.
- `exclude` lists generic technologies that do not run in that environment. When a block both excludes and versions one technology, the exclusion wins and validation warns.
- `image` is recorded for the environment only; no registry is queried.
- A technology's `envs` limits it to the environments listed. Without `envs` it runs everywhere. A lockfile keeps its own `env`.
- The order is: the generic list, limited by each technology's `envs`; then the block's `techs` laid over it; then `exclude` removes what it names.
- A block for an environment the project does not have is an error, with fixes that add the environment to `envs` or drop its differences. Under the old spelling it is a warning.

The old `environments:` key still loads with the same meaning, and a hint says it is the old spelling. `migrate_envs` rewrites it as `when@` blocks in one previewed step and changes nothing else: `cvewatch project shop -migrate-envs -save`, `m` on the Differences list in the TUI, or the MCP kind `migrate_envs`. Any edit to the differences converts the whole old block too. New files are written with `when@` blocks.

| Edit kind | CLI flag | What it does |
|---|---|---|
| `set_env_tech` | `-env-set ENV:TECH=VERSION` | the version in one environment, or a technology that runs only there |
| `remove_env_tech` | `-env-unset ENV:TECH` | drops that version; the generic one applies again |
| `exclude_env_tech`, `include_env_tech` | `-env-exclude`, `-env-include` | a generic technology does not run in an environment, or runs there again |
| `set_tech_envs` | `-tech-envs TECH=ENV,ENV` | limits a generic technology to some environments |
| `set_image` | `-image ENV=TAG` | the image of one environment |
| `migrate_envs` | `-migrate-envs` | rewrites the old `environments:` block |

Setup asks once, after the environments, whether an environment differs from the rest (default no). It is asked only with more than one environment. Yes asks per environment for the differences only: another version, an extra technology, an excluded one or an image. No removes the differences the project has.

## Start date per project

A project file can set `since`, the first day its items count:

```yaml
name: middleware
since: 2026-01-01              # vulnerabilities published before this day are not checked for this project
techs: [{name: php, version: "8.2"}]
```

- A vulnerability published before `since` creates no findings for that project. The day itself counts, from 00:00 UTC. Other projects are not affected.
- Items with no publish date are still checked.
- A later article about an old CVE uses the earliest publish date already known for that CVE. So a new article does not bring an old CVE into a project that starts later.
- Findings that already exist for older advisories are closed by the next judgement of the configuration (see [Changing the configuration](#changing-the-configuration)): as not affected, with the note `published before this project's since date (2026-01-01); closed automatically`. Moving the date earlier, or removing it, reopens the ones cvewatch closed. A status you set yourself is never changed. To decide one yourself, use `cvewatch ignore ID -project middleware -env prod -note "..."` or `cvewatch not-affected`.
- `cvewatch why ID` shows each project that skipped the item for this reason:

  ```text
    not matched: middleware: published 2025-12-31, before the project's start date 2026-01-01
  ```

- `cvewatch check` warns when `since` is in the future. Until that day, the project gets only items that have no publish date.
- `cvewatch revalidate` applies the same rule to what is stored.
- An item that every project skips is kept as a record with its title, IDs, a short summary and up to 20 product names, but no findings and no report. That lets a project or technology added later pick it up without a new download.
- A value that is not a `YYYY-MM-DD` date stops the configuration from loading.

## Update schedule per project

A project file can say how it is kept up to date:

```yaml
name: shop
update:
  every: 1h                    # how often this project is refreshed; at least 5m (default: interval in config.yaml)
  auto: true                   # false leaves the project out of scheduled runs
```

- Without an `update:` block a project is refreshed every `interval` of `config.yaml`, and the block is not needed. The block is read in both spellings of the file (`when@<env>` and `environments:`) and does not touch the generic and per-environment layout.
- A project is due one `every` after its last refresh, and at once when it never was. The last refresh is kept in the state and shown in `cvewatch status` and on the TUI Status screen, together with the next due time. The TUI Projects screen shows each project as `every 1h · next 14:05`, `every 1h · due now`, `paused` (`auto: false`) or `manual` (scheduled updates are off).
- The daemon sleeps until the first project is due, but at most `interval`, so changes to the configuration are looked at. It never sleeps less than a minute, and after a failed cycle it waits at least 5 minutes.
- A scheduled cycle fetches the feeds once and judges, writes reports and alerts only for the projects that are due. Advisories fetched earlier are judged for a project when it becomes due, so it misses nothing, and its alerts go out then.
- `cvewatch update`, `cvewatch run` and `F` in the TUI refresh every project, including the ones with `auto: false`, and count as an update for each. A back-fill or revalidation after a configuration change looks at every project and is not an update.
- `update: {auto: true}` in `config.yaml` is the main switch, true by default. False turns scheduled refreshes off for everything, in the daemon and the TUI; only `cvewatch update` and `F` refresh then.
- Edit the block with `cvewatch project NAME -update-every 2h -update-auto false`, with the Updates field of the TUI field editor (`c` on a project), or with `set_update` in the MCP `edit_project` tool. `-update-every default` removes the period, and `auto: true` is not written because it is the default.
- A period under 5 minutes stops the configuration from loading and is an error in `cvewatch check` and `cvewatch doctor`. A period over 30 days is a warning, and `auto: false` is a hint: scheduled runs skip the project. A missing block is not a hint.

## Alert horizon

`horizon` in `config.yaml` limits which vulnerabilities are judged, alerted and put in digests, by their publication date, like Google's time filter:

```yaml
horizon:
  window: week                 # unlimited (the default) | hour | day | week | month | year | custom
# window: custom
# from: 2026-01-01             # custom only: YYYY-MM-DD or RFC3339; empty means no start
# to: 2026-03-01               # custom only: YYYY-MM-DD (the whole day counts) or RFC3339; empty means no end
```

- Rolling windows count back from each cycle's time: `hour` is one hour, `day` 24 hours, `week` 7 days, `month` 30 days and `year` 365 days. `from` and `to` are checked only while the window is `custom`; they are kept when another window is chosen.
- A vulnerability published outside the window is not judged. It creates no new finding, is not alerted and is not in a digest. Findings that already exist stay and stay visible, and can still be fixed, ignored or assigned.
- An item without a publication date is always inside.
- It works with `since`: an item has to pass both, so the later start wins.
- A source's first run reaches back only as far as `lookback` (7 days by default). A window that reaches further back gives a warning in `cvewatch check`: the older items are not seen until you raise `lookback`. Keep `lookback` at least as long as the window.
- A wider window, or a `since` date that moves earlier, makes the sources reach back for the older advisories (see [Back-fill](#back-fill)).
- The Settings screen shows the windows with Google's names (Any time, Past hour, Past 24 hours, Past week, Past month, Past year, Custom range). The change is judged the next time the configuration is read (see [Changing the configuration](#changing-the-configuration)). On the command line: `cvewatch settings set horizon.window week -yes`.
- Overview and Status show `alert horizon: past week (only vulnerabilities published then are judged and alerted)` when the window is not unlimited.
- Lists and search are not limited by it. To narrow what you look at, use the time filter (`t`) or `published:` (see [search.md](search.md)).

## Changing the configuration

The judgement depends on the projects (their environments, technologies with their versions per environment, lockfile packages and `since` date), on the `techs.yaml` entries those projects use, and on the alert horizon. cvewatch keeps a fingerprint of these inputs, per project and for the horizon, with the time the findings were judged against them. A comment, the order of keys, or a setting that does not feed the judgement (such as `http`) changes nothing.

When the fingerprint differs from the recorded one, the stored advisories are judged again, offline, in this order:

1. Every stored advisory is judged against the current configuration, including the ones that matched nothing before. A match creates its finding. Nothing that is stored is removed. An advisory that matched nothing kept only a short summary and up to 20 product names, so it is judged on those; its fix details come with the next sighting from a source.
2. Open findings of an environment the project no longer declares are set to `ignored`, with the note `environment removed from project`, the actor `cvewatch` and a mark that cvewatch set it. Their history stays. When the environment is declared again, those findings reopen. A project without `envs` declares the four default environments, so nothing of it is closed. A status a person set is never touched.
3. Open findings whose advisory was published before their project's `since` date are closed as not affected, with a note saying why and a mark that cvewatch set it. When the date moves earlier or is removed, the findings it closed reopen. A status a person set is never touched.
4. Open findings are checked against the installed versions again, as after a lockfile upgrade. If a technology was removed from a project, or a lockfile that is read no longer lists a package, its open findings stay open but stop applying: they are hidden from the lists (`-all` shows them), are not alerted, their reasons say `no longer installed`, and their history records the removal. A lockfile or SBOM that is missing or cannot be read proves nothing: the findings that came from it are left as they were until it can be read again, and the project check and the cycle log report the problem. A finding that stopped applying this way is judged again against the advisory when the package is installed again.
5. The sources are asked to reach back if the change starts earlier than what they have covered (see [Back-fill](#back-fill)).
6. The new fingerprint is recorded, and the run leaves one audit entry with the counts.

Every finding this creates, and every status change cvewatch makes by itself (steps 2 and 3), also leaves its own audit entry: `detected` with the project and environment for a new finding, `status` with the actor `cvewatch` for a close or a reopen, and `inventory` when step 4 changes a finding. The environment and inventory checks also run at the end of every cycle, so data left by an earlier version is repaired.

It runs in these places:

- At the start of every cycle, so `cvewatch update` and the daemon's cycles do it when the fingerprint differs.
- Between cycles the daemon looks at `config.yaml`, `techs.yaml`, the project files and the source files every 15 seconds. It reads their sizes and times, not their content. When one changes, it waits 2 seconds for a save made in several steps, then revalidates and back-fills at once instead of waiting for the next `interval`.
- On the command line, `cvewatch revalidate` lists what would change and writes nothing. `-apply` makes the changes. `-fetch` also fetches the older advisories the change needs, and implies `-apply`. `-json` prints the counts and the changes. `rescan` is the old name and still works.
- In the TUI, when a read finds the findings out of date, the same work runs as a quiet job, and `V` shows the preview first (see [Refresh and fetch](#refresh-and-fetch)).

A ledger written before this version has no record of its judgement yet, so every project counts as changed. The first cycle judges the stored advisories once, which can add findings for advisories stored earlier, and asks the sources to reach back to the earliest start of any project (its `since` date or the horizon, whichever is later). The TUI leaves that to the cycle, or to `V`.

### Back-fill

A project's start is the later of its `since` date and the start of the alert horizon. When a change moves that start earlier than what the sources have covered, the sources reach back on their next fetch. Examples: a `since` date set or moved earlier, a wider horizon, or a technology added to a project that has a start. A project with neither asks for nothing older than what the sources serve. The sources do this:

- **NVD** is asked in windows of 119 days, the most NVD accepts per query, and each window is followed page by page. A span of 300 days takes three windows. Each request waits for the host rate in `http.host_rates` (0.1 a second for NVD by default), so a long back-fill takes a while. The TUI header shows its progress as `back-fill 2/3`; the command line and the daemon log each part.
- **GitHub advisories** are followed page by page through their `Link` headers.
- **CISA KEV** serves its full list every time; the entries added since the date are kept.
- **CSAF** advisories follow the date as far as their index lists them.
- **Vendor records (`cve-records`), RSS and Hacker News** serve only recent items. They cannot go back, and the cycle notes say `cannot go back for ...: they only serve recent items`.

A back-fill that fails, or is cancelled, stays owed and is tried again at the next fetch. Advisories it finds that are already tracked join their records, so nothing is duplicated. A back-fill can add many findings at once. Each alert channel gets at most 50 advisories per cycle, and the rest go out in later cycles.

## Is it working?

`cvewatch status` shows the daemon (running, overdue, or only manual runs), each feed (last success, failures in a row), each channel, the last update and next due time of each project, and the last cycles. The overall level is `unknown` until a cycle has read at least one feed (a new monitor has shown nothing yet, so it is not `ok`), and `warn` when no feed is enabled. It exits non-zero only when something fails, so `unknown` and `warn` exit 0. `cvewatch dashboard` writes a static HTML page with the same plus open findings. Set `dashboard: {enabled: true}` in `config.yaml` and the daemon refreshes it every cycle. The page has no scripts and makes no external requests.

## Vendor records (CVE Program)

Vendors that issue their own CVE ids (Adobe, Cisco, Microsoft, Oracle and hundreds more) write the record themselves. The `cve-records` source reads these records from the official CVE Program repository (`cvelistV5`), usually before NVD has added its analysis. Vendor knowledge-base pages and bulletins are web pages without a feed, so this is the reliable way to get the same data.

How it works, in short:
- The repository's change log is read from the newest end, in small steps, until the last change already handled.
- Each newly published record is fetched, oldest first, at most 500 per cycle. The place reached is stored, so a failed or interrupted cycle repeats instead of losing records. A record that is gone (404) is skipped; any other error repeats the cycle.
- The title names the affected products, so technology matching works on it. Versions are checked only when the record has CPE names and plain version numbers; free text such as `2.4.9, 2.4.8-p5` stays `unchecked` for a person to confirm.
- The first run takes only the newest 100 records. Older ones come from NVD and the lookback. Changes older than about a week (a week-long outage) are not recovered from this source.
- Requests go to `raw.githubusercontent.com` at up to 5 a second (`host_rates`). Switch it off with `sources: [{id: cve-records, disabled: true}]` in a file in `sources/`. An entry for a feed that already exists changes only the fields it gives (here `disabled`), so it needs no type or url.

## Inventory

| Source | `type:` | Notes |
|---|---|---|
| Declared techs | `techs:` | `php: "8.2.30"`; per environment in a `when@<env>` block (see [Environments and differences](#environments-and-differences)) |
| composer.lock | `composer` | `packages-dev` counts as development |
| package-lock.json | `npm` | v1, v2 and v3; `"dev": true` counts as development |
| go.mod | `go` | `replace` applied; indirect requirements included |
| requirements.txt | `pip` | only exactly pinned lines; the rest is reported as skipped |
| poetry.lock, Pipfile.lock | `poetry`, `pipfile` | |
| gradle.lockfile, pom.xml | `gradle`, `maven` | pom properties resolved; parent poms are not read |
| CycloneDX / SPDX JSON | `cyclonedx`, `spdx` | packages by purl: npm, composer, go, pypi, maven |

Lockfiles can be limited to one environment (`env: prod`, so a prod SBOM differs from dev) and read every cycle. A lockfile whose `env` is not in the project's `envs` is never read; the project editor and `check_projects` warn about it. Development-only packages count in development-like environments (`local`, `dev`, `int`, `development` and `test`) unless the lockfile sets `dev: true`. Per environment you can also record the versions that differ and an image reference, in a `when@<env>` block (`image:` is recorded only; no registry is queried).

```yaml
name: shop
envs: [dev, prod]
techs: [{name: php, version: "8.3"}]
lockfiles:
  - {type: composer, path: /repos/shop/composer.lock}
  - {type: cyclonedx, path: /releases/shop-prod.cdx.json, env: prod}
when@prod:
  techs: {php: "8.2.30"}
  image: "registry.example/shop@sha256:..."
```

`cvewatch inventory` shows what the tool believes runs where, and what could not be read. Package names and versions are compared per ecosystem: `pip` equals `PyPI`, PyPI names are normalized (PEP 503), Maven uses `group:artifact`, and each ecosystem orders versions by its own rules (PEP 440, Maven, semver for Go, npm and Composer).

## Matching, versions and noise

An item matches an environment when it is about a technology it runs, or names a package it has installed.

- **By structured data, which wins when present.** NVD names affected products as CPE names. A technology with `cpe: [php:php]` then matches only when the advisory names that product, so "a Moodle plugin written in PHP" no longer matches PHP. GitHub advisories list packages with ecosystem and ranges; those match installed packages exactly and the word "PHP" in them is ignored.
- **By text, when there is no structured data.** An alias as a whole word in the title or summary (`excludes` veto it; `match_title_only` limits a source to the title; `match_structured` on the NVD source makes technologies with CPE names wait for NVD's product data).
- **Versions.** When the feed gives affected ranges, the installed version is compared: `affected`, `not affected`, or `unchecked` when no range or version is available, or a declared series such as `8.2` cannot be decided against a patch-level bound. Findings known to be `not affected` are kept but hidden and never alerted (`-all` shows them). News and Hacker News carry no versions, so those findings stay `unchecked`.
- **Kernel and distribution versions.** `6.12.85+`, `6.8.0-45-generic`, `6.12.85-1ubuntu1` and `6.12.85+deb12u1` order by their numbers (`6.12.85`, `6.8.0`). The build suffix is ignored for ordering and does not make a pre-release, so `6.12.86-generic` is not before a fix at `6.12.86`, and a range below `6.12.86` covers `6.12.85+`.
- **Late data.** If ranges arrive later (a CVE first seen in the news, then analysed by NVD), existing findings are re-checked. If your inventory changes, open findings are re-checked too, and the finding's history says what changed.
- **Check the CPE names** in `techs.yaml`. The repository's CI compares them with an independent list of NVD product names, and `cvewatch doctor -online` asks NVD. A wrong name hides real advisories.

`techs.yaml` can change at any time. Saving a change judges the stored advisories again (see [Changing the configuration](#changing-the-configuration)): a new keyword or CPE name creates the findings it now matches, and nothing is removed. `cvewatch why ID` shows the recorded reasons next to what today's config says.

## Same issue, one record

- Items sharing an advisory id belong to the same record. An advisory naming one CVE and one GHSA id unifies two records into one.
- An article naming several CVEs (a roundup) never merges them; it is linked to each.
- A relevant report without a shared id joins a tracked, relevant record when their titles share at least 60% of their distinctive words and are dated within 14 days. Irrelevant items never merge.

Each issue keeps its age since publication, the articles in chronological order, fix evidence (patched version, patch, vendor advisory, mitigation, CISA required action; `official` means a vendor or authority said it), the CISA KEV listing with its due date, and optionally the EPSS score.

## Tracking per environment

Status lives per vulnerability, project and environment: `open`, `fixed`, `ignored`, or `not_affected` (a human VEX-style statement that needs a reason). Every change records who, when and why in the finding's history and in the audit log.

```bash
cvewatch assign CVE-2026-1234 -project shop -env prod -owner alice -due 2026-11-30 -ticket https://tickets.example/SEC-12
cvewatch evidence add CVE-2026-1234 -project shop -env prod -note "patched image deployed" -url https://ci.example/run/77
cvewatch fix CVE-2026-1234 -project shop -env dev -note "php 8.2.30"
cvewatch not-affected CVE-2026-1234 -project shop -env dev -note "feature disabled, no network exposure"
cvewatch evidence CVE-2026-1234          # timeline: detection, alerts, status, owners, evidence, per-environment matrix
```

`cvewatch show ID` opens one issue. `cvewatch search` finds issues by words, IDs and fields such as `project:shop` or `published:week`. See [search.md](search.md).

## Priority and policy

The default order is: known exploited (CISA KEV) first, then severity, then open in prod, then EPSS, then age. The list, alerts, digest and exports all use it; each issue carries the reasons for its position. No proprietary score is computed.

Policy rules in `config.yaml` define deadlines; `cvewatch policy` lists the findings that break them (and exits non-zero, so CI or cron can notice):

```yaml
policy:
  rules:
    - {name: kev-prod, env: prod, kev: true, owner_within: 24h, fix_within: 168h}
```

A finding's own due date is always checked.

## Notifications

Channels switch on when their secret is in the environment, so one config file is safe to share: Slack (`SLACK_WEBHOOK_URL`), a signed JSON webhook (`notify.webhook`, HMAC-SHA256 in `X-Cvewatch-Signature`; works for Teams, Jira or GitLab bridges) and email (`notify.email`, SMTP with STARTTLS). Delivery is tracked per channel, so one failing channel never repeats alerts on the others. A daily digest of what is still open (`notify.digest`, e.g. prod only) goes out in the first cycle after its time; `cvewatch digest -send` sends it now.

## Exports and the JSON contract

`cvewatch export -format json|csv|md|sarif` lists open issues with the status of every environment. JSON from `export`, `list -json` and MCP is one versioned document (`schema_version`, `generated_at`, `count`, `issues`); the schema is in [schema/export-v1.schema.json](schema/export-v1.schema.json). Feed text sits under `untrusted`. CSV cells that could be read as spreadsheet formulas are neutralized.

## Layout

| Path | Purpose |
|---|---|
| `config/config.yaml` | interval, HTTP limits, Slack, notify, policy, enrich, storage, access, horizon, tui (refresh, fetch and editor) |
| `config/techs.yaml` | your additions to the built-in technology catalog, including your own keywords (`cvewatch tech`) |
| `config/projects/*.yaml` | one file per project |
| `sources/*.yaml` | your additions to the built-in feeds (an entry with the id of an existing feed changes only the fields it gives, such as `disabled: true` to switch it off; a new id needs a `type` and a `url`) |
| `data/` | state (`state.json`, or `state.db` with the SQLite backend), `audit.log`, `project-backups/` |
| `alerts/` | generated markdown reports and calendar pages |

## Storage

State is one JSON file by default (diffable; one process at a time, enforced by a lock). Set `storage: {backend: sqlite}` for a SQLite file: several processes can use it, and a stale write is refused instead of overwriting newer data. Both sit behind the same `store.Storage` interface.

## CVSS scores

Every source type is read for all the CVSS versions it carries: NVD (`cvssMetricV2`, V30, V31, V40), CVE records (`cvssV2_0` to `cvssV4_0`, in the CNA container and in ADP containers), GitHub advisories (`cvss`, `cvss_severities.cvss_v3` and `cvss_v4`) and CSAF advisories (`cvss_v2`, `cvss_v3`, `cvss_v4`). A score quoted in an article ("CVSS 9.8", "CVSS v4.0 base score 9.3") is read too, but only when the article names at most one CVE.

An issue keeps one score, chosen like this:

1. The party that issued or analysed the record comes first: NVD's own (Primary) metric, the CNA's, GitHub's, the vendor's CSAF. Secondary metrics (a CNA's score inside an NVD record, ADP containers) come next, a score quoted in an article last. A newer version from a lower group never replaces a score from a higher group.
2. Inside a group the newer version wins: 4.0, 3.1, 3.0, 2.0.
3. On a tie the score already kept stays, so it does not change between sightings.

Severity bands follow the version: 2.0 has no critical band (0-3.9 low, 4-6.9 medium, 7-10 high); 3.x and 4.0 use 0.1-3.9 low, 4-6.9 medium, 7-8.9 high, 9-10 critical. NVD's own severity word is used as given; otherwise the band of the score decides, and CSAF always uses the band of its score.

The JSON export and `show` carry `cvss`, `cvss_version`, `cvss_vector` and `cvss_source` (`nvd`, `nvd-secondary`, `cna`, `adp`, `ghsa`, `csaf` or `text`). The last three are absent for scores recorded before versions were kept.

## Enrichment and privacy

`enrich: {cvss: true}` (the default) rates tracked CVEs that no source scored, which is every issue that arrived only as a news item. Each cycle it asks NVD's public CVE API for up to 5 of them, by CVE id, at the pace of `http.host_rates` for `services.nvd.nist.gov`. A CVE NVD has not analysed yet is asked again after a day. A score quoted in an article counts as unrated, so NVD's replaces it. A failed lookup is a warning in the log and is tried again next cycle. Only the CVE id is sent, and no key is needed.

`enrich: {epss: true}` asks FIRST's public EPSS service for the CVE ids you track. It is off by default because the list of CVEs you care about reveals your stack. Nothing else leaves the machine except the configured feeds and channels.

## Several people

By default everyone who can run the tool may do everything. To limit that, add `access` to `config.yaml`: per actor (`CVEWATCH_ACTOR`, else the OS user), the projects visible and whether changes are allowed. Reads are filtered, writes need write access to the project, and `update` needs write access to all projects. This is authorization on top of a local identity, not authentication.

## Platforms

Linux, macOS and Windows are built and tested in CI. Platform differences (file locking, owner-only files, atomic replace, stop signals) are isolated in `src/host`. On Windows owner-only modes are not enforced by the OS; keep `data/` and `alerts/` in the user profile or restrict them with ACLs.

## Limits

- Fixes are what feeds say; no package or image registry is queried.
- Free-text feeds give no versions, so those findings stay `unchecked`.
- Images and SBOMs are inventory you provide; cvewatch does not scan them.
- Lockfile support is listed above; yarn.lock, pnpm-lock and Pipfile without a lock are not read.
- Authorization relies on the local identity; do not expose the tool to people you cannot identify otherwise.
- Security and privacy: see [security.md](security.md) and [compliance.md](compliance.md). Architecture: [architecture.md](architecture.md).
