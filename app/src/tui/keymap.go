package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/setup"
)

// mo holds the modes; the tables are built in init because their actions call
// back into code that looks the modes up.
var mo struct {
	noData, overview, status, findings, detail, filter, projects, project, fix *mode
	formText, formChoice, formMulti, formConfirm, formReview, formBusy         *mode
	prompt, promptBusy, folder, confirm, help, doc                             *mode
	jump, notice, formPick                                                     *mode
	fields, fieldSub, picker, life                                             *mode
}

var statusKeys = map[string]model.Status{
	"f": model.StatusFixed, "i": model.StatusIgnored, "n": model.StatusNotAffected, "o": model.StatusOpen,
	"F": model.StatusFixed, "I": model.StatusIgnored, "N": model.StatusNotAffected, "O": model.StatusOpen,
}

// ---- shared bindings ----

func bindHelp() binding {
	return binding{keys: ks("?"), help: "show or hide this help", short: "help", nav: true, do: plain(func(m *app) tea.Cmd { m.openHelp(); return nil })}
}

// bindHelpTyped is help for the modes where ? is a letter of the text.
func bindHelpTyped() binding {
	return binding{keys: ks("f1"), disp: "f1", help: "show or hide this help (a ? is typed into the field)", short: "help",
		do: plain(func(m *app) tea.Cmd { m.openHelp(); return nil })}
}

func bindRefresh() binding {
	return binding{keys: ks("r"), help: "refresh now (it also refreshes by itself)", short: "refresh", prio: 3,
		do: plain(func(m *app) tea.Cmd { return m.refresh(reList | reDetail) })}
}

func bindQuit() binding {
	return binding{keys: ks("q"), help: "quit", short: "quit", do: plain(func(*app) tea.Cmd { return tea.Quit })}
}

// bindBack goes back one level, or closes the popup. q does the same.
func bindBack(what string, f func(m *app) tea.Cmd) binding {
	return binding{keys: ks("esc", "left", "h", "backspace", "q"), disp: "esc, left", help: what + " (backspace and q do the same)", short: "back", do: plain(f)}
}

// bindTabs switches the screen from a level inside one.
func bindTabs() binding {
	return binding{keys: ks("tab", "shift+tab", "1", "2", "3", "4"), disp: "tab, 1-4",
		help: "switch screen: tab and shift+tab cycle, 1-4 jump", prio: 4, nav: true, do: func(m *app, k tea.KeyMsg) tea.Cmd {
			switch s := k.String(); s {
			case "tab":
				m.stepScreen(1)
			case "shift+tab":
				m.stepScreen(-1)
			default:
				m.scr = screen(s[0] - '1')
			}
			return nil
		}}
}

// bindScreens is left and right on the first level of a screen.
func bindScreens() binding {
	return binding{keys: ks("left", "h", "right", "l"), disp: "left/right", help: "previous or next screen (it wraps around)", short: "screens", prio: 2, nav: true,
		do: func(m *app, k tea.KeyMsg) tea.Cmd {
			if s := k.String(); s == "left" || s == "h" {
				m.stepScreen(-1)
			} else {
				m.stepScreen(1)
			}
			return nil
		}}
}

// bindJump opens the jump box. It is in every mode that is not a text input.
func bindJump() binding {
	return binding{keys: ks(":", "ctrl+g"), disp: ":", help: "jump to an issue by id or a project by name; matches are listed as you type",
		short: "jump", prio: 3, nav: true, do: plain((*app).openJump)}
}

// bindReturn goes back to where the last jump came from, on the level it landed on.
func bindReturn(level string) binding {
	return binding{keys: ks("esc", "backspace"), disp: "esc", help: "return to where the jump came from (backspace does the same)", short: "back", prio: 1,
		when: func(m *app) bool { return m.retAt(level) }, do: plain((*app).goBack)}
}

func rootBinds(own ...binding) []binding {
	return append(append(own, bindScreens(), bindTabs(), bindJump(), bindRefresh(), bindHelp()), bindQuit())
}

func viewportOf(get func(m *app) *viewport) func(m *app, key string) bool {
	return func(m *app, key string) bool { return get(m).handle(key) }
}

// rowAt is the row of vp drawn on body line y, -1 for none.
func rowAt(vp *viewport, y int) int {
	start, end := vp.window(vp.room)
	if i := start + y; y >= 0 && i < end {
		return i
	}
	return -1
}

// pageScreen is Overview or Status: text with rows that can be selected.
func pageScreen(scr screen, name, title, enterShort, enterHelp, moveHelp string) *mode {
	return &mode{name: name, title: title, level: true, move: (*app).pageMove, moveShort: "select", moveHelp: moveHelp,
		wheel: func(m *app, up bool) { m.txt[scr].move(wheelStep(up)) },
		click: func(m *app, x, y int) tea.Cmd { return m.clickPage(y) },
		binds: rootBinds(
			binding{keys: ks("enter"), help: enterHelp, short: enterShort, prio: 1,
				when: func(m *app) bool { _, ok := m.selectedRow(); return ok }, do: plain((*app).pageEnter)},
		),
	}
}

func init() {
	mo.noData = &mode{name: "nodata", title: "Keys while nothing is loaded", level: true,
		binds: []binding{
			{keys: ks("r"), help: "try to load the state again", short: "try again", do: plain(func(m *app) tea.Cmd { return m.refresh(reList | reDetail) })},
			bindQuit(), bindHelp(), bindScreens(), bindTabs(),
		}}
	mo.overview = pageScreen(scrOverview, "overview", "Keys on the overview screen", "open",
		"open the issue of the selected policy violation", "up/down select a policy violation; pgup/pgdn, home/end scroll the page")
	mo.status = pageScreen(scrStatus, "status", "Keys on the status screen", "details",
		"go to the project the selected error names, else show the error in full", "up/down select an error; pgup/pgdn, home/end scroll the page")

	// ---- findings ----
	mo.findings = &mode{name: "findings", title: "Keys on the findings screen", level: true,
		move:  viewportOf(func(m *app) *viewport { return &m.fnd.vp }),
		click: func(m *app, x, y int) tea.Cmd { return m.clickIssue(y - 2) },
		binds: rootBinds(
			binding{keys: ks("enter"), help: "open the selected issue: its environments and what to do", short: "open", prio: 1, do: plain((*app).openIssue)},
			binding{keys: ks("/"), help: "filter by words or fields such as severity:high", short: "filter", prio: 1, do: plain((*app).startFilter)},
			binding{keys: ks("s"), help: "cycle the minimum severity: all, low+, medium+, high+, critical+", short: "severity", prio: 2, do: plain((*app).cycleSeverity)},
			binding{keys: ks(" "), disp: "space", help: "mark or unmark the issue for a change of many; the cursor moves on", short: "select", prio: 2, do: plain((*app).toggleSelect)},
			binding{keys: ks("ctrl+a"), help: "select every issue in the list, or none when all of them are selected", short: "all", prio: 3, do: plain((*app).selectAll)},
			binding{keys: ks("f", "i", "n", "o"), disp: "f/i/n/o", help: "mark every selected issue fixed, ignored, not affected or reopened (its open environments); one note for all",
				short: "mark selected", prio: 1, when: hasSelection, do: m2(func(m *app, s string) { m.startBulk(statusKeys[s]) })},
			binding{keys: ks("esc"), help: "clear the selection", short: "clear selection", prio: 1, when: hasSelection, do: plain((*app).clearSelection)},
			bindReturn(lvList),
			binding{keys: ks("esc"), help: "clear the filter", short: "clear filter", prio: 2,
				when: func(m *app) bool { return m.fnd.text != "" && !m.retAt(lvList) }, do: plain((*app).clearFilter)},
		),
		notes: []string{"Enter opens an issue; inside it f i n o mark the selected environment."},
	}
	mo.filter = &mode{name: "filter", title: "Keys while typing a filter", modal: true,
		typed: func(m *app, k tea.KeyMsg) bool { return m.filterType(k) },
		binds: []binding{
			{short: "type to filter", help: "type words or fields such as severity:high; the list narrows as you type"},
			{keys: ks("enter"), help: "keep the filter and go back to the list", short: "keep", do: plain((*app).keepFilter)},
			{keys: ks("esc"), help: "clear the filter", short: "clear", do: plain((*app).clearFilter)},
			bindHelpTyped(),
		}}
	mo.detail = &mode{name: "detail", title: "Keys in an issue", level: true,
		move: (*app).detailMove, moveShort: "env", moveHelp: "up/down select an environment; pgup/pgdn, home/end (or space) scroll the page",
		wheel: func(m *app, up bool) { m.fnd.det.body.move(wheelStep(up)) },
		click: func(m *app, x, y int) tea.Cmd { return m.clickEnv(y) },
		binds: []binding{
			{keys: ks("f", "i", "n", "o"), disp: "f/i/n/o", help: "mark the selected environment fixed, ignored, not affected or reopened; not-affected needs a reason",
				short: "status", prio: 1, do: m2(func(m *app, s string) { m.startStatus(statusKeys[s], false) })},
			{keys: ks("F", "I", "N", "O"), disp: "F/I/N/O", help: "the same for every environment of the project",
				short: "project", prio: 2, do: m2(func(m *app, s string) { m.startStatus(statusKeys[s], true) })},
			{keys: ks("a", "A"), disp: "a/A", help: "assign owner, due date and ticket to the selected environment / to the project",
				short: "assign", prio: 2, do: m2(func(m *app, s string) { m.startAssign(s == "A") })},
			{keys: ks("]", "J"), disp: "]", help: "open the next issue of the list (J does the same)", short: "next", prio: 1, do: func(m *app, k tea.KeyMsg) tea.Cmd { return m.stepIssue(1) }},
			{keys: ks("[", "K"), disp: "[", help: "open the previous issue of the list (K does the same)", short: "prev", prio: 1, do: func(m *app, k tea.KeyMsg) tea.Cmd { return m.stepIssue(-1) }},
			{keys: ks("p"), help: "go to the project of the selected environment", short: "to project", prio: 2, do: plain((*app).goProject)},
			{keys: ks("l", "L"), disp: "l/L", help: "select the next or previous link of References (the page scrolls to it)", short: "links", prio: 2,
				do: func(m *app, k tea.KeyMsg) tea.Cmd {
					if k.String() == "L" {
						return m.stepLink(-1)
					}
					return m.stepLink(1)
				}},
			{keys: ks("enter"), help: "open the selected link in the browser", short: "open link", prio: 1, when: hasLink, do: plain((*app).openLink)},
			{keys: ks("c"), help: "copy the selected link to the clipboard; without a clipboard tool the link is shown", short: "copy link", prio: 1, when: hasLink, do: plain((*app).copyLink)},
			{keys: ks("v"), help: "show the evidence pack of the issue: facts, per-environment truth and the audit trail", short: "evidence pack", prio: 3, do: plain((*app).openEvidence)},
			{keys: ks("R"), help: "show the full report of the issue, as cvewatch show prints it", short: "report", prio: 3, do: plain((*app).openReport)},
			{keys: ks("+"), help: "add evidence (a note, a link or both) to the selected environment", short: "add evidence", prio: 2, do: plain(func(m *app) tea.Cmd { m.startEvidence(); return nil })},
			{keys: ks("esc"), help: "unselect the link", short: "unselect", prio: 4, when: hasLink, do: plain((*app).clearLink)},
			bindBack("back to the list of issues", func(m *app) tea.Cmd {
				if m.retAt(lvDetail) {
					return m.goBack()
				}
				m.fnd.det = nil
				return nil
			}),
			bindJump(), bindRefresh(), bindTabs(), bindHelp(),
		}}

	// ---- projects ----
	mo.doc = &mode{name: "doc", title: "Keys in the report and the evidence pack", level: true,
		move: func(m *app, key string) bool {
			if key == " " {
				key = "pgdown"
			}
			return m.fnd.det.doc.vp.handle(key)
		},
		moveShort: "scroll", moveHelp: "scroll; pgup/pgdn page (or space), home/end first and last (k j g G work too)",
		binds: []binding{
			bindBack("back to the issue", (*app).closeDoc),
			bindJump(), bindTabs(), bindHelp(),
		}}
	mo.projects = &mode{name: "projects", title: "Keys on the projects screen", level: true,
		move: func(m *app, key string) bool {
			before := m.prj.proj.id()
			if !m.prj.proj.handle(key) {
				return false
			}
			m.refitProjects(before)
			return true
		},
		click: func(m *app, x, y int) tea.Cmd { return m.clickProject(y - 1) },
		binds: rootBinds(
			binding{keys: ks("enter"), help: "open the project: its problems, each with its fix", short: "open", prio: 1, do: plain((*app).enterProject)},
			binding{keys: ks("c"), help: "open the project's fields: environments, technologies, lockfiles, versions, images, since", short: "fields", prio: 1, do: plain((*app).openFields)},
			binding{keys: ks("e"), help: "edit the project step by step in a guided form (to change one field directly, press c)", short: "guided edit", prio: 3, do: plain((*app).editProject)},
			binding{keys: ks("a", "n"), disp: "a", help: "add a project with the guided form", short: "add", prio: 2, do: plain((*app).addProject)},
			binding{keys: ks("N"), help: "new empty project: a name and its environments, no folder needed", short: "new", prio: 3, do: plain((*app).newProject)},
			binding{keys: ks("d"), help: "add a project from a folder: it is scanned and proposals are offered", short: "scan folder", prio: 2, do: plain((*app).scanFolder)},
			binding{keys: ks("x", "f"), disp: "x", help: "fix the selected problem: shows the change to the file, enter or y applies it", short: "fix", prio: 2, do: plain((*app).startFix)},
			binding{keys: ks("E", "o"), disp: "E", help: "open the project's file in $EDITOR (also when it is broken), then reload", short: "editor", prio: 3, do: plain((*app).openEditor)},
			binding{keys: ks("p", "P"), alias: true, help: "next or previous problem of the project", do: (*app).stepProblem},
			binding{keys: ks("i", "F"), disp: "i", help: "the issues of this project: the findings screen filtered by it", short: "issues", prio: 2, do: plain((*app).goFindings)},
			binding{keys: ks("R"), help: "rename the project: its findings and access rules follow the new name", short: "rename", prio: 4, do: lifeKey(ops.VerbRename)},
			binding{keys: ks("D"), help: "duplicate the project under another name", short: "duplicate", prio: 5, do: lifeKey(ops.VerbDuplicate)},
			binding{keys: ks("X"), help: "delete the project: its file moves to the project backups", short: "delete", prio: 5, do: lifeKey(ops.VerbDelete)},
			binding{keys: ks("Z"), help: "disable the project (its file is switched off), or enable a disabled one", short: "disable/enable", prio: 4, do: lifeKey(ops.VerbDisable)},
			bindReturn(lvList),
		),
	}
	mo.project = &mode{name: "project", title: "Keys in a project", level: true,
		move:      viewportOf(func(m *app) *viewport { return &m.prj.prob }),
		moveShort: "problem",
		binds: []binding{
			{keys: ks("enter", "right", "l", "x", "f"), disp: "enter", help: "preview the fix of the selected problem; enter or y applies it", short: "fix", prio: 1, do: plain((*app).startFix)},
			{keys: ks("c"), help: "edit the project's fields directly: environments, technologies, lockfiles, versions, images, since", short: "fields", prio: 1, do: plain((*app).openFields)},
			{keys: ks("e"), help: "edit the project step by step in a guided form (to change one field directly, press c)", short: "guided edit", prio: 4, do: plain((*app).editProject)},
			{keys: ks("E", "o"), disp: "E", help: "open the project's file in $EDITOR (also when it is broken), then reload", short: "editor", prio: 3, do: plain((*app).openEditor)},
			{keys: ks("R"), help: "rename the project: its findings and access rules follow the new name", short: "rename", prio: 4, do: lifeKey(ops.VerbRename)},
			{keys: ks("D"), help: "duplicate the project under another name", short: "duplicate", prio: 5, do: lifeKey(ops.VerbDuplicate)},
			{keys: ks("X"), help: "delete the project: its file moves to the project backups", short: "delete", prio: 5, do: lifeKey(ops.VerbDelete)},
			{keys: ks("Z"), help: "disable the project (its file is switched off)", short: "disable", prio: 4, do: lifeKey(ops.VerbDisable)},
			{keys: ks("N"), help: "new empty project: a name and its environments, no folder needed", prio: 4, do: plain((*app).newProject)},
			{keys: ks("a", "n"), disp: "a", help: "add a project with the guided form", prio: 4, do: plain((*app).addProject)},
			{keys: ks("d"), help: "add a project from a folder", prio: 4, do: plain((*app).scanFolder)},
			{keys: ks("i", "F"), disp: "i", help: "the issues of this project: the findings screen filtered by it", short: "issues", prio: 3, do: plain((*app).goFindings)},
			{keys: ks("[", "]"), disp: "[/]", help: "choose another fix of the problem when it has several", short: "fix", prio: 2,
				when: severalFixes, do: func(m *app, k tea.KeyMsg) tea.Cmd { m.chooseFix(k.String() == "]"); return nil }},
			bindBack("back to the list of projects", func(m *app) tea.Cmd {
				if m.retAt(lvProblem) {
					return m.goBack()
				}
				m.prj.deep = false
				return nil
			}),
			bindJump(), bindRefresh(), bindTabs(), bindHelp(),
		}}
	mo.fix = &mode{name: "fix", title: "Keys in the fix preview", move: viewportOf(func(m *app) *viewport { return &m.prj.fix.vp }), moveShort: "scroll",
		binds: []binding{
			{keys: ks("enter", "y", "Y"), disp: "enter/y", help: "apply the fix or the change to the project file", short: "apply",
				when: notSaving, do: plain((*app).applyFix)},
			{keys: ks("[", "]", "left", "right", "h", "l"), disp: "[/]", help: "choose another fix of the problem: left and right work too", short: "fix", prio: 1,
				when: fixChoice, do: func(m *app, k tea.KeyMsg) tea.Cmd {
					return m.stepFix(k.String() == "]" || k.String() == "right" || k.String() == "l")
				}},
			{keys: ks("esc", "backspace", "q"), disp: "esc", help: "cancel; nothing is saved (backspace and q do the same)", short: "cancel",
				when: notSaving, do: plain((*app).cancelFix)},
			{keys: ks("left", "h"), alias: true, help: "cancel", when: func(m *app) bool { return notSaving(m) && !fixChoice(m) }, do: plain((*app).cancelFix)},
			bindHelp(),
		}}

	// ---- forms ----
	formBack := func(typing bool) binding {
		b := binding{keys: ks("esc", "left", "h", "backspace", "q"), disp: "esc", help: "go back one step; on the first step leave the form (backspace and q do the same)",
			short: "back", do: plain((*app).formBack)}
		if typing { // left, backspace, h and q belong to the text
			b.keys, b.help = ks("esc"), "go back one step; on the first step leave the form"
		}
		return b
	}
	formScan := func(keys ...string) binding {
		return binding{keys: keys, disp: keys[0], help: "scan a folder and merge what it finds into the project", short: "scan folder", prio: 3,
			do: plain(func(m *app) tea.Cmd { m.startPath(); return nil })}
	}
	formNext := func(help string) binding {
		return binding{keys: ks("enter"), help: help, short: "next", prio: 1, do: plain((*app).formAnswerCurrent)}
	}
	mo.formBusy = &mode{name: "form busy", title: "Keys in the project form",
		binds: []binding{{short: "working, please wait", help: "wait for the preview or the save to finish"}}}
	mo.formText = &mode{name: "form text", title: "Keys in the project form",
		typed: func(m *app, k tea.KeyMsg) bool { return m.frm.in.key(k) },
		binds: []binding{
			{short: "type the answer", help: "type the answer to the question"},
			formNext("accept the answer and go on"),
			formBack(true),
			formScan("ctrl+d"),
			bindHelpTyped(),
		}}
	choice := func(name string, multi bool) *mode {
		md := &mode{name: name, title: "Keys in the project form", moveShort: "move",
			move: viewportOf(func(m *app) *viewport { return &m.frm.vp }), click: func(m *app, x, y int) tea.Cmd { return m.clickOption(y) }}
		next := formNext("choose the highlighted option and go on")
		next.short = "select"
		if multi {
			next = formNext("confirm the ticked options and go on")
			md.binds = append(md.binds, next,
				binding{keys: ks(" ", "x"), disp: "space", help: "tick or untick the option", short: "toggle", prio: 1, do: plain((*app).toggleOption)},
				binding{keys: ks("a"), help: "tick all, or untick all", short: "all/none", prio: 2, do: plain((*app).toggleAll)})
		} else {
			md.binds = append(md.binds, next)
		}
		md.binds = append(md.binds, formBack(false), formScan("d", "ctrl+d"), bindHelp())
		return md
	}
	mo.formChoice = choice("form choice", false)
	mo.formMulti = choice("form multi", true)
	mo.formConfirm = &mode{name: "form confirm", title: "Keys in the project form", move: viewportOf(func(m *app) *viewport { return &m.frm.rev }), moveShort: "scroll",
		binds: []binding{
			{keys: ks("y", "Y", "n", "N"), disp: "y/n", help: "answer the question", short: "yes/no", do: func(m *app, k tea.KeyMsg) tea.Cmd {
				v := "no"
				if s := k.String(); s == "y" || s == "Y" {
					v = "yes"
				}
				return m.formAnswer(v)
			}},
			formBack(false), formScan("d", "ctrl+d"), bindHelp(),
		}}
	mo.formReview = &mode{name: "form review", title: "Keys in the project form", move: viewportOf(func(m *app) *viewport { return &m.frm.rev }), moveShort: "scroll",
		binds: []binding{
			{keys: ks("enter", "y", "Y"), disp: "enter/y", help: "save the project file", short: "save", do: plain(func(m *app) tea.Cmd { return m.formAnswer("yes") })},
			{keys: ks("n", "N"), alias: true, help: "do not save: back to the step before the review", do: plain(func(m *app) tea.Cmd { return m.formAnswer("no") })},
			{keys: ks("e"), help: "change one step: pick it from a list; the review comes back after it", short: "edit step", prio: 1, do: plain((*app).openPick)},
			formBack(false), formScan("d", "ctrl+d"), bindHelp(),
		}}
	mo.formPick = &mode{name: "form pick", title: "Keys in the list of steps", move: viewportOf(func(m *app) *viewport { return &m.frm.pick.vp }), moveShort: "pick",
		click: func(m *app, x, y int) tea.Cmd { return m.clickPick(y) },
		binds: []binding{
			{keys: ks("enter", "right", "l"), disp: "enter", help: "go to the highlighted step; once it is answered the review comes back", short: "go", prio: 0, do: plain((*app).pickEnter)},
			{keys: ks("esc", "left", "h", "backspace", "q"), disp: "esc", help: "back to the review (backspace and q do the same)", short: "back", do: plain(func(m *app) tea.Cmd { m.frm.pick = nil; return nil })},
			bindHelp(),
		}}

	// ---- popups ----
	mo.prompt = &mode{name: "prompt", title: "Keys in a prompt", modal: true,
		typed: func(m *app, k tea.KeyMsg) bool { p := m.prm; return p.fields[p.idx].in.key(k) },
		binds: []binding{
			{short: "type", help: "type into the field"},
			{keys: ks("enter"), help: "confirm; on a field that is not the last, go to the next", short: "confirm", do: plain((*app).promptEnter)},
			{keys: ks("tab", "down"), disp: "tab", help: "next field", short: "next field", prio: 2, when: multiField,
				do: plain(func(m *app) tea.Cmd { m.prm.idx = min(m.prm.idx+1, len(m.prm.fields)-1); return nil })},
			{keys: ks("shift+tab", "up"), disp: "shift+tab", help: "previous field", prio: 3, when: multiField,
				do: plain(func(m *app) tea.Cmd { m.prm.idx = max(m.prm.idx-1, 0); return nil })},
			{keys: ks("esc"), help: "cancel; nothing is written", short: "cancel", do: plain(func(m *app) tea.Cmd { m.prm = nil; return nil })},
			bindHelpTyped(),
		}}
	mo.promptBusy = &mode{name: "prompt busy", title: "Keys in a prompt that is saving", modal: true,
		typed: func(*app, tea.KeyMsg) bool { return true },
		binds: []binding{
			{short: "working", help: "wait for the change to be written"},
			{keys: ks("esc"), help: "close the prompt; the change that is being written still lands", short: "close", do: plain(func(m *app) tea.Cmd { m.prm = nil; return nil })},
			bindHelpTyped(),
		}}
	boxKey := func(m *app, k tea.KeyMsg) tea.Cmd { m.prm.box.key(k); return nil }
	mo.folder = &mode{name: "folder", title: "Keys in the folder box", modal: true,
		typed: func(m *app, k tea.KeyMsg) bool { m.prm.box.key(k); return true },
		binds: []binding{
			{short: "type a path", help: "type a folder; the list narrows as you type"},
			{keys: ks("tab"), help: "complete the name, or open the highlighted folder", short: "complete or open", prio: 1, do: boxKey},
			{keys: ks("shift+tab"), help: "go up one folder", short: "up", prio: 2, do: boxKey},
			{keys: ks("up", "down", "pgup", "pgdown"), disp: "up/down", help: "pick a folder in the list (pgup/pgdn page)", short: "pick", prio: 1, do: boxKey},
			{keys: ks("enter"), help: "use the highlighted folder, or the typed text when none is picked", short: "use", do: plain((*app).promptEnter)},
			{keys: ks("esc"), help: "cancel", short: "cancel", do: plain(func(m *app) tea.Cmd { m.prm = nil; return nil })},
			bindHelpTyped(),
		}}
	mo.confirm = &mode{name: "confirm", title: "Keys in a question", modal: true,
		binds: []binding{
			{keys: ks("y", "Y", "enter"), disp: "y/enter", help: "yes", short: "yes", do: plain(func(m *app) tea.Cmd { c := m.cfm; m.cfm = nil; return c.yes(m) })},
			{keys: ks("n", "N", "esc", "q"), disp: "n/esc", help: "no, carry on (q does the same)", short: "no", do: plain(func(m *app) tea.Cmd { m.cfm = nil; return nil })},
		}}
	mo.jump = &mode{name: "jump", title: "Keys in the jump box", modal: true,
		typed: func(m *app, k tea.KeyMsg) bool { used := m.jmp.in.key(k); m.jmp.refit(m); return used },
		binds: []binding{
			{short: "type an id or a name", help: "type part of an issue id or a project name; matches are listed as you type, ids and names that start with it first"},
			{keys: ks("enter"), help: "go to the highlighted match; text that looks like an issue id is tried as one", short: "go", do: plain((*app).jumpEnter)},
			{keys: ks("up", "down", "pgup", "pgdown"), disp: "up/down", help: "pick a match (pgup/pgdn page)", short: "pick", prio: 1,
				do: func(m *app, k tea.KeyMsg) tea.Cmd { m.jmp.vp.handle(k.String()); return nil }},
			{keys: ks("tab"), help: "complete the text with the highlighted match", short: "complete", prio: 2, do: plain((*app).jumpComplete)},
			{keys: ks("esc"), help: "cancel", short: "cancel", do: plain(func(m *app) tea.Cmd { m.jmp = nil; return nil })},
			bindHelpTyped(),
		}}
	mo.notice = &mode{name: "notice", title: "Keys in a message", modal: true,
		binds: []binding{
			{keys: ks("enter", "esc", "q", "left", "h", "backspace"), disp: "enter/esc", help: "close the message", short: "close", do: plain(func(m *app) tea.Cmd { m.nt = nil; return nil })},
			bindHelp(),
		}}
	mo.help = &mode{name: "help", title: "Keys in the help", modal: true, move: viewportOf(func(m *app) *viewport { return &m.helpVP }), moveShort: "scroll",
		binds: []binding{
			{keys: ks("?", "f1", "esc", "left", "h", "backspace", "q"), disp: "? or esc", help: "close the help", short: "close help", nav: true, do: plain(func(m *app) tea.Cmd { m.closeHelp(); return nil })},
		}}
}

// m2 runs f with the key that was pressed.
func m2(f func(m *app, key string)) func(*app, tea.KeyMsg) tea.Cmd {
	return func(m *app, k tea.KeyMsg) tea.Cmd { f(m, k.String()); return nil }
}

// formMode is the mode of the step the form shows.
func formMode(f *form) *mode {
	switch {
	case f.saving || f.waiting():
		return mo.formBusy
	case f.pick != nil:
		return mo.formPick
	case f.step.Kind == setup.KindText:
		return mo.formText
	case f.step.Kind == setup.KindChoice:
		return mo.formChoice
	case f.step.Kind == setup.KindMulti:
		return mo.formMulti
	case f.step.ID == "review":
		return mo.formReview
	}
	return mo.formConfirm
}

// allModes lists every mode, for the tests.
func allModes() []*mode {
	return []*mode{mo.noData, mo.overview, mo.status, mo.findings, mo.filter, mo.detail, mo.projects, mo.project, mo.fix,
		mo.formBusy, mo.formText, mo.formChoice, mo.formMulti, mo.formConfirm, mo.formReview, mo.formPick, mo.prompt, mo.promptBusy, mo.folder, mo.confirm,
		mo.jump, mo.notice, mo.help, mo.doc, mo.fields, mo.fieldSub, mo.picker, mo.life}
}

func wheelStep(up bool) int {
	if up {
		return -3
	}
	return 3
}

func notSaving(m *app) bool { return m.prj.fix == nil || !m.prj.fix.saving }

func hasSelection(m *app) bool { return len(m.fnd.sel) > 0 }

func multiField(m *app) bool { return m.prm != nil && len(m.prm.fields) > 1 }
