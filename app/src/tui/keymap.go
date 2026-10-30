package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/setup"
)

// mo holds the modes; the tables are built in init because their actions call
// back into code that looks the modes up.
var mo struct {
	noData, overview, status, findings, detail, filter, projects, project, fix *mode
	formText, formChoice, formMulti, formConfirm, formReview, formBusy         *mode
	prompt, folder, confirm, help                                              *mode
}

var statusKeys = map[string]model.Status{
	"f": model.StatusFixed, "i": model.StatusIgnored, "n": model.StatusNotAffected, "o": model.StatusOpen,
	"F": model.StatusFixed, "I": model.StatusIgnored, "N": model.StatusNotAffected, "O": model.StatusOpen,
}

// ---- shared bindings ----

func bindHelp() binding {
	return binding{keys: ks("?"), help: "show or hide this help", short: "help", do: plain(func(m *app) tea.Cmd { m.openHelp(); return nil })}
}

// bindHelpTyped is help for the modes where ? is a letter of the text.
func bindHelpTyped() binding {
	return binding{keys: ks("f1"), disp: "f1", help: "show or hide this help (a ? is typed into the field)", short: "help",
		do: plain(func(m *app) tea.Cmd { m.openHelp(); return nil })}
}

func bindRefresh() binding {
	return binding{keys: ks("r"), help: "refresh now (it also refreshes by itself)", short: "refresh", prio: 3,
		do: plain(func(m *app) tea.Cmd { return m.reload() })}
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
		help: "switch screen: tab and shift+tab cycle, 1-4 jump", prio: 4, do: func(m *app, k tea.KeyMsg) tea.Cmd {
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
	return binding{keys: ks("left", "h", "right", "l"), disp: "left/right", help: "previous or next screen (it wraps around)", short: "screens", prio: 2,
		do: func(m *app, k tea.KeyMsg) tea.Cmd {
			if s := k.String(); s == "left" || s == "h" {
				m.stepScreen(-1)
			} else {
				m.stepScreen(1)
			}
			return nil
		}}
}

func rootBinds(own ...binding) []binding {
	return append(append(own, bindScreens(), bindTabs(), bindRefresh(), bindHelp()), bindQuit())
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

func textScreen(scr screen, name, title string) *mode {
	return &mode{name: name, title: title, level: true,
		move:  viewportOf(func(m *app) *viewport { return &m.txt[scr] }),
		binds: rootBinds(),
		notes: []string{"This screen is text: it scrolls, it has nothing to select."},
	}
}

func init() {
	mo.noData = &mode{name: "nodata", title: "Keys while nothing is loaded", level: true,
		binds: []binding{
			{keys: ks("r"), help: "try to load the state again", short: "try again", do: plain(func(m *app) tea.Cmd { return m.reload() })},
			bindQuit(), bindHelp(), bindScreens(), bindTabs(),
		}}
	mo.overview = textScreen(scrOverview, "overview", "Keys on the overview screen")
	mo.status = textScreen(scrStatus, "status", "Keys on the status screen")

	// ---- findings ----
	mo.findings = &mode{name: "findings", title: "Keys on the findings screen", level: true,
		move:  viewportOf(func(m *app) *viewport { return &m.fnd.vp }),
		click: func(m *app, x, y int) tea.Cmd { return m.clickIssue(y - 2) },
		binds: rootBinds(
			binding{keys: ks("enter"), help: "open the selected issue: its environments and what to do", short: "open", prio: 1, do: plain((*app).openIssue)},
			binding{keys: ks("/"), help: "filter by words or fields such as severity:high", short: "filter", prio: 1, do: plain((*app).startFilter)},
			binding{keys: ks("s"), help: "cycle the minimum severity: all, low+, medium+, high+, critical+", short: "severity", prio: 2, do: plain((*app).cycleSeverity)},
			binding{keys: ks("esc"), help: "clear the filter", short: "clear filter", prio: 2,
				when: func(m *app) bool { return m.fnd.text != "" }, do: plain((*app).clearFilter)},
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
		click: func(m *app, x, y int) tea.Cmd { m.clickEnv(y); return nil },
		binds: []binding{
			{keys: ks("f", "i", "n", "o"), disp: "f/i/n/o", help: "mark the selected environment fixed, ignored, not affected or reopened; not-affected needs a reason",
				short: "status", prio: 1, do: m2(func(m *app, s string) { m.startStatus(statusKeys[s], false) })},
			{keys: ks("F", "I", "N", "O"), disp: "F/I/N/O", help: "the same for every environment of the project",
				short: "project", prio: 2, do: m2(func(m *app, s string) { m.startStatus(statusKeys[s], true) })},
			{keys: ks("a", "A"), disp: "a/A", help: "assign owner, due date and ticket to the selected environment / to the project",
				short: "assign", prio: 2, do: m2(func(m *app, s string) { m.startAssign(s == "A") })},
			bindBack("back to the list of issues", func(m *app) tea.Cmd { m.fnd.det = nil; return nil }),
			bindRefresh(), bindTabs(), bindHelp(),
		}}

	// ---- projects ----
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
			binding{keys: ks("e"), help: "edit the project (technologies, versions, lockfiles, environments)", short: "edit", prio: 1, do: plain((*app).editProject)},
			binding{keys: ks("a", "n"), disp: "a", help: "add a project", short: "add", prio: 2, do: plain((*app).addProject)},
			binding{keys: ks("d"), help: "add a project from a folder: it is scanned and proposals are offered", short: "scan folder", prio: 2, do: plain((*app).scanFolder)},
			binding{keys: ks("x", "f"), disp: "x", help: "fix the selected problem: shows the change to the file, enter or y applies it", short: "fix", prio: 2, do: plain((*app).startFix)},
			binding{keys: ks("E", "o"), disp: "E", help: "open the project's file in $EDITOR (also when it is broken), then reload", short: "editor", prio: 3, do: plain((*app).openEditor)},
			binding{keys: ks("p", "P"), alias: true, help: "next or previous problem of the project", do: (*app).stepProblem},
		),
	}
	mo.project = &mode{name: "project", title: "Keys in a project", level: true,
		move:      viewportOf(func(m *app) *viewport { return &m.prj.prob }),
		moveShort: "problem",
		binds: []binding{
			{keys: ks("enter", "right", "l", "x", "f"), disp: "enter", help: "preview the fix of the selected problem; enter or y applies it", short: "fix", prio: 1, do: plain((*app).startFix)},
			{keys: ks("e"), help: "edit the project (technologies, versions, lockfiles, environments)", short: "edit", prio: 2, do: plain((*app).editProject)},
			{keys: ks("E", "o"), disp: "E", help: "open the project's file in $EDITOR (also when it is broken), then reload", short: "editor", prio: 2, do: plain((*app).openEditor)},
			{keys: ks("a", "n"), disp: "a", help: "add a project", prio: 4, do: plain((*app).addProject)},
			{keys: ks("d"), help: "add a project from a folder", prio: 4, do: plain((*app).scanFolder)},
			bindBack("back to the list of projects", func(m *app) tea.Cmd { m.prj.deep = false; return nil }),
			bindRefresh(), bindTabs(), bindHelp(),
		}}
	mo.fix = &mode{name: "fix", title: "Keys in the fix preview", move: viewportOf(func(m *app) *viewport { return &m.prj.fix.vp }), moveShort: "scroll",
		binds: []binding{
			{keys: ks("enter", "y", "Y"), disp: "enter/y", help: "apply the fix to the project file", short: "apply",
				when: notSaving, do: plain((*app).applyFix)},
			{keys: ks("esc", "left", "h", "backspace", "q"), disp: "esc", help: "cancel; nothing is saved (backspace and q do the same)", short: "cancel",
				when: notSaving, do: plain((*app).cancelFix)},
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
			formBack(false), formScan("d", "ctrl+d"), bindHelp(),
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
	mo.help = &mode{name: "help", title: "Keys in the help", modal: true, move: viewportOf(func(m *app) *viewport { return &m.helpVP }), moveShort: "scroll",
		binds: []binding{
			{keys: ks("?", "f1", "esc", "left", "h", "backspace", "q"), disp: "? or esc", help: "close the help", short: "close help", do: plain(func(m *app) tea.Cmd { m.closeHelp(); return nil })},
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
		mo.formBusy, mo.formText, mo.formChoice, mo.formMulti, mo.formConfirm, mo.formReview, mo.prompt, mo.folder, mo.confirm, mo.help}
}

func wheelStep(up bool) int {
	if up {
		return -3
	}
	return 3
}

func notSaving(m *app) bool { return m.prj.fix == nil || !m.prj.fix.saving }

func multiField(m *app) bool { return m.prm != nil && len(m.prm.fields) > 1 }
