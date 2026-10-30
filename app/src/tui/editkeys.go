package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ops"
)

// lifeKey starts a lifecycle change of the selected project.
func lifeKey(verb ops.LifecycleVerb) func(*app, tea.KeyMsg) tea.Cmd {
	return func(m *app, _ tea.KeyMsg) tea.Cmd { return m.startLife(verb) }
}

func (m *app) newProject() tea.Cmd {
	m.prm = &prompt{kind: pkNew, title: "New empty project", fields: []field{{label: "Name"}, {label: "Environments"}},
		hint: "letters, digits, - and _; environments are dev, int, staging, prod separated by commas, empty means all"}
	return nil
}

// onFieldRow is whether the cursor of the field editor is on an item of this kind.
func onFieldRow(m *app, add, set bool) bool {
	p, ed, ok := m.fieldCtx()
	if !ok {
		return false
	}
	row, ok := ed.row(p)
	return ok && (!add || row.add) && (!set || row.set)
}

func onLockRow(m *app) bool {
	_, ed, ok := m.fieldCtx()
	return ok && ed.open == fldLocks && !onFieldRow(m, true, false) && onFieldRow(m, false, false)
}

func canAdd(m *app) bool {
	_, ed, ok := m.fieldCtx()
	return ok && (ed.open == fldTechs || ed.open == fldLocks)
}

func canRemove(m *app) bool { return onFieldRow(m, false, true) }

func init() {
	mo.fields = &mode{name: "fields", title: "Keys in the fields of a project", level: true,
		move:      viewportOf(func(m *app) *viewport { return &m.prj.ed.top }),
		moveShort: "field",
		click:     func(m *app, x, y int) tea.Cmd { return m.clickField(y) },
		binds: []binding{
			{keys: ks("enter", "right", "l"), disp: "enter", help: "change the field: environments and since open an editor, the others open their list", short: "edit", prio: 1, do: plain((*app).fieldOpen)},
			bindBack("back to the problems of the project", (*app).closeFields),
			bindJump(), bindRefresh(), bindTabs(), bindHelp(),
		},
		notes: []string{"Every change is previewed as a change to the file before it is saved; esc in the preview saves nothing."},
	}
	mo.fieldSub = &mode{name: "field list", title: "Keys in the list of a field", level: true,
		move:      viewportOf(func(m *app) *viewport { return &m.prj.ed.sub }),
		moveShort: "item",
		click:     func(m *app, x, y int) tea.Cmd { return m.clickField(y) },
		binds: []binding{
			{keys: ks("d", "enter"), disp: "enter/d", help: "lockfiles: include or leave out development packages in every environment", short: "toggle dev", prio: 1, when: onLockRow, do: plain((*app).fieldDev)},
			{keys: ks("enter", "right", "l"), disp: "enter", help: "change the selected item (its version, deployed version or image); on the last row, add one", short: "edit", prio: 1, do: plain((*app).fieldOpen)},
			{keys: ks("a"), help: "add a technology or a lockfile", short: "add", prio: 2, when: canAdd, do: plain((*app).fieldAdd)},
			{keys: ks("x", "delete"), disp: "x", help: "remove the selected item (a deployed version or an image is cleared)", short: "remove", prio: 2, when: canRemove, do: plain((*app).fieldRemove)},
			bindBack("back to the list of fields", (*app).closeFieldList),
			bindJump(), bindRefresh(), bindTabs(), bindHelp(),
		},
	}
	mo.picker = &mode{name: "picker", title: "Keys in a list to choose from",
		move:      viewportOf(func(m *app) *viewport { return &m.pickerOf().vp }),
		moveShort: "move",
		click:     func(m *app, x, y int) tea.Cmd { return m.clickPicker(y) },
		binds: []binding{
			{keys: ks("enter"), help: "choose the highlighted option, or confirm the ticked ones", short: "choose", prio: 0, do: plain((*app).pickAccept)},
			{keys: ks(" ", "x"), disp: "space", help: "tick or untick the option", short: "toggle", prio: 1, when: isMultiPick, do: plain((*app).pickToggle)},
			{keys: ks("a"), help: "tick all, or untick all", short: "all/none", prio: 2, when: isMultiPick, do: plain((*app).pickAll)},
			bindBack("back; nothing is changed", (*app).pickBack),
			bindHelp(),
		},
	}
	mo.life = &mode{name: "life", title: "Keys in the consequences of a change to a project",
		move:      viewportOf(func(m *app) *viewport { return &m.prj.life.vp }),
		moveShort: "scroll",
		binds: []binding{
			{keys: ks("enter", "y", "Y"), disp: "enter/y", help: "go on: rename, duplicate, disable and enable apply; delete asks you to type the project name", short: "go on", prio: 0, when: lifeIdle, do: plain((*app).confirmLife)},
			{keys: ks("c"), help: "delete: also mark the project's open findings ignored", short: "close findings", prio: 1, when: lifeDeleting, do: plain((*app).toggleClose)},
			{keys: ks("esc", "left", "h", "backspace", "q"), disp: "esc", help: "cancel; nothing is changed (backspace and q do the same)", short: "cancel", prio: 0, when: lifeIdle, do: plain((*app).cancelLife)},
			bindHelp(),
		},
	}
}
