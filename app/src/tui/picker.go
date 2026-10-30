package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// picker is a short list to choose from inside the field editor: one option
// (a choice) or any number (a checklist). done gets the values chosen.
type picker struct {
	title string
	hint  string
	crumb string
	items []pickItem
	multi bool
	sel   map[string]bool // multi: the ticked values
	vp    viewport
	done  func(m *app, vals []string) tea.Cmd

	problem string // why the last answer was refused
}

type pickItem struct{ value, label, detail string }

// pickHead is the number of lines above the first option: title, hint, blank.
const pickHead = 3

func (pk *picker) values() []string {
	if !pk.multi {
		if i := pk.vp.at(); i >= 0 && i < len(pk.items) {
			return []string{pk.items[i].value}
		}
		return nil
	}
	var vs []string
	for _, it := range pk.items {
		if pk.sel[it.value] {
			vs = append(vs, it.value)
		}
	}
	return vs
}

func (pk *picker) view(w, h int) []string {
	out := []string{stBold.Render(trunc(pk.title, w)), stMuted.Render(trunc(pk.hint, w)), ""}
	start, end := pk.vp.window(max(h-pickHead-2, 1))
	for i := start; i < end; i++ {
		it := pk.items[i]
		box := ""
		if pk.multi {
			box = "[ ] "
			if pk.sel[it.value] {
				box = "[x] "
			}
		}
		line := box + oneLine(it.label)
		if d := oneLine(it.detail); d != "" {
			line += "  - " + d
		}
		if i == pk.vp.at() {
			out = append(out, stSel.Render(pad("> "+line, w)))
		} else {
			out = append(out, trunc("  "+line, w))
		}
	}
	if pk.problem != "" {
		out = append(out, "", stErr.Render("problem: ")+trunc(pk.problem, w-9))
	}
	return out
}

// pickerOf is the open picker, nil when there is none.
func (m *app) pickerOf() *picker {
	if m.scr == scrSettings {
		return m.set.pick
	}
	if m.prj.ed == nil {
		return nil
	}
	return m.prj.ed.pick
}

func (m *app) pickAccept() tea.Cmd {
	pk := m.pickerOf()
	vals := pk.values()
	if len(vals) == 0 {
		pk.problem = "tick at least one"
		return nil
	}
	pk.problem = ""
	return pk.done(m, vals)
}

func (m *app) pickToggle() tea.Cmd {
	pk := m.pickerOf()
	if pk.multi && len(pk.items) > 0 {
		v := pk.items[pk.vp.at()].value
		pk.sel[v] = !pk.sel[v]
		pk.problem = ""
	}
	return nil
}

// pickAll ticks every option, or none when all are ticked.
func (m *app) pickAll() tea.Cmd {
	pk := m.pickerOf()
	all := len(pk.values()) < len(pk.items)
	pk.sel = map[string]bool{}
	for _, it := range pk.items {
		pk.sel[it.value] = all
	}
	return nil
}

// clickPicker selects the option drawn on the given body line; a second click
// ticks it (a checklist) or chooses it.
func (m *app) clickPicker(line int) tea.Cmd {
	pk := m.pickerOf()
	i := rowAt(&pk.vp, line-pickHead)
	switch {
	case i < 0:
		return nil
	case i != pk.vp.at():
		pk.vp.to(i)
	case pk.multi:
		return m.pickToggle()
	default:
		return m.pickAccept()
	}
	return nil
}

func (m *app) pickBack() tea.Cmd {
	if m.scr == scrSettings {
		m.set.pick = nil
		return nil
	}
	m.prj.ed.pick = nil
	return nil
}

func isMultiPick(m *app) bool { pk := m.pickerOf(); return pk != nil && pk.multi }
