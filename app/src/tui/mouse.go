package tui

import tea "github.com/charmbracelet/bubbletea"

// bodyTop is the first screen line of the body: the header and the
// breadcrumb are above it.
const bodyTop = 2

// mouse is the pointer on top of the keys: the wheel scrolls what has the
// focus, a click picks a row, a tab or a breadcrumb. Nothing needs it.
func (m *app) mouse(msg tea.MouseMsg) tea.Cmd {
	md := m.top()
	if msg.Action != tea.MouseActionPress {
		return nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp, tea.MouseButtonWheelDown:
		up := msg.Button == tea.MouseButtonWheelUp
		switch {
		case md.wheel != nil:
			md.wheel(m, up)
		case md.move != nil:
			key := "down"
			if up {
				key = "up"
			}
			for range 3 {
				md.move(m, key)
			}
		}
	case tea.MouseButtonLeft:
		return m.click(md, msg.X, msg.Y)
	}
	return nil
}

func (m *app) click(md *mode, x, y int) tea.Cmd {
	w, _ := m.size()
	switch {
	case y == 0 && md.level:
		_, spans := m.tabs()
		for i, sp := range spans {
			if x >= sp[0] && x < sp[1] {
				m.scr = screen(i)
			}
		}
	case y == 1 && !md.modal:
		if cmd, ok := m.clickChipAt(x, w); ok {
			return cmd
		}
		_, spans := m.crumbLine(w)
		cs := m.crumbs()
		for _, sp := range spans {
			if x >= sp.from && x < sp.to && sp.idx < len(cs)-1 && cs[sp.idx].back != nil {
				return cs[sp.idx].back(m)
			}
		}
	case y >= bodyTop && y-bodyTop < m.bodyH() && md.click != nil:
		return md.click(m, x, y-bodyTop)
	}
	return nil
}
