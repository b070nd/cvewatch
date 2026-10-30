package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// crumb is one level of the path shown under the header. back, when set,
// returns to that level; the last crumb is where the user is.
type crumb struct {
	label string
	back  func(m *app) tea.Cmd
}

var stCrumbOn = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))

func popTo(f func(m *app)) func(m *app) tea.Cmd {
	return func(m *app) tea.Cmd { f(m); return nil }
}

// crumbs is the path of levels the user is in, from the screen down.
func (m *app) crumbs() []crumb {
	cs := []crumb{{label: screenNames[m.scr]}}
	switch m.scr {
	case scrFindings:
		d := m.fnd.det
		if d == nil {
			break
		}
		cs[0].back = popTo(func(m *app) { m.fnd.det = nil })
		cs = append(cs, crumb{label: oneLine(d.id)})
		if !d.loading && d.err == nil && d.sel.at() >= 0 && d.sel.at() < len(d.is.Targets) {
			t := d.is.Targets[d.sel.at()]
			cs = append(cs, crumb{label: oneLine(t.Project) + ":" + oneLine(string(t.Env))})
		}
	case scrProjects:
		switch {
		case m.frm != nil:
			cs[0].back = (*app).leaveForm
			name := "add project"
			if !m.frm.creating {
				name = "edit " + oneLine(m.frm.existing)
			}
			cs = append(cs, crumb{label: name}, crumb{label: oneLine(m.frm.step.Title)})
		case m.prj.deep || m.prj.fix != nil:
			p, ok := m.selectedProject()
			if !ok {
				break
			}
			cs[0].back = popTo(func(m *app) { m.prj.deep, m.prj.fix = false, nil })
			cs = append(cs, crumb{label: oneLine(p.Name)})
			if len(p.Problems) > 0 && m.prj.prob.at() < len(p.Problems) {
				cs = append(cs, crumb{label: "problem: " + oneLine(p.Problems[m.prj.prob.at()].Message)})
			}
			if m.prj.fix != nil {
				cs[1].back = popTo(func(m *app) { m.prj.deep, m.prj.fix = true, nil })
				if len(cs) > 2 {
					cs[2].back = popTo(func(m *app) { m.prj.fix = nil })
				}
				cs = append(cs, crumb{label: "fix"})
			}
		}
	}
	return cs
}

// crumbSpan is the cells of the breadcrumb line that one crumb covers.
type crumbSpan struct{ from, to, idx int }

// crumbLine draws the path on one line of w cells. A path that is too long
// loses its start to an ellipsis. The rest of the line is a rule.
func (m *app) crumbLine(w int) (string, []crumbSpan) {
	cs := m.crumbs()
	type cell struct {
		r   rune
		seg int // the crumb it belongs to, -1 for a separator
		w   int
	}
	var cells []cell
	total := 0
	for i, c := range cs {
		if i > 0 {
			for _, r := range " › " {
				cells = append(cells, cell{r, -1, rw(r)})
				total += rw(r)
			}
		}
		for _, r := range trunc(c.label, max(w*2/3, 12)) {
			cells = append(cells, cell{r, i, rw(r)})
			total += rw(r)
		}
	}
	if total > w {
		drop := 0
		for total+1 > w && drop < len(cells)-1 {
			total -= cells[drop].w
			drop++
		}
		for drop < len(cells)-1 && cells[drop].seg < 0 {
			total -= cells[drop].w
			drop++
		}
		cells = append([]cell{{'…', cells[drop].seg, 1}}, cells[drop:]...)
		total++
	}

	var out strings.Builder
	var spans []crumbSpan
	x := 0
	for i := 0; i < len(cells); {
		j := i
		var run strings.Builder
		runW := 0
		for j < len(cells) && cells[j].seg == cells[i].seg {
			run.WriteRune(cells[j].r)
			runW += cells[j].w
			j++
		}
		switch seg := cells[i].seg; {
		case seg < 0:
			out.WriteString(stMuted.Render(run.String()))
		case seg == len(cs)-1:
			out.WriteString(stCrumbOn.Render(run.String()))
		default:
			out.WriteString(run.String())
		}
		if seg := cells[i].seg; seg >= 0 {
			if n := len(spans); n > 0 && spans[n-1].idx == seg {
				spans[n-1].to = x + runW
			} else {
				spans = append(spans, crumbSpan{x, x + runW, seg})
			}
		}
		x += runW
		i = j
	}
	if x+2 <= w {
		out.WriteString(stMuted.Render(" " + strings.Repeat("─", w-x-1)))
	}
	return out.String(), spans
}
