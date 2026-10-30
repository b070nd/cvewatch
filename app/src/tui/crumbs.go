package tui

import (
	"fmt"
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
	cs := []crumb{{label: screens[m.scr].name}}
	if f := screens[m.scr].crumbs; f != nil {
		cs = f(m, cs)
	}
	return cs
}

func findingsCrumbs(m *app, cs []crumb) []crumb {
	d := m.fnd.det
	if d == nil {
		return cs
	}
	cs[0].back = popTo(func(m *app) { m.fnd.det = nil })
	cs = append(cs, crumb{label: oneLine(d.id)})
	if !d.loading && d.err == nil && d.sel.at() >= 0 && d.sel.at() < len(d.is.Targets) {
		t := d.is.Targets[d.sel.at()]
		cs = append(cs, crumb{label: oneLine(t.Project) + ":" + oneLine(string(t.Env))})
	}
	switch {
	case d.doc != nil:
		closeDoc := popTo(func(m *app) { m.fnd.det.doc = nil })
		for i := 1; i < len(cs); i++ {
			cs[i].back = closeDoc
		}
		cs = append(cs, crumb{label: d.doc.kind})
	case d.link > 0 && d.link <= len(d.links()):
		cs = append(cs, crumb{label: fmt.Sprintf("References %d/%d", d.link, len(d.links()))})
	}
	return cs
}

func projectsCrumbs(m *app, cs []crumb) []crumb {
	switch {
	case m.frm != nil:
		cs[0].back = (*app).leaveForm
		name := "add project"
		if !m.frm.creating {
			name = "edit " + oneLine(m.frm.existing)
		}
		cs = append(cs, crumb{label: name}, crumb{label: oneLine(m.frm.step.Title)})
	case m.prj.deep || m.prj.fix != nil || m.prj.life != nil || m.prj.ed != nil:
		cs = m.projectCrumbs(cs)
	}
	return cs
}

// crumbSpan is the cells of the breadcrumb line that one crumb covers.
type crumbSpan struct{ from, to, idx int }

// crumbLine draws the path on one line of w cells. A path that is too long
// loses its start to an ellipsis. The rest of the line is a rule.
func (m *app) crumbLine(w int) (string, []crumbSpan) {
	cs := m.crumbs()
	chip := m.scopeChip()
	if chip != "" && w > width(chip)+12 {
		w -= width(chip) + 1 // the scope chip sits at the right end
	} else {
		chip = ""
	}
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
	} else if chip != "" {
		out.WriteString(spaces(w - x))
	}
	if chip != "" {
		out.WriteString(" " + stScope.Render(chip))
	}
	return out.String(), spans
}

// projectCrumbs is the path inside a project: the project, then the field
// editor and what is open in it, or the problem and its fix, or the change to
// the whole project that waits for its confirmation. Each crumb goes back to
// its own level, closing what is open above it.
func (m *app) projectCrumbs(cs []crumb) []crumb {
	p, ok := m.selectedProject()
	if !ok {
		return cs
	}
	cs[0].back = popTo(func(m *app) { m.prj.deep, m.prj.fix, m.prj.life, m.prj.ed = false, nil, nil, nil })
	level := func(label string, to func(m *app)) {
		cs = append(cs, crumb{label: label, back: popTo(func(m *app) { m.prj.fix, m.prj.life = nil, nil; to(m) })})
	}
	level(oneLine(p.Name), func(m *app) { m.prj.deep, m.prj.ed = true, nil })
	fx := m.prj.fix
	switch ed := m.prj.ed; {
	case ed != nil:
		if ed.open == "" {
			level("Fields", func(m *app) {
				if m.prj.ed != nil {
					m.prj.ed.pick = nil
				}
			})
		} else {
			level(fieldLabels[ed.open], func(m *app) {
				if m.prj.ed != nil {
					m.prj.ed.open, m.prj.ed.pick = "", nil
				}
			})
			if row, ok := ed.row(p); ok && ed.pick == nil {
				level(oneLine(row.name), func(m *app) {
					if m.prj.ed != nil {
						m.prj.ed.pick = nil
					}
				})
			}
		}
		if ed.pick != nil {
			level(ed.pick.crumb, func(*app) {})
		}
	case m.prj.life != nil:
	case fx != nil && fx.edit:
	case len(p.Problems) > 0 && m.prj.prob.at() < len(p.Problems):
		level("problem: "+oneLine(p.Problems[m.prj.prob.at()].Message), func(m *app) { m.prj.deep = true })
	}
	switch {
	case fx != nil && fx.edit:
		level("review", func(*app) {})
	case fx != nil:
		level("fix", func(*app) {})
	case m.prj.life != nil:
		level(strings.ToLower(verbWords[m.prj.life.req.Verb]), func(*app) {})
	}
	return cs
}
