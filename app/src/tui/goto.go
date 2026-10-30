package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
)

type targetKind uint8

const (
	tgNone     targetKind = iota
	tgScreen              // a screen as it is
	tgIssue               // an issue on the findings screen
	tgProject             // a project on the projects screen, or one problem of its file
	tgFindings            // the findings screen with a filter
)

// target is a place in the interface. goTo is the one way to get there from
// another screen: it switches the screen, sets the filter, places the cursor
// and, by doing so, builds the breadcrumb.
type target struct {
	kind    targetKind
	scr     screen // tgScreen
	issue   string // tgIssue
	open    bool   // tgIssue: open its page, else only put the list cursor on it
	row     string // tgIssue: the environment row to select on the page, as targetID names it
	project string // tgProject
	field   string // tgProject: the problem on this field of the project's file
	filter  string // tgFindings
}

func issueTarget(id string, open bool) target {
	return target{kind: tgIssue, issue: id, open: open}
}
func projectTarget(name, field string) target {
	return target{kind: tgProject, project: name, field: field}
}
func findingsTarget(filter string) target { return target{kind: tgFindings, filter: filter} }

// The levels a target can land on, which is where going back returns.
const (
	lvList    = "list"
	lvDetail  = "detail"
	lvProblem = "problem"
)

// returnPoint is where the user came from, offered by back on the level the
// jump landed on. It dies with a change of screen.
type returnPoint struct {
	to     target
	dest   screen
	level  string
	filter string // the filter the jump set; it goes again with the way back
}

// retAt is whether back on this level returns to where the jump came from.
// A filter the user typed after the jump is cleared by esc first.
func (m *app) retAt(level string) bool {
	r := m.ret
	if r == nil || r.dest != m.scr || r.level != level {
		return false
	}
	return level != lvList || m.scr != scrFindings || m.fnd.text == "" || m.fnd.text == r.filter
}

// goBack returns to where the last jump came from.
func (m *app) goBack() tea.Cmd {
	r := m.ret
	m.ret = nil
	if r.filter != "" && m.scr == scrFindings && m.fnd.text == r.filter {
		m.fnd.text = ""
		m.fnd.refit(m.dataIssues())
	}
	cmd := m.goTo(r.to)
	m.ret = nil
	return cmd
}

// here is the place the user is at, as a target to come back to.
func (m *app) here() (target, bool) {
	if m.data == nil || m.frm != nil {
		return target{}, false
	}
	switch m.scr {
	case scrFindings:
		if d := m.fnd.det; d != nil {
			t := issueTarget(d.id, true)
			if !d.loading && d.err == nil && d.sel.at() >= 0 && d.sel.at() < len(d.is.Targets) {
				t.row = targetID(d.is.Targets[d.sel.at()])
			}
			return t, true
		}
		if len(m.fnd.vis) > 0 {
			return issueTarget(m.fnd.vis[m.fnd.vp.at()].ID, false), true
		}
	case scrProjects:
		p, ok := m.selectedProject()
		if !ok {
			break
		}
		field := ""
		if (m.prj.deep || m.prj.fix != nil) && m.prj.prob.at() < len(p.Problems) {
			field = p.Problems[m.prj.prob.at()].Field
		}
		return projectTarget(p.Name, field), true
	default:
		return target{kind: tgScreen, scr: m.scr}, true
	}
	return target{}, false
}

// goTo takes the user to t. The place they leave is kept, so that back on the
// level they land on returns.
func (m *app) goTo(t target) tea.Cmd {
	if m.data == nil {
		return nil
	}
	from, hadFrom := m.here()
	level := lvList
	var cmd tea.Cmd
	switch t.kind {
	case tgScreen:
		m.scr = t.scr
	case tgIssue:
		m.scr = scrFindings
		m.fnd.filtering, m.fnd.det = false, nil
		i := m.visibleIssue(t.issue)
		if i < 0 && !t.open { // the cursor has to land somewhere: show everything
			m.fnd.text, m.fnd.min = "", model.SevUnknown
			m.fnd.refit(m.dataIssues())
			i = m.visibleIssue(t.issue)
		}
		if i >= 0 {
			m.fnd.vp.to(i)
		}
		if t.open {
			level = lvDetail
			cmd = m.openIssueID(t.issue)
			m.fnd.det.sel.key = t.row // the page selects it once it is read
		}
	case tgFindings:
		m.scr = scrFindings
		m.fnd.filtering, m.fnd.det = false, nil
		m.fnd.text, m.fnd.min = t.filter, model.SevUnknown
		m.fnd.refit(m.dataIssues())
		m.fnd.vp.to(0)
	case tgProject:
		i := -1
		for j, p := range m.data.Projects {
			if p.Name == t.project {
				i = j
			}
		}
		if i < 0 {
			m.fail("project " + oneLine(t.project) + " is not listed here")
			return nil
		}
		m.scr, m.prj.fix, m.prj.life, m.prj.ed = scrProjects, nil, nil, nil
		before := m.prj.proj.id()
		m.prj.proj.to(i)
		m.refitProjects(before)
		m.prj.deep = false
		for j, is := range m.data.Projects[i].Problems {
			if t.field != "" && is.Field == t.field {
				m.prj.prob.to(j)
				m.prj.deep, level = true, lvProblem
				break
			}
		}
	default:
		return nil
	}
	m.ret = nil
	if hadFrom && from != t {
		m.ret = &returnPoint{to: from, dest: m.scr, level: level, filter: t.filter}
	}
	return cmd
}

// visibleIssue is the row of issue id in the filtered list, -1 for none.
func (m *app) visibleIssue(id string) int {
	for i, is := range m.fnd.vis {
		if is.ID == id {
			return i
		}
	}
	return -1
}

// ---- keys that go somewhere ----

// goProject is p in an issue: the project of the selected environment.
func (m *app) goProject() tea.Cmd {
	d := m.fnd.det
	if d == nil || d.loading || d.err != nil || d.sel.at() < 0 || d.sel.at() >= len(d.is.Targets) {
		m.fail("nothing selected: open an issue with an environment first")
		return nil
	}
	return m.goTo(projectTarget(d.is.Targets[d.sel.at()].Project, ""))
}

// goFindings is i on Projects: the issues of the project, found with the
// filter language the findings screen already has.
func (m *app) goFindings() tea.Cmd {
	p, ok := m.selectedProject()
	if !ok {
		return nil
	}
	return m.goTo(findingsTarget("project:" + strings.TrimSpace(p.Name)))
}
