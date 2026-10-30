package tui

import (
	"slices"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/query"
)

var stScope = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))

// scopedIssues are the issues of the snapshot that are in the scope.
type scopedIssues []query.Issue

// narrow keeps the issues that have a target in the project, each with only
// the targets there; what is derived from the targets follows them.
func narrow(issues []query.Issue, project string) []query.Issue {
	var out []query.Issue
	for _, is := range issues {
		var ts []query.Target
		for _, t := range is.Targets {
			if t.Project == project {
				ts = append(ts, t)
			}
		}
		if len(ts) == 0 {
			continue
		}
		is.Targets = ts
		is.ProdOpen, is.Applies = false, ""
		for i, t := range ts {
			is.ProdOpen = is.ProdOpen || (t.Env == model.EnvProd && t.Status == model.StatusOpen)
			switch {
			case i > 0:
				is.Applies = is.Applies.Worse(t.Applies)
			case t.Applies == "":
				is.Applies = model.AppUnknown
			default:
				is.Applies = t.Applies
			}
		}
		out = append(out, is)
	}
	return out
}

// dataIssues are the issues the lists and counts work on: all of them, or
// those of the scope.
func (m *app) dataIssues() []query.Issue {
	switch {
	case m.data == nil:
		return nil
	case m.scope == "":
		return m.data.Issues
	}
	return m.narrowed
}

// violations are the policy violations in the scope.
func (m *app) violations() []priority.Violation {
	if m.data == nil {
		return nil
	}
	if m.scope == "" {
		return m.data.Violations
	}
	var out []priority.Violation
	for _, v := range m.data.Violations {
		if v.Subject.Project == m.scope {
			out = append(out, v)
		}
	}
	return out
}

// rescope narrows the snapshot again and drops what was drawn from the old one.
func (m *app) rescope() {
	m.narrowed = nil
	if m.scope != "" && m.data != nil {
		m.narrowed = narrow(m.data.Issues, m.scope)
	}
	m.cache[scrOverview] = textCache{}
	m.refitLists()
}

// setScope narrows the Overview and the Findings to one project.
func (m *app) setScope(project string) {
	if project == "" {
		m.clearScope()
		return
	}
	if m.data != nil && !m.hasProject(project) {
		m.fail("project " + oneLine(project) + " is not listed here")
		return
	}
	m.scope = project
	m.rescope()
	m.say("scope: " + oneLine(project) + " (0 shows all projects)")
}

// clearScope shows all projects again.
func (m *app) clearScope() {
	if m.scope == "" {
		return
	}
	m.scope = ""
	m.rescope()
	m.say("scope cleared: all projects")
}

// checkScope runs when a snapshot arrives: the scope goes when its project is
// gone or switched off, and is narrowed again over the new issues.
func (m *app) checkScope() {
	if m.scope != "" && !m.hasProject(m.scope) {
		gone := m.scope
		m.scope = ""
		m.say("scope cleared: project " + oneLine(gone) + " is gone")
	}
	m.rescope()
}

func (m *app) hasProject(name string) bool {
	return m.data != nil && slices.ContainsFunc(m.data.Projects, func(p projectRow) bool { return p.Name == name && !p.Disabled })
}

func bindClearScope() binding {
	return binding{keys: ks("0"), help: "show all projects again: clears the scope that narrows the overview and the findings to one project",
		short: "all projects", prio: 2, when: func(m *app) bool { return m.scope != "" }, do: plain(func(m *app) tea.Cmd { m.clearScope(); return nil })}
}

// scopeChip is the note on the breadcrumb line that tells which project the
// lists are narrowed to; empty without a scope.
func (m *app) scopeChip() string {
	if m.scope == "" {
		return ""
	}
	return "scope: " + trunc(oneLine(m.scope), 24) + " ×"
}

// clickChip clears the scope when the click on the breadcrumb line is on the chip.
func (m *app) clickChip(x, w int) bool {
	chip := m.scopeChip()
	if chip == "" || w <= width(chip)+12 || x < w-width(chip) || x >= w {
		return false
	}
	m.clearScope()
	return true
}
