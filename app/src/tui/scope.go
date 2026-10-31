package tui

import (
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/query"
)

var stScope = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))

// tenant is the context the interface works in: one project, all the projects
// of one vendor, or all projects, which is a portfolio view that never merges
// the rows of two projects. Everything the screens list, count, search and act
// on is inside it.
type tenant struct {
	vendor  string // all the projects of this vendor, model.NoVendor for those without one
	project string // this project alone
}

func (t tenant) all() bool { return t == tenant{} }

// filter is the query filter that reads what the context holds.
func (t tenant) filter() query.Filter { return query.Filter{Vendor: t.vendor, Project: t.project} }

// multi is whether the context holds several projects, whose rows are listed in sections.
func (t tenant) multi() bool { return t.project == "" }

// scopedIssues are the issues of the context that the lists work on.
type scopedIssues []query.Issue

// overviewTop is how many issues of each project the overview lists when it shows several.
const overviewTop = 3

// arrow joins a vendor and a project, or a vendor and what it holds.
const arrow = " ▸ "

// rowProject is the project a row of a list belongs to. Every row is read for
// one project, so all its targets are in it.
func rowProject(is query.Issue) string {
	if len(is.Targets) > 0 {
		return is.Targets[0].Project
	}
	return ""
}

// projectsOf lists the projects an issue has targets in.
func projectsOf(is query.Issue) []string {
	var out []string
	for _, t := range is.Targets {
		if !slices.Contains(out, t.Project) {
			out = append(out, t.Project)
		}
	}
	return out
}

// issueKey identifies a row of a list: the same issue in two projects is two rows.
func issueKey(is query.Issue) string { return rowProject(is) + "\x00" + is.ID }

// active are the projects that are not switched off, in the order of the list.
func (m *app) active() []projectRow {
	if m.data == nil {
		return nil
	}
	var out []projectRow
	for _, p := range m.data.Projects {
		if !p.Disabled {
			out = append(out, p)
		}
	}
	return out
}

func (m *app) hasVendors() bool {
	return m.data != nil && slices.ContainsFunc(m.data.Projects, func(p projectRow) bool { return p.Vendor != "" })
}

// namesIn are the projects of the context, in the order of the list.
func (m *app) namesIn(t tenant) []string {
	var out []string
	for _, p := range m.active() {
		switch {
		case t.project != "" && p.Name != t.project:
		case t.vendor != "" && model.VendorLabel(p.Vendor) != t.vendor:
		default:
			out = append(out, p.Name)
		}
	}
	return out
}

func (m *app) tenantNames() []string { return m.namesIn(m.tenant) }

// vendorOf is the vendor of a project, empty for none.
func (m *app) vendorOf(project string) string {
	if m.data != nil {
		for _, p := range m.data.Projects {
			if p.Name == project {
				return p.Vendor
			}
		}
	}
	return ""
}

// projectLabelOf is a project as the context names it: with its vendor when any project has one.
func (m *app) projectLabelOf(project string) string {
	if v := m.vendorOf(project); v != "" {
		return v + arrow + project
	}
	if m.hasVendors() {
		return "no vendor" + arrow + project
	}
	return project
}

func vendorWord(v string) string {
	if v == model.NoVendor {
		return "no vendor"
	}
	return v
}

// tenantLabel names the context: acme ▸ shop, acme ▸ all projects, or all projects.
func (m *app) tenantLabel() string {
	t := m.tenant
	switch {
	case t.project != "":
		return m.projectLabelOf(t.project)
	case t.vendor != "":
		return vendorWord(t.vendor) + arrow + "all projects"
	}
	return "all projects"
}

// dataIssues are the issues the lists and counts work on: those of the context
// that the time filter lets through, each row of one project.
func (m *app) dataIssues() []query.Issue {
	if m.data == nil {
		return nil
	}
	return m.narrowed
}

// violations are the policy violations in the context.
func (m *app) violations() []priority.Violation {
	if m.data == nil {
		return nil
	}
	if m.tenant.all() {
		return m.data.Violations
	}
	names := m.tenantNames()
	var out []priority.Violation
	for _, v := range m.data.Violations {
		if slices.Contains(names, v.Subject.Project) {
			out = append(out, v)
		}
	}
	return out
}

// rescope reads the issues of the context out of the snapshot again and drops
// what was drawn from the old ones.
func (m *app) rescope() {
	m.narrowed = nil
	m.ovw.lead = nil
	m.ovw.grouped, m.fnd.grouped = m.tenant.multi(), m.tenant.multi()
	m.ovw.per = 0
	if m.tenant.multi() {
		m.ovw.per = overviewTop
	}
	if m.data != nil {
		var all []query.Issue
		for _, name := range m.tenantNames() {
			all = append(all, m.data.ByProject[name]...)
		}
		m.narrowed = inRange(all, m.published, m.timeNow())
		m.ovw.lead = m.data.Status.Problems
	}
	m.cache[scrOverview] = textCache{}
	m.refitLists()
}

// setTenant moves the context. It says what it did unless quiet.
func (m *app) setTenant(t tenant, quiet bool) {
	switch {
	case m.data == nil:
		return
	case t.project != "" && !m.hasProject(t.project):
		m.fail("project " + oneLine(t.project) + " is not listed here")
		return
	case t.vendor != "" && len(m.namesIn(t)) == 0:
		m.fail("vendor " + oneLine(vendorWord(t.vendor)) + " has no project here")
		return
	}
	m.tenantAuto = false
	if t == m.tenant {
		return
	}
	m.tenant = t
	m.rescope()
	if !quiet {
		m.say("context: " + oneLine(m.tenantLabel()))
	}
}

// checkScope runs when a snapshot arrives: the context goes when its project
// is gone or switched off, a portfolio of one project works in that project,
// and the issues are read out of the snapshot again.
func (m *app) checkScope() {
	t := m.tenant
	if (t.project != "" && !m.hasProject(t.project)) || (t.vendor != "" && len(m.namesIn(t)) == 0) {
		m.tenant, m.tenantAuto = tenant{}, false
		if m.flash == "" {
			m.say("context cleared: " + oneLine(m.tenantWord(t)) + " is gone")
		}
	}
	switch act := m.active(); {
	case m.tenant.all() && len(act) == 1:
		m.tenant, m.tenantAuto = tenant{project: act[0].Name}, true
	case m.tenantAuto && len(act) != 1:
		m.tenant, m.tenantAuto = tenant{}, false
	}
	m.rescope()
}

func (m *app) tenantWord(t tenant) string {
	if t.project != "" {
		return "project " + t.project
	}
	return "vendor " + vendorWord(t.vendor)
}

func (m *app) hasProject(name string) bool {
	return m.data != nil && slices.ContainsFunc(m.data.Projects, func(p projectRow) bool { return p.Name == name && !p.Disabled })
}

// tenantChip is the note on the breadcrumb line that tells the context. It is
// always there; a click on it opens the choice.
func (m *app) tenantChip() string {
	if m.data == nil {
		return ""
	}
	return "context: " + trunc(oneLine(m.tenantLabel()), 40)
}

// clickChipAt opens the context choice when the click on the breadcrumb line
// is on its chip, and clears the time filter when it is on that one; it
// reports whether the click was on a chip.
func (m *app) clickChipAt(x, w int) (tea.Cmd, bool) {
	tchip, chip := m.chips(w)
	end := w
	if chip != "" {
		if x >= w-width(chip) && x < w {
			return m.openTenantPicker(), true
		}
		end = w - width(chip) - 1
	}
	if tchip != "" && !m.published.Any() && x >= end-width(tchip) && x < end {
		m.clearTime()
		return nil, true
	}
	return nil, false
}

func bindContext() binding {
	return binding{keys: ks("C"), help: "choose the context: all projects, one vendor or one project; the overview, the findings, the counts and the actions then work inside it only",
		short: "context", prio: 3, nav: true, do: plain((*app).openTenantPicker)}
}

// openTenantPicker lists the contexts to choose from, the current one marked by the cursor.
func (m *app) openTenantPicker() tea.Cmd {
	if m.data == nil {
		return nil
	}
	var items []pickItem
	at := 0
	add := func(it pickItem, t tenant) {
		if t == m.tenant {
			at = len(items)
		}
		items = append(items, it)
	}
	act := m.active()
	if len(act) > 1 {
		add(pickItem{value: "all", label: "all projects", detail: plural(len(act), "project", "projects") + ", listed one after the other, never merged"}, tenant{})
	}
	vendors := m.hasVendors()
	last := "\x00"
	for _, p := range act {
		v := model.VendorLabel(p.Vendor)
		if vendors && v != last {
			last = v
			n := len(m.namesIn(tenant{vendor: v}))
			add(pickItem{value: "vendor:" + v, label: vendorWord(v) + arrow + "all projects", detail: plural(n, "project", "projects")}, tenant{vendor: v})
		}
		add(pickItem{value: "project:" + p.Name, label: m.projectLabelOf(p.Name)}, tenant{project: p.Name})
	}
	if len(items) == 0 {
		m.fail("there is no project to work in yet")
		return nil
	}
	m.choose(&picker{title: "Choose the context", hint: "enter chooses, esc cancels; the overview, the findings and every action then work inside it only", crumb: "context", items: items,
		done: func(m *app, vals []string) tea.Cmd {
			m.chs = nil
			switch kind, name, _ := strings.Cut(vals[0], ":"); kind {
			case "vendor":
				m.setTenant(tenant{vendor: name}, false)
			case "project":
				m.setTenant(tenant{project: name}, false)
			default:
				m.setTenant(tenant{}, false)
			}
			return nil
		}})
	m.chs.vp.to(at)
	return nil
}
