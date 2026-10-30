package tui

import (
	"strconv"
	"strings"
)

type screen int

const (
	scrOverview screen = iota
	scrFindings
	scrProjects
	scrStatus
	scrSettings
	numScreens
)

// screenDef is one screen: what the tab strip, the Left/Right cycle, the number
// keys, the breadcrumb, the jump box and the help are all drawn from. The
// behaviour of each screen is attached in init, because it reaches code that
// reads this table again.
type screenDef struct {
	name string
	key  string // the key that jumps to it
	// standalone says the screen works without the snapshot of the other screens,
	// so it still opens when that cannot be read.
	standalone bool

	modes  func(m *app) []*mode             // the layers open on the screen, the root first
	body   func(m *app, w, h int) []string  // what the root level draws
	layout func(m *app, w, h int)           // tells the lists on the screen their room
	crumbs func(m *app, cs []crumb) []crumb // the levels below the screen
	badge  func(m *app) string              // a note after the name in the tab
}

var screens = [numScreens]screenDef{
	scrOverview: {name: "Overview", key: "1"},
	scrFindings: {name: "Findings", key: "2"},
	scrProjects: {name: "Projects", key: "3"},
	scrStatus:   {name: "Status", key: "4"},
	scrSettings: {name: "Settings", key: "5", standalone: true},
}

// screenList is the names of the screens in tab order.
func screenList() string {
	var names []string
	for _, sc := range screens {
		names = append(names, sc.name)
	}
	return strings.Join(names, ", ")
}

func init() {
	page := func(scr screen, root func() *mode) screenDef {
		sc := screens[scr]
		sc.modes = func(*app) []*mode { return []*mode{root()} }
		sc.body = func(m *app, w, h int) []string {
			start, end := m.txt[m.scr].window(h)
			return m.page(m.scr, w).view(start, end, m.pageSel[m.scr].at())
		}
		sc.layout = func(m *app, w, h int) {
			pg := m.page(m.scr, w)
			m.cache[m.scr] = textCache{w: w, snap: m.data, page: pg}
			m.txt[m.scr].refit(len(pg.lines), nil)
			m.txt[m.scr].fit(h)
			m.pageSel[m.scr].refit(len(pg.rows), func(i int) string { return pg.rows[i].key })
			m.pageSel[m.scr].fit(h)
		}
		return sc
	}
	o := &screens[scrOverview]
	o.modes, o.body, o.layout, o.crumbs = overviewModes, overviewBody, overviewLayout, overviewCrumbs
	screens[scrStatus] = page(scrStatus, func() *mode { return mo.status })

	f := &screens[scrFindings]
	f.badge = func(m *app) string {
		if m.data == nil {
			return ""
		}
		return " (" + strconv.Itoa(len(m.dataIssues())) + ")"
	}
	f.modes = func(m *app) []*mode {
		s := []*mode{mo.findings}
		switch {
		case m.fnd.det != nil:
			s = append(s, mo.detail)
			if m.fnd.det.doc != nil {
				s = append(s, mo.doc)
			}
		case m.fnd.filtering:
			s = append(s, mo.filter)
		}
		return s
	}
	f.body = func(m *app, w, h int) []string { return m.findingsBody(w, h) }
	f.layout = func(m *app, w, h int) {
		switch {
		case m.fnd.det != nil && m.fnd.det.doc != nil:
			doc := m.fnd.det.doc
			doc.vp.refit(len(doc.layout(w)), nil)
			doc.vp.fit(h)
		case m.fnd.det != nil:
			d := m.fnd.det
			d.lay = d.layout(w)
			d.body.refit(len(d.lay.lines), nil)
			d.body.fit(h)
		default:
			m.fnd.vp.fit(findingsRoom(h))
		}
	}
	f.crumbs = findingsCrumbs

	p := &screens[scrProjects]
	p.modes = func(m *app) []*mode {
		s := []*mode{mo.projects}
		if m.prj.deep {
			s = append(s, mo.project)
			if m.prj.sec.focus && m.prj.ed == nil {
				s = append(s, mo.projectIssues)
			}
			if ed := m.prj.ed; ed != nil {
				if ed.open == "" {
					s = append(s, mo.fields)
				} else {
					s = append(s, mo.fieldSub)
				}
				if ed.pick != nil {
					s = append(s, mo.picker)
				}
			}
		}
		switch {
		case m.frm != nil:
		case m.prj.fix != nil:
			s = append(s, mo.fix)
		case m.prj.life != nil:
			s = append(s, mo.life)
		}
		return s
	}
	p.body = func(m *app, w, h int) []string {
		if m.prj.fix != nil {
			return m.prj.fix.view(w, h)
		}
		if m.prj.life != nil {
			return m.prj.life.view(w, h)
		}
		if p, ed, ok := m.fieldCtx(); ok {
			if ed.pick != nil {
				return ed.pick.view(w, h)
			}
			return ed.view(p, w, h)
		}
		if p, ok := m.selectedProject(); ok && m.prj.deep {
			if m.prj.sec.focus {
				return securityPage(p, &m.prj.sec, w, h)
			}
			return projectDetail(p, &m.prj, w, deepRoom(h), true)
		}
		return renderProjects(m.data.Projects, &m.prj, w, h)
	}
	p.layout = func(m *app, w, h int) {
		m.syncSecurity()
		m.prj.sec.vp.fit(max(h-secHead-1, 1))
		switch {
		case m.prj.fix != nil:
			m.prj.fix.layout(w, h)
		case m.prj.life != nil:
			m.prj.life.layout(w, h)
		case m.prj.ed != nil:
			if p, ed, ok := m.fieldCtx(); ok {
				ed.layout(p, w, h)
			}
		case m.prj.deep:
			m.prj.prob.fit(deepRoom(h))
		default:
			_, room := projectsPanel(m.data.Projects, &m.prj, w, h)
			m.prj.proj.fit(room)
			m.prj.prob.fit(problemRoom)
		}
	}
	p.crumbs = projectsCrumbs
}
