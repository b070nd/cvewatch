package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
)

// overviewState is the Overview: a short summary above the list of all the
// loaded issues, which is searched and selected like the Findings.
type overviewState struct {
	issueList
	viol bool // the policy violations are open, in place of the list
	top  int  // the body lines the summary takes, so that a click can find its row
}

// summaryBlock is a part of the summary and how long it stays when the screen is short.
type summaryBlock struct {
	prio  int // 0 is kept first
	lines []string
}

// flow joins the items with two spaces into lines of at most w cells; later
// lines are indented.
func flow(items []string, w int, indent string) []string {
	var out []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case width(cur)+2+width(it) <= w:
			cur += "  " + it
		default:
			out = append(out, cur)
			cur = indent + it
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// overviewHead is the summary above the list: is the tool healthy, how much is
// open, and where. Wording follows the HTML dashboard. On a short screen the
// less important blocks go, so that the list keeps room.
func (m *app) overviewHead(w, h int) []string {
	sn := m.data
	c := countsOf(m.dataIssues())
	rep := sn.Status
	const listMin = 7 // count line, column heads and a few rows
	var blocks []summaryBlock

	state := section("Status") + "  " + levelText(rep.Level)
	blocks = append(blocks, summaryBlock{0, []string{state + trunc("  daemon: "+orDash(oneLine(rep.Daemon.Message)), max(w-width(state), 0))}})

	cycle := []string{"last cycle: none yet"}
	var cycleErr []string
	if len(rep.Cycles) > 0 {
		cy := rep.Cycles[0]
		cycle = flow([]string{"last cycle: " + when(cy.Finished, sn.At), fmt.Sprintf("items %d", cy.Items), fmt.Sprintf("new %d", cy.New),
			fmt.Sprintf("merged %d", cy.Merged), fmt.Sprintf("findings %d", cy.Findings), fmt.Sprintf("alerted %d", cy.Alerted),
			fmt.Sprintf("digests %d", cy.Digests), fmt.Sprintf("failed feeds %d", cy.Failed)}, w, "  ")
		if cy.Err != "" {
			cycleErr = []string{"  error: " + trunc(oneLine(cy.Err), max(w-9, 0))}
		}
	}
	blocks = append(blocks, summaryBlock{2, append(cycle, cycleErr...)})

	blocks = append(blocks, summaryBlock{1, flow([]string{
		fmt.Sprintf("open issues %d", c.Issues), fmt.Sprintf("open findings %d", c.Findings),
		fmt.Sprintf("critical + high %d", c.BySev[4]+c.BySev[3]), fmt.Sprintf("known exploited (KEV) %d", c.KEV),
		fmt.Sprintf("in prod %d", c.ProdOpen), fmt.Sprintf("overdue %d", c.Overdue),
		fmt.Sprintf("policy violations %d", len(m.violations()))}, w, "  ")})

	barW := max(min((w-60)/8, 8), 0)
	most := 0
	for _, n := range c.BySev {
		most = max(most, n)
	}
	var sev []string
	for _, s := range severities {
		n := c.BySev[s.Rank()]
		sev = append(sev, sevText(s, len(sevWord(s)))+fmt.Sprintf(" %d ", n)+sevStyles[s.Rank()].Render(bar(n, most, barW)))
	}
	blocks = append(blocks, summaryBlock{3, []string{"  by severity  " + strings.Join(sev, "  ")}})

	most = 0
	for _, n := range c.ByEnv {
		most = max(most, n)
	}
	var envs []string
	for _, e := range model.AllEnvs {
		envs = append(envs, fmt.Sprintf("%s %d %s", e, c.ByEnv[e], bar(c.ByEnv[e], most, barW)))
	}
	blocks = append(blocks, summaryBlock{4, []string{"  by environment  " + strings.Join(envs, "  ")}})

	var warns []string
	warns = append(warns, rep.Warnings...)
	warns = append(warns, sn.Warnings...)
	if len(warns) > 0 {
		wl := []string{"! " + trunc(oneLine(warns[0]), w-2)}
		if len(warns) > 1 {
			wl = append(wl, fmt.Sprintf("  ... and %d more (v shows them)", len(warns)-1))
		}
		blocks = append(blocks, summaryBlock{1, wl})
	}

	room := max(h-listMin, 1)
	keep := make([]bool, len(blocks))
	used := 0
	for p := 0; p <= 4; p++ {
		for i, b := range blocks {
			if b.prio == p && (used+len(b.lines) <= room || used == 0) {
				keep[i] = true
				used += len(b.lines)
			}
		}
	}
	var out []string
	for i, b := range blocks {
		if keep[i] {
			out = append(out, b.lines...)
		}
	}
	return out
}

// overviewBody is the summary with the list of issues below it, or the policy
// violations when they are open.
func overviewBody(m *app, w, h int) []string {
	head := m.overviewHead(w, h)
	room := max(h-len(head), 1)
	if m.ovw.viol {
		start, end := m.txt[scrOverview].window(room)
		return append(head, m.page(scrOverview, w).view(start, end, m.pageSel[scrOverview].at())...)
	}
	return append(head, renderFindings(len(m.dataIssues()), &m.ovw.issueList, m.scope, w, room)...)
}

func overviewLayout(m *app, w, h int) {
	head := m.overviewHead(w, h)
	m.ovw.top = len(head)
	room := max(h-len(head), 1)
	if m.ovw.viol {
		pg := m.page(scrOverview, w)
		m.cache[scrOverview] = textCache{w: w, snap: m.data, page: pg}
		m.txt[scrOverview].refit(len(pg.lines), nil)
		m.txt[scrOverview].fit(room)
		m.pageSel[scrOverview].refit(len(pg.rows), func(i int) string { return pg.rows[i].key })
		m.pageSel[scrOverview].fit(room)
		return
	}
	m.ovw.vp.fit(findingsRoom(room))
}

func overviewModes(m *app) []*mode {
	s := []*mode{mo.overview}
	switch {
	case m.ovw.viol:
		s = append(s, mo.violations)
	case m.ovw.filtering:
		s = append(s, mo.filter)
	}
	return s
}

func overviewCrumbs(m *app, cs []crumb) []crumb {
	if m.ovw.viol {
		cs[0].back = popTo(func(m *app) { m.ovw.viol = false })
		cs = append(cs, crumb{label: "Policy violations"})
	}
	return cs
}

// openFromOverview opens the issue under the cursor on the Findings screen;
// back returns to the Overview.
func (m *app) openFromOverview() tea.Cmd {
	l := &m.ovw
	if len(l.vis) == 0 {
		return nil
	}
	return m.goTo(issueTarget(l.vis[l.vp.at()].ID, true))
}

// clickOverview selects the issue drawn on the given body row; a click on the
// selected one opens it.
func (m *app) clickOverview(y int) tea.Cmd {
	l := &m.ovw
	i := rowAt(&l.vp, y-m.ovw.top-2)
	switch {
	case i < 0:
		return nil
	case i == l.vp.at():
		return m.openFromOverview()
	}
	l.vp.to(i)
	return nil
}

func (m *app) openViolations() tea.Cmd {
	m.ovw.viol = true
	return nil
}

func init() {
	mo.overview = &mode{name: "overview", title: "Keys on the overview screen", level: true,
		move:  viewportOf(func(m *app) *viewport { return &m.ovw.vp }),
		click: func(m *app, x, y int) tea.Cmd { return m.clickOverview(y) },
		binds: rootBinds(
			binding{keys: ks("enter"), help: "open the selected issue: its environments and what to do", short: "open", prio: 1, do: plain((*app).openFromOverview)},
			bindFilter(),
			bindSeverity(),
			binding{keys: ks("v"), help: "show the policy violations and the warnings; enter opens the issue of a violation", short: "violations", prio: 2, do: plain((*app).openViolations)},
			bindClearFilter(func(m *app) bool { return false }),
		),
		notes: []string{"The list holds every open issue (of the scope, when one is set); the filter takes the words and fields of cvewatch search."},
	}
	mo.violations = &mode{name: "violations", title: "Keys in the policy violations", level: true, move: (*app).pageMove, moveShort: "select",
		moveHelp: "up/down select a policy violation; pgup/pgdn, home/end scroll the page",
		wheel:    func(m *app, up bool) { m.txt[scrOverview].move(wheelStep(up)) },
		click:    func(m *app, x, y int) tea.Cmd { return m.clickPage(y - m.ovw.top) },
		binds: []binding{
			{keys: ks("enter"), help: "open the issue of the selected policy violation", short: "open", prio: 1,
				when: func(m *app) bool { _, ok := m.selectedRow(); return ok }, do: plain((*app).pageEnter)},
			bindBack("back to the list of issues", func(m *app) tea.Cmd { m.ovw.viol = false; return nil }),
			bindJump(), bindRefresh(), bindTabs(), bindHelp(),
		}}
}

// renderViolations is the page of policy violations and warnings.
func renderViolations(viols []priority.Violation, warns []string, w int) *textPage {
	var out []string
	var rows []pageRow
	add := func(l ...string) { out = append(out, l...) }

	add(section("Policy violations"))
	if len(viols) == 0 {
		add("  none")
	}
	for i, v := range viols {
		if i == maxViolations {
			add(fmt.Sprintf("  ... and %d more (see the dashboard or `cvewatch report`)", len(viols)-maxViolations))
			break
		}
		ls := violationLines(v, w)
		rows = append(rows, pageRow{at: len(out), n: len(ls), key: violationKey(v), tgt: violationTarget(v),
			title: "Policy violation " + oneLine(v.Rule), info: violationText(v)})
		add(ls...)
	}
	add("")

	if len(warns) > 0 {
		add(section("Warnings"))
		for _, wn := range warns {
			add(indentWrap("  ! ", oneLine(wn), w)...)
		}
	}
	return &textPage{lines: out, rows: rows}
}

// maxViolations is how many violations the overview lists; each can be selected.
const maxViolations = 20

func violationText(v priority.Violation) string {
	s := v.Subject
	text := fmt.Sprintf("%s: %s %s/%s %s", oneLine(v.Rule), oneLine(s.VulnID), oneLine(s.Project), s.Env, oneLine(v.Reason))
	if v.Late >= time.Hour {
		text += fmt.Sprintf(" (%dh late)", int(v.Late.Hours()))
	}
	return text
}

func violationLines(v priority.Violation, w int) []string {
	return indentWrap("  - ", violationText(v), w)
}

func violationKey(v priority.Violation) string {
	s := v.Subject
	return v.Rule + "\x00" + s.VulnID + "\x00" + s.Project + "\x00" + string(s.Env)
}

// violationTarget is the issue a violation is about.
func violationTarget(v priority.Violation) target {
	switch s := v.Subject; {
	case s.VulnID != "":
		return issueTarget(s.VulnID, true)
	case s.Project != "":
		return projectTarget(s.Project, "")
	}
	return target{}
}
