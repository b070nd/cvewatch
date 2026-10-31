package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/query"
)

type projectsState struct {
	proj viewport // the project rows, followed by name
	prob viewport // the problems of the selected project, followed by field and message
	fix  *fixState
	deep bool         // inside the selected project: up/down move between its problems
	ed   *fieldEditor // the focus is on the fields of the selected project
	life *lifeState   // a change to the whole project awaits its confirmation
	sec  secState     // the open security issues of the selected project

	fixOf string // the problem whose fix was chosen (see chosenFix)
	fixAt int
}

// problemRoom is how many problems the project panel shows at once.
const problemRoom = 5

// deepRoom is how many problems fit when the project has the whole body.
func deepRoom(h int) int { return clamp(h-6, 1, 40) }

func problemID(i projectfile.Issue) string { return i.Field + "\x00" + i.Message }

// refitProjects takes the rows of a new snapshot, or a move to another project:
// the problem cursor starts over when the project under the cursor changed.
func (m *app) refitProjects(before string) {
	rows := m.data.Projects
	m.prj.proj.refit(len(rows), func(i int) string { return rows[i].Name })
	var probs []projectfile.Issue
	p, ok := m.selectedProject()
	if ok {
		probs = p.Problems
	}
	if m.prj.proj.id() != before {
		m.prj.prob.reset(len(probs))
		m.prj.deep = false
		m.prj.sec.focus = false
	}
	if !ok {
		m.prj.deep = false
	}
	if ed := m.prj.ed; ed != nil && (!ok || p.Name != ed.project) {
		m.prj.ed = nil
	}
	if lf := m.prj.life; lf != nil && !lf.saving && (!ok || p.Name != lf.req.Project) {
		m.prj.life = nil // the project is gone or the cursor is elsewhere: the question no longer fits
	}
	m.prj.prob.refit(len(probs), func(i int) string { return problemID(probs[i]) })
}

// stepProblem is the p/P alias: it steps the problem cursor from the project list.
func (m *app) stepProblem(k tea.KeyMsg) tea.Cmd {
	if p, ok := m.selectedProject(); ok && len(p.Problems) > 0 {
		d := 1
		if k.String() == "P" {
			d = len(p.Problems) - 1
		}
		m.prj.prob.to((m.prj.prob.at() + d) % len(p.Problems))
	}
	return nil
}

// enterProject opens the selected project and narrows the overview and the
// findings to it, so its security issues are what the lists show.
func (m *app) enterProject() tea.Cmd {
	p, ok := m.selectedProject()
	if !ok {
		return nil
	}
	m.prj.deep, m.prj.sec.focus = true, false
	if !p.Disabled && m.scope != p.Name {
		m.setScope(p.Name)
	}
	return nil
}

func (m *app) editProject() tea.Cmd {
	p, ok := m.selectedProject()
	if !ok {
		return nil
	}
	if p.Broken != "" {
		m.fail("the file of " + p.Name + " does not load; press E to edit it")
		return nil
	}
	if p.Disabled {
		m.fail(p.Name + " is disabled; press Z to enable it first")
		return nil
	}
	return m.start("opening "+oneLine(p.Name)+"...", "flow", 0, nil, startFlowCmd(m.b, p.Name, ""))
}

func (m *app) addProject() tea.Cmd {
	return m.start("opening...", "flow", 0, nil, startFlowCmd(m.b, "", ""))
}

func (m *app) scanFolder() tea.Cmd {
	m.startPath()
	return nil
}

// clickProject selects the project drawn on the given body row; a click on
// the selected one opens it.
func (m *app) clickProject(line int) tea.Cmd {
	i := rowAt(&m.prj.proj, line)
	switch {
	case i < 0:
		return nil
	case i == m.prj.proj.at():
		return m.enterProject()
	}
	before := m.prj.proj.id()
	m.prj.proj.to(i)
	m.refitProjects(before)
	return nil
}

// techList is "php 8.2, nginx", as much as fits.
func techList(p projectRow) string {
	var parts []string
	for _, t := range p.Techs {
		parts = append(parts, strings.TrimSpace(oneLine(t.Name)+" "+oneLine(t.Version)))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// projectsPanel lays the selected project out under the list and says how
// many project rows that leaves room for.
func projectsPanel(rows []projectRow, st *projectsState, w, h int) (detail []string, room int) {
	if len(rows) == 0 {
		return nil, 1
	}
	detail = projectDetail(rows[st.proj.at()], st, w, problemRoom, false)
	detailH := 0
	if h > 14 {
		detailH = len(detail) + 1
	}
	return detail, max(h-1-detailH, 1)
}

// renderProjects lists the projects with their declared technologies and the
// number of lockfiles, and below the list the selected project in full.
func renderProjects(rows []projectRow, st *projectsState, w, h int) []string {
	if len(rows) == 0 {
		return []string{stMuted.Render("No projects yet."), "", "Press + to add one: from a folder, from a Dockerfile or compose file, or empty."}
	}
	nameW := 8
	for _, p := range rows {
		nameW = max(nameW, min(width(oneLine(p.Name)), 24))
	}
	const envW, lockW, probW, hintW = 22, 9, 13, 8
	techW := max(w-2-nameW-1-envW-1-lockW-1-probW-1-hintW-1, 10)
	lines := []string{stHead.Render(trunc("  "+pad("PROJECT", nameW)+" "+pad("ENVIRONMENTS", envW)+" "+pad("LOCKFILES", lockW)+" "+pad("PROBLEMS", probW)+" "+pad("HINTS", hintW)+" TECHNOLOGIES", w))}

	detail, room := projectsPanel(rows, st, w, h)
	start, end := st.proj.window(room)
	for i := start; i < end; i++ {
		p := rows[i]
		envs := orDash(strings.Join(p.Envs, ","))
		if p.EnvsUnset {
			envs = "old default"
		}
		techs := techList(p)
		if p.Broken != "" {
			envs, techs = "-", oneLine(p.Broken)
		}
		cells := pad(oneLine(p.Name), nameW) + " " + pad(envs, envW) + " " + pad(fmt.Sprint(len(p.Lockfiles)), lockW) + " " + pad(problemBadge(p), probW) + " " + pad(hintBadge(p), hintW) + " " + trunc(techs, techW)
		if i == st.proj.at() {
			lines = append(lines, stSel.Render(pad("> "+cells, w)))
		} else {
			lines = append(lines, "  "+cells)
		}
	}
	if h > 14 {
		lines = append(lines, "")
		lines = append(lines, detail...)
	}
	return lines
}

// problemBadge is the count of what is wrong with the project file, in words.
func problemBadge(p projectRow) string {
	errs, warns := p.counts()
	switch {
	case p.Disabled:
		return "disabled"
	case p.Broken != "":
		return "BROKEN"
	case errs+warns == 0:
		return "-"
	case warns == 0:
		return fmt.Sprintf("%d err", errs)
	case errs == 0:
		return fmt.Sprintf("%d warn", warns)
	}
	return fmt.Sprintf("%d err %d warn", errs, warns)
}

func projectDetail(p projectRow, st *projectsState, w, room int, deep bool) []string {
	out := []string{section(oneLine(p.Name))}
	if !p.HasFile {
		out[0] += stMuted.Render("  defined in the main config, not editable here")
	}
	if n := len(st.sec.issues); deep && n > 0 && p.Broken == "" && !p.Disabled {
		out[0] += stMuted.Render("  " + securitySummary(st.sec.issues))
	}
	if p.Disabled {
		out = append(out, "  "+stMuted.Render("disabled: the file is switched off, so no findings are matched; Z enables it, X deletes it"))
		out = append(out, "  file: "+trunc(oneLine(p.File), w-8))
		return out
	}
	if p.Broken != "" {
		out = append(out, clip(indentWrap("  "+stErr.Render("broken: "), oneLine(p.Broken), w), 3)...)
		out = append(out, "  file: "+trunc(oneLine(p.File), w-8))
	} else {
		out = append(out, indentWrap("  technologies: ", techList(p), w)...)
	}
	out = append(out, problemLines(p.Problems, st, w, room, deep)...)
	if p.Broken != "" {
		return out
	}
	if deep {
		out = append(out, stMuted.Render("  c edits the fields (environments, technologies, lockfiles, versions, images, since)   + add   - remove"))
	} else {
		out = append(out, stMuted.Render("  + add   - remove   c edit fields   R rename   D duplicate   Z disable"))
	}
	if len(p.Lockfiles) == 0 {
		out = append(out, "  lockfiles: none")
	}
	for i, l := range p.Lockfiles {
		if i == 4 {
			out = append(out, fmt.Sprintf("  ... and %d more lockfiles", len(p.Lockfiles)-4))
			break
		}
		s := oneLine(l.Type) + " " + oneLine(l.Path)
		if l.Env != "" {
			s += " (" + oneLine(l.Env) + ")"
		}
		out = append(out, indentWrap("  lockfile: ", s, w)...)
	}
	if deep {
		out = append(out, securityLines(&st.sec, w)...)
		out = append(out, projectHintLines(p, w)...)
	}
	return out
}

// problemLines lists the problems, the selected one marked, with the label of
// its fix underneath. At most room are shown, the selected one among them.
func problemLines(issues []projectfile.Issue, st *projectsState, w, room int, deep bool) []string {
	if len(issues) == 0 {
		return nil
	}
	sel := st.prob.at()
	start, end := st.prob.window(room)
	hint := "problems (enter to select them, x to fix):"
	if deep {
		hint = "problems (up/down move, enter or x fix):"
	}
	out := []string{stMuted.Render("  " + hint)}
	for i := start; i < end; i++ {
		is := issues[i]
		mark := "    "
		if i == sel {
			mark = "  > "
		}
		out = append(out, trunc(mark+pad(oneLine(is.Level), 7)+" "+oneLine(is.Field)+": "+oneLine(is.Message), w))
		if i == sel {
			out = append(out, fixLines(is, st.chosenFix(is), w)...)
		}
	}
	if start > 0 || end < len(issues) {
		out = append(out, stMuted.Render(fmt.Sprintf("    (%d of %d)", sel+1, len(issues))))
	}
	return out
}

// fixLines lists the fixes of a problem under it: one on a line of its own, or
// several numbered with the chosen one marked.
func fixLines(is projectfile.Issue, chosen, w int) []string {
	const shown = 3
	var out []string
	switch len(is.Fixes) {
	case 0:
		return nil
	case 1:
		return []string{stMuted.Render(trunc("        fix: "+oneLine(is.Fixes[0].Label), w))}
	}
	from := clamp(chosen-shown+1, 0, len(is.Fixes)-shown)
	for j := from; j < min(from+shown, len(is.Fixes)); j++ {
		mark := "  "
		if j == chosen {
			mark = "> "
		}
		out = append(out, stMuted.Render(trunc(fmt.Sprintf("      %sfix %d: %s", mark, j+1, oneLine(is.Fixes[j].Label)), w)))
	}
	return append(out, stMuted.Render(trunc(fmt.Sprintf("        (fix %d of %d: [ and ] choose another)", chosen+1, len(is.Fixes)), w)))
}

// ---- security issues ----

// secState is the open issues of the selected project, narrowed from the
// snapshot once per snapshot and project.
type secState struct {
	snap    *snapshot
	project string
	issues  []query.Issue
	envs    []string // the environments the project monitors
	vp      viewport
	focus   bool // the focus is on the issues
}

// secHead is the number of lines above the first issue of the security page: title, summary, column heads.
const secHead = 3

func (m *app) syncSecurity() {
	sc := &m.prj.sec
	p, ok := m.selectedProject()
	if !ok || m.data == nil {
		*sc = secState{}
		return
	}
	if sc.snap == m.data && sc.project == p.Name {
		return
	}
	if sc.project != p.Name {
		sc.vp.reset(0)
		sc.focus = false
	}
	sc.snap, sc.project, sc.envs = m.data, p.Name, p.Envs
	sc.issues = narrow(m.data.Issues, p.Name)
	sc.vp.refit(len(sc.issues), func(i int) string { return sc.issues[i].ID })
}

var sevOrder = []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevUnknown}

// securitySummary counts the issues by severity, in words.
func securitySummary(issues []query.Issue) string {
	if len(issues) == 0 {
		return "no open security issues"
	}
	var parts []string
	for _, sev := range sevOrder {
		n := 0
		for _, is := range issues {
			if is.Severity == sev || (sev == model.SevUnknown && is.Severity.Rank() == 0) {
				n++
			}
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sevWord(sev)))
		}
	}
	return plural(len(issues), "open security issue", "open security issues") + ": " + strings.Join(parts, ", ")
}

func securityRow(is query.Issue, project string, envs []string, sel bool, w int) string {
	title := oneLine(is.Untrusted.Title)
	if is.KEV != nil {
		title = "[KEV] " + title
	}
	rest := " " + pad(oneLine(is.ID), 16) + " " + pad(openIn(is, project, envs), 18) + " " + title
	if sel {
		return stSel.Render(pad("> "+pad(sevWord(is.Severity), 8)+rest, w))
	}
	return "  " + sevText(is.Severity, 8) + trunc(rest, max(w-10, 1))
}

// securityLines is the section of the project page: the counts and the first issues.
func securityLines(sc *secState, w int) []string {
	const shown = 4
	out := []string{"", section("Security issues") + stMuted.Render("  "+securitySummary(sc.issues))}
	for _, is := range sc.issues[:min(len(sc.issues), shown)] {
		out = append(out, securityRow(is, sc.project, sc.envs, false, w))
	}
	if more := len(sc.issues) - shown; more > 0 {
		out = append(out, stMuted.Render(fmt.Sprintf("  ... and %d more", more)))
	}
	if len(sc.issues) > 0 {
		out = append(out, stMuted.Render("  s selects them, i lists them on the findings screen"))
	}
	return out
}

// securityPage is the project page with the focus on its security issues.
func securityPage(p projectRow, sc *secState, w, h int) []string {
	out := []string{section("Security issues of " + oneLine(p.Name)), stMuted.Render(trunc("  "+securitySummary(sc.issues)+"   enter opens one, i lists them on the findings screen", w))}
	if len(sc.issues) == 0 {
		return append(out, "", "Nothing is open for this project.")
	}
	out = append(out, stHead.Render(trunc("  "+pad("SEVERITY", 8)+" "+pad("ID", 16)+" "+pad("OPEN IN", 18)+" TITLE", w)))
	start, end := sc.vp.window(max(h-secHead, 1))
	for i := start; i < end; i++ {
		out = append(out, securityRow(sc.issues[i], sc.project, sc.envs, i == sc.vp.at(), w))
	}
	return out
}

func hasSecurity(m *app) bool { return len(m.prj.sec.issues) > 0 }

// onlySecurity is whether enter on the project page can only mean the issues: there is no problem to fix.
func onlySecurity(m *app) bool {
	p, ok := m.selectedProject()
	return ok && len(p.Problems) == 0 && hasSecurity(m)
}

func (m *app) focusSecurity() tea.Cmd {
	if hasSecurity(m) {
		m.prj.sec.focus = true
	}
	return nil
}

func (m *app) leaveSecurity() tea.Cmd {
	if m.retAt(lvProblem) {
		return m.goBack()
	}
	m.prj.sec.focus = false
	return nil
}

// openSecurityIssue shows the issue under the cursor; back comes to the list of them.
func (m *app) openSecurityIssue() tea.Cmd {
	sc := &m.prj.sec
	if len(sc.issues) == 0 {
		return nil
	}
	if m.scope != sc.project {
		m.setScope(sc.project)
	}
	return m.goTo(issueTarget(sc.issues[sc.vp.at()].ID, true))
}

// clickSecurity selects the issue drawn on the given body row; a click on the selected one opens it.
func (m *app) clickSecurity(line int) tea.Cmd {
	sc := &m.prj.sec
	i := rowAt(&sc.vp, line-secHead)
	switch {
	case i < 0:
		return nil
	case i == sc.vp.at():
		return m.openSecurityIssue()
	}
	sc.vp.to(i)
	return nil
}
