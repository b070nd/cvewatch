package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/query"
)

type findingsState struct {
	vp        viewport // over vis; follows its issue by id
	vis       []query.Issue
	min       model.Severity
	text      string
	filtering bool
	in        input
	det       *detail
}

// minCycle is the order `s` steps through; unknown means no minimum.
var minCycle = []model.Severity{model.SevUnknown, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical}

func minLabel(s model.Severity) string {
	if s.Rank() == 0 {
		return "all"
	}
	return string(s) + "+"
}

// filterIssues keeps issues at or above min that match the search text (see
// query.ParseSearch); text that does not parse is matched as plain words.
func filterIssues(all []query.Issue, min model.Severity, text string) []query.Issue {
	search, perr := query.ParseSearch(text)
	words := strings.Fields(strings.ToLower(text))
	var out []query.Issue
	for _, is := range all {
		if !is.Severity.AtLeast(min) {
			continue
		}
		if perr == nil {
			if search.Match(is) {
				out = append(out, is)
			}
			continue
		}
		// A field still being typed, such as "severity:", does not parse yet; match words until it does.
		if len(words) > 0 {
			hay := strings.ToLower(strings.Join(append([]string{is.ID, is.Untrusted.Title, strings.Join(is.Techs, " "), strings.Join(is.Aliases, " ")}, targetWords(is)...), " "))
			if !slices.ContainsFunc(words, func(w string) bool { return !strings.Contains(hay, w) }) {
				out = append(out, is)
			}
			continue
		}
		out = append(out, is)
	}
	return out
}

func targetWords(is query.Issue) []string {
	var out []string
	for _, t := range is.Targets {
		out = append(out, t.Project, string(t.Env), t.Owner)
	}
	return out
}

// refit filters the issues again after they or the filter changed and puts
// the cursor back on its issue.
func (f *findingsState) refit(all []query.Issue) {
	f.vis = filterIssues(all, f.min, f.text)
	f.vp.refit(len(f.vis), func(i int) string { return f.vis[i].ID })
}

func (m *app) findingsKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.fnd.det != nil {
		return m.detailKey(k)
	}
	if m.fnd.vp.handle(k.String()) {
		return m, nil
	}
	switch k.String() {
	case "s":
		m.fnd.min = minCycle[(m.fnd.min.Rank()+1)%len(minCycle)] // the cycle is in rank order
		m.fnd.refit(m.dataIssues())
		m.say("minimum severity: " + minLabel(m.fnd.min))
	case "/":
		m.fnd.filtering = true
		m.fnd.in.set(m.fnd.text)
	case "esc":
		if m.fnd.text != "" {
			m.fnd.text = ""
			m.fnd.refit(m.dataIssues())
		}
	case "enter":
		if len(m.fnd.vis) == 0 {
			return m, nil
		}
		is := m.fnd.vis[m.fnd.vp.at()]
		m.fnd.det = &detail{id: is.ID, loading: true, body: scrolling()}
		return m, detailCmd(m.b, is.ID)
	}
	return m, nil
}

func (m *app) dataIssues() []query.Issue {
	if m.data == nil {
		return nil
	}
	return m.data.Issues
}

func (m *app) filterKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.fnd.filtering, m.fnd.text = false, ""
	case "enter":
		m.fnd.filtering = false
	default:
		m.fnd.in.key(k)
		m.fnd.text = m.fnd.in.String()
	}
	m.fnd.refit(m.dataIssues())
	return m, nil
}

func (m *app) findingsBody(w, h int) []string {
	if d := m.fnd.det; d != nil {
		return d.view(w, h)
	}
	return renderFindings(len(m.data.Issues), &m.fnd, w, h)
}

// projectEnvs summarises where an issue is open, e.g. "shop:dev,prod mw:prod".
func projectEnvs(is query.Issue) string {
	var order []string
	envs := map[string][]string{}
	for _, t := range is.Targets {
		if t.Status != model.StatusOpen {
			continue
		}
		if _, ok := envs[t.Project]; !ok {
			order = append(order, t.Project)
		}
		envs[t.Project] = append(envs[t.Project], string(t.Env))
	}
	var parts []string
	for _, p := range order {
		parts = append(parts, oneLine(p)+":"+oneLine(strings.Join(envs[p], ",")))
	}
	return strings.Join(parts, " ")
}

func owners(is query.Issue) string {
	var out []string
	for _, t := range is.Targets {
		if o := oneLine(t.Owner); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

// findingsRoom is the number of issue rows under the count line and the header.
func findingsRoom(h int) int { return max(h-2, 1) }

// renderFindings draws the table: a count line, a header and the rows around
// the cursor. total is the unfiltered count.
func renderFindings(total int, st *findingsState, w, h int) []string {
	rows := st.vis
	info := fmt.Sprintf("%d of %d open issues   min severity: %s", len(rows), total, minLabel(st.min))
	switch {
	case st.filtering:
		info += "   filter: " + st.in.view(30, true)
	case st.text != "":
		info += "   filter: " + oneLine(st.text)
	}
	lines := []string{stMuted.Render(trunc(info, w))}
	if len(rows) == 0 {
		msg := "Nothing open. No open vulnerabilities to act on."
		if total > 0 {
			msg = "No issue matches the filter. Press s to lower the severity, / to change the text."
		}
		return append(lines, "", msg)
	}

	idW := 10
	for _, is := range rows {
		idW = max(idW, min(width(oneLine(is.ID)), 20))
	}
	const sevW, ageW, ownW = 8, 7, 10
	projW := 22
	showOwn, showProj := w >= 100, w >= 80
	fixed := 2 + sevW + 1 + idW + 1 + ageW + 1
	if showProj {
		fixed += projW + 1
	}
	if showOwn {
		fixed += ownW + 1
	}
	titleW := max(w-fixed, 8)

	row := func(cells ...string) string { return strings.Join(cells, " ") }
	head := []string{pad("SEVERITY", sevW), pad("ID", idW), pad("AGE", ageW)}
	if showProj {
		head = append(head, pad("PROJECTS:ENVS", projW))
	}
	if showOwn {
		head = append(head, pad("OWNER", ownW))
	}
	head = append(head, "TITLE")
	lines = append(lines, stHead.Render(trunc("  "+row(head...), w)))

	start, end := st.vp.window(findingsRoom(h))
	for i := start; i < end; i++ {
		is := rows[i]
		title := oneLine(is.Untrusted.Title)
		if is.KEV != nil {
			title = "[KEV] " + title
		}
		age := is.Age
		if age == "" {
			age = "-"
		}
		cells := func(sev string) []string {
			c := []string{sev, pad(oneLine(is.ID), idW), pad(age, ageW)}
			if showProj {
				c = append(c, pad(projectEnvs(is), projW))
			}
			if showOwn {
				c = append(c, pad(owners(is), ownW))
			}
			return append(c, trunc(title, titleW))
		}
		if i == st.vp.at() {
			lines = append(lines, stSel.Render(pad("> "+row(cells(pad(sevWord(is.Severity), sevW))...), w)))
		} else {
			lines = append(lines, "  "+row(cells(sevText(is.Severity, sevW))...))
		}
	}
	return lines
}

// ---- detail ----

type detail struct {
	id      string
	loading bool
	err     error
	is      query.Issue
	ex      *ops.Explanation
	exErr   string
	sel     viewport // the environment rows, followed by project and env
	body    viewport // the scrolling page
	lay     *detailLayout
}

func targetID(t query.Target) string { return t.Project + "/" + string(t.Env) }

func (m *app) detailLoaded(msg detailMsg) {
	d := m.fnd.det
	if d == nil || d.id != msg.id {
		return
	}
	d.loading, d.err, d.lay = false, msg.err, nil
	if msg.err != nil {
		return
	}
	d.is, d.ex = msg.is, msg.ex
	if msg.exErr != nil {
		d.exErr = msg.exErr.Error()
	}
	slices.SortStableFunc(d.is.Targets, func(a, b query.Target) int {
		if c := strings.Compare(a.Project, b.Project); c != 0 {
			return c
		}
		return slices.Index(model.AllEnvs, a.Env) - slices.Index(model.AllEnvs, b.Env)
	})
	d.sel.refit(len(d.is.Targets), func(i int) string { return targetID(d.is.Targets[i]) })
}

// reveal scrolls the page so that the selected environment row is visible.
func (d *detail) reveal() {
	if d.lay != nil && d.sel.at() >= 0 && d.sel.at() < len(d.lay.rows) {
		d.body.show(d.lay.rows[d.sel.at()].at)
	}
}

func (m *app) detailKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	d := m.fnd.det
	switch s := k.String(); s {
	case "esc", "backspace", "left", "h":
		m.fnd.det = nil
	case "up", "k", "down", "j":
		if d.loading || len(d.is.Targets) == 0 {
			return m, nil
		}
		d.sel.handle(s)
		d.reveal()
	case "pgup", "pgdown", "home", "g", "end", "G":
		d.body.handle(s)
	case " ":
		d.body.handle("pgdown")
	case "f":
		m.startStatus(model.StatusFixed, false)
	case "i":
		m.startStatus(model.StatusIgnored, false)
	case "n":
		m.startStatus(model.StatusNotAffected, false)
	case "o":
		m.startStatus(model.StatusOpen, false)
	case "F":
		m.startStatus(model.StatusFixed, true)
	case "I":
		m.startStatus(model.StatusIgnored, true)
	case "N":
		m.startStatus(model.StatusNotAffected, true)
	case "O":
		m.startStatus(model.StatusOpen, true)
	case "a":
		m.startAssign(false)
	case "A":
		m.startAssign(true)
	}
	return m, nil
}

// view is the visible part of the page. The page itself is laid out once per
// load and width; the selected row is only swapped in here.
func (d *detail) view(w, h int) []string {
	lay := d.layout(w)
	start, end := d.body.window(h)
	start, end = min(start, len(lay.lines)), min(end, len(lay.lines))
	out := slices.Clone(lay.lines[start:end])
	if i := d.sel.at(); i >= 0 && i < len(lay.rows) {
		if at := lay.rows[i].at; at >= start && at < end {
			out[at-start] = lay.rows[i].hl
		}
	}
	return out
}
