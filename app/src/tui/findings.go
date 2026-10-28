package tui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/query"
)

type findingsState struct {
	cursor    int
	selID     string // the issue under the cursor, so a refresh keeps it
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

// filterIssues keeps issues at or above min whose id, title, techs,
// projects or owners contain every word of text.
func filterIssues(all []query.Issue, min model.Severity, text string) []query.Issue {
	words := strings.Fields(strings.ToLower(text))
	var out []query.Issue
	for _, is := range all {
		if !is.Severity.AtLeast(min) {
			continue
		}
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

func (m *app) visible() []query.Issue {
	if m.data == nil {
		return nil
	}
	return filterIssues(m.data.Issues, m.fnd.min, m.fnd.text)
}

// refit puts the cursor back on the selected issue after the list changed.
func (f *findingsState) refit(all []query.Issue) {
	vis := filterIssues(all, f.min, f.text)
	if i := slices.IndexFunc(vis, func(is query.Issue) bool { return is.ID == f.selID }); i >= 0 {
		f.cursor = i
	} else {
		f.cursor = clamp(f.cursor, 0, len(vis)-1)
	}
	f.sync(vis)
}

func (f *findingsState) sync(vis []query.Issue) {
	f.selID = ""
	if f.cursor >= 0 && f.cursor < len(vis) {
		f.selID = vis[f.cursor].ID
	}
}

func (m *app) move(d int) {
	vis := m.visible()
	m.fnd.cursor = clamp(m.fnd.cursor+d, 0, len(vis)-1)
	m.fnd.sync(vis)
}

func (m *app) findingsKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.fnd.det != nil {
		return m.detailKey(k)
	}
	switch k.String() {
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		m.move(-max(m.bodyH()-3, 1))
	case "pgdown":
		m.move(max(m.bodyH()-3, 1))
	case "home", "g":
		m.move(-1 << 20)
	case "end", "G":
		m.move(1 << 20)
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
		vis := m.visible()
		if len(vis) == 0 {
			return m, nil
		}
		is := vis[clamp(m.fnd.cursor, 0, len(vis)-1)]
		m.fnd.det = &detail{id: is.ID, loading: true}
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
		return d.view(m.data.At, w, h)
	}
	return renderFindings(m.visible(), len(m.data.Issues), &m.fnd, w, h)
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

// renderFindings draws the table: a count line, a header and the rows around
// the cursor. rows is the filtered list, total the unfiltered count.
func renderFindings(rows []query.Issue, total int, st *findingsState, w, h int) []string {
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

	room := max(h-len(lines), 1)
	start := clamp(st.cursor-room/2, 0, len(rows)-room)
	end := min(start+room, len(rows))
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
		if i == st.cursor {
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
	sel     int // the selected environment row
	scroll  int
}

func (m *app) detailLoaded(msg detailMsg) {
	d := m.fnd.det
	if d == nil || d.id != msg.id {
		return
	}
	d.loading, d.err = false, msg.err
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
	d.sel = clamp(d.sel, 0, len(d.is.Targets)-1)
}

func (m *app) detailKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	d := m.fnd.det
	w, _ := m.size()
	switch s := k.String(); s {
	case "esc", "backspace", "left", "h":
		m.fnd.det = nil
	case "up", "k", "down", "j":
		if d.loading || len(d.is.Targets) == 0 {
			return m, nil
		}
		step := 1
		if s == "up" || s == "k" {
			step = -1
		}
		d.sel = clamp(d.sel+step, 0, len(d.is.Targets)-1)
		_, selLine := d.lines(m.data.At, w)
		if selLine < d.scroll {
			d.scroll = selLine
		} else if selLine >= d.scroll+m.bodyH() {
			d.scroll = selLine - m.bodyH() + 1
		}
	case "pgup":
		d.scroll = max(0, d.scroll-m.bodyH()+1)
	case "pgdown", " ":
		d.scroll += m.bodyH() - 1
	case "home", "g":
		d.scroll = 0
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

func (d *detail) view(now time.Time, w, h int) []string {
	lines, _ := d.lines(now, w)
	off := clamp(d.scroll, 0, len(lines)-h)
	d.scroll = off
	return lines[off:]
}
