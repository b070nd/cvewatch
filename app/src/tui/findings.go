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
	sel       map[string]bool // issues marked for a change of many; always among vis
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
	for id := range f.sel {
		if !slices.ContainsFunc(f.vis, func(is query.Issue) bool { return is.ID == id }) {
			delete(f.sel, id)
		}
	}
	if d := f.det; d != nil {
		if i := slices.IndexFunc(f.vis, func(is query.Issue) bool { return is.ID == d.id }); i >= 0 {
			d.pos = i
		}
	}
}

func (m *app) toggleSelect() tea.Cmd {
	f := &m.fnd
	if len(f.vis) == 0 {
		return nil
	}
	id := f.vis[f.vp.at()].ID
	if f.sel == nil {
		f.sel = map[string]bool{}
	}
	if f.sel[id] {
		delete(f.sel, id)
	} else {
		f.sel[id] = true
	}
	f.vp.move(1)
	return nil
}

// selectAll marks every issue in the list, or none when all are marked.
func (m *app) selectAll() tea.Cmd {
	f := &m.fnd
	all := len(f.sel) < len(f.vis)
	f.sel = map[string]bool{}
	if all {
		for _, is := range f.vis {
			f.sel[is.ID] = true
		}
	}
	return nil
}

func (m *app) clearSelection() tea.Cmd {
	m.fnd.sel = nil
	return nil
}

// stepIssue opens the next or previous issue of the list, keeping the page
// open. An issue that left the list (it was just closed) leaves its place to
// the one that slid into it, which is the next.
func (m *app) stepIssue(dir int) tea.Cmd {
	d := m.fnd.det
	i := m.visibleIssue(d.id)
	to := i + dir
	if i < 0 {
		to = d.pos
		if dir < 0 {
			to--
		}
	}
	if to < 0 || to >= len(m.fnd.vis) {
		if dir > 0 {
			m.say("this is the last issue of the list")
		} else {
			m.say("this is the first issue of the list")
		}
		return nil
	}
	m.fnd.vp.to(to)
	return m.openIssueID(m.fnd.vis[to].ID)
}

func (m *app) cycleSeverity() tea.Cmd {
	m.fnd.min = minCycle[(m.fnd.min.Rank()+1)%len(minCycle)] // the cycle is in rank order
	m.fnd.refit(m.dataIssues())
	m.say("minimum severity: " + minLabel(m.fnd.min))
	return nil
}

func (m *app) startFilter() tea.Cmd {
	m.fnd.filtering = true
	m.fnd.in.set(m.fnd.text)
	return nil
}

func (m *app) clearFilter() tea.Cmd {
	m.fnd.filtering, m.fnd.text = false, ""
	m.fnd.refit(m.dataIssues())
	return nil
}

func (m *app) keepFilter() tea.Cmd {
	m.fnd.filtering = false
	return nil
}

// openIssue opens the issue under the cursor.
func (m *app) openIssue() tea.Cmd {
	if len(m.fnd.vis) == 0 {
		return nil
	}
	return m.openIssueID(m.fnd.vis[m.fnd.vp.at()].ID)
}

// openIssueID shows the page of an issue and reads it in the background.
func (m *app) openIssueID(id string) tea.Cmd {
	m.fnd.det = &detail{id: id, loading: true, body: scrolling(), pos: m.visibleIssue(id)}
	return m.start("loading "+oneLine(id)+"...", "show "+id, 0, nil, detailCmd(m.b, id))
}

// clickIssue selects the issue drawn on the given body row; a click on the
// selected one opens it.
func (m *app) clickIssue(line int) tea.Cmd {
	i := rowAt(&m.fnd.vp, line)
	switch {
	case i < 0:
		return nil
	case i == m.fnd.vp.at():
		return m.openIssue()
	}
	m.fnd.vp.to(i)
	return nil
}

func (m *app) dataIssues() []query.Issue {
	if m.data == nil {
		return nil
	}
	return m.data.Issues
}

// filterType feeds a key to the filter text and filters again.
func (m *app) filterType(k tea.KeyMsg) bool {
	used := m.fnd.in.key(k)
	m.fnd.text = m.fnd.in.String()
	m.fnd.refit(m.dataIssues())
	return used
}

func (m *app) findingsBody(w, h int) []string {
	if d := m.fnd.det; d != nil {
		if d.doc != nil {
			return d.doc.view(w, h)
		}
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
	if n := len(st.sel); n > 0 {
		info += fmt.Sprintf("   %d selected", n)
	}
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
	fixed := 3 + sevW + 1 + idW + 1 + ageW + 1
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
	lines = append(lines, stHead.Render(trunc("   "+row(head...), w)))

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
		mark := " " // the first column marks the issues picked for a change of many
		if st.sel[is.ID] {
			mark = "*"
		}
		if i == st.vp.at() {
			lines = append(lines, stSel.Render(pad(mark+"> "+row(cells(pad(sevWord(is.Severity), sevW))...), w)))
		} else {
			lines = append(lines, mark+"  "+row(cells(sevText(is.Severity, sevW))...))
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
	det     *query.Detail // the fuller view of the same issue; nil until read
	md      string        // its report
	link    int           // the link selected in References, counted from 1; 0 for none
	doc     *docView      // the report or the evidence pack, shown over the page
	ex      *ops.Explanation
	exErr   string
	sel     viewport // the environment rows, followed by project and env
	body    viewport // the scrolling page
	lay     *detailLayout
	pos     int // where the issue is, or was, in the list
}

func targetID(t query.Target) string { return t.Project + "/" + string(t.Env) }

func (m *app) detailLoaded(msg detailMsg) {
	d := m.fnd.det
	if d == nil || d.id != msg.id {
		return
	}
	if msg.err != nil && !d.loading && d.err == nil {
		return // a refresh failed: the page on screen is still the latest there is
	}
	d.loading, d.err, d.lay = false, msg.err, nil
	if msg.err != nil {
		return
	}
	prev, _ := d.selectedLink()
	d.is, d.det, d.md, d.ex, d.exErr = msg.is, msg.det, msg.md, msg.ex, ""
	d.keepLink(prev)
	if d.doc != nil && d.doc.kind == docReport {
		d.doc.set(d.md)
	}
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

// links are the links of the References section.
func (d *detail) links() []query.Link {
	if d.det == nil {
		return nil
	}
	return d.det.Links
}

// selectedLink is the link picked in References.
func (d *detail) selectedLink() (query.Link, bool) {
	if ls := d.links(); d.link >= 1 && d.link <= len(ls) {
		return ls[d.link-1], true
	}
	return query.Link{}, false
}

// keepLink puts the selection back on the link it was on after the page was
// read again, or drops it when the link is gone.
func (d *detail) keepLink(prev query.Link) {
	d.link = 0
	if prev.URL == "" {
		return
	}
	for i, l := range d.links() {
		if l.URL == prev.URL {
			d.link = i + 1
		}
	}
}

// stepLink selects the next or previous link; the first press picks the first
// (or the last, going back). It wraps around.
func (m *app) stepLink(dir int) tea.Cmd {
	d := m.fnd.det
	n := len(d.links())
	if n == 0 {
		m.say("this issue has no links")
		return nil
	}
	switch {
	case d.link == 0 && dir > 0:
		d.link = 1
	case d.link == 0:
		d.link = n
	default:
		d.link = (d.link-1+dir+n)%n + 1
	}
	d.revealLink()
	return nil
}

func (m *app) clearLink() tea.Cmd {
	m.fnd.det.link = 0
	return nil
}

func hasLink(m *app) bool {
	d := m.fnd.det
	if d == nil {
		return false
	}
	_, ok := d.selectedLink()
	return ok
}

// openLink shows the selected link in the browser.
func (m *app) openLink() tea.Cmd {
	l, ok := m.fnd.det.selectedLink()
	if !ok {
		return nil
	}
	return m.start("opening the link...", "open "+l.URL, 0, nil, openLinkCmd(m.sys, l.URL))
}

// copyLink puts the selected link on the clipboard.
func (m *app) copyLink() tea.Cmd {
	l, ok := m.fnd.det.selectedLink()
	if !ok {
		return nil
	}
	return m.start("copying the link...", "copy "+l.URL, 0, nil, copyLinkCmd(m.sys, l.URL))
}

// revealLink scrolls the page so that the whole selected link is visible.
func (d *detail) revealLink() {
	if d.lay == nil || d.link < 1 || d.link > len(d.lay.links) {
		return
	}
	r := d.lay.links[d.link-1]
	d.body.show(r.at + len(r.plain) - 1)
	d.body.show(r.at)
}

// reveal scrolls the page so that the selected environment row is visible.
func (d *detail) reveal() {
	if d.lay != nil && d.sel.at() >= 0 && d.sel.at() < len(d.lay.rows) {
		d.body.show(d.lay.rows[d.sel.at()].at)
	}
}

// detailMove is the movement of an issue: up and down pick the environment
// row, the other keys scroll the page.
func (m *app) detailMove(key string) bool {
	d := m.fnd.det
	switch key {
	case "up", "k", "down", "j":
		if !d.loading && len(d.is.Targets) > 0 {
			d.sel.handle(key)
			d.reveal()
		}
		return true
	case " ":
		key = "pgdown"
	}
	return d.body.handle(key)
}

// clickEnv selects the environment row or the link drawn on the given body
// line; a second click on the selected link opens it.
func (m *app) clickEnv(line int) tea.Cmd {
	d := m.fnd.det
	if d.lay == nil {
		return nil
	}
	start, _ := d.body.window(d.body.room)
	at := start + line
	for i, r := range d.lay.rows {
		if r.at == at {
			d.sel.to(i)
			return nil
		}
	}
	for i, r := range d.lay.links {
		if at >= r.at && at < r.at+len(r.plain) {
			if d.link == i+1 {
				return m.openLink()
			}
			d.link = i + 1
		}
	}
	return nil
}

// view is the visible part of the page. The page itself is laid out once per
// load and width; the selected row and link are only swapped in here.
func (d *detail) view(w, h int) []string {
	lay := d.layout(w)
	start, end := d.body.window(h)
	start, end = min(start, len(lay.lines)), min(end, len(lay.lines))
	out := slices.Clone(lay.lines[start:end])
	swap := func(r detailRow) {
		for j, l := range r.hl {
			if at := r.at + j; at >= start && at < end {
				out[at-start] = l
			}
		}
	}
	if i := d.sel.at(); i >= 0 && i < len(lay.rows) {
		swap(lay.rows[i])
	}
	if i := d.link - 1; i >= 0 && i < len(lay.links) {
		swap(lay.links[i])
	}
	return out
}
