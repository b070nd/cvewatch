package tui

import (
	"regexp"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// textPage is a plain-text screen laid out for one width. Some of its lines
// belong to a row that can be selected: Enter on it goes somewhere, or shows
// the row in full when there is nowhere to go.
type textPage struct {
	lines []string
	rows  []pageRow
}

type pageRow struct {
	at, n int    // first line and number of lines
	key   string // identity, so the selection survives a refresh
	tgt   target // where Enter goes; the zero target for nowhere
	title string // the row in full, when Enter has nowhere to go
	info  string
}

// view is the lines in [start, end), the selected row drawn selected.
func (p *textPage) view(start, end, sel int) []string {
	start, end = min(start, len(p.lines)), min(end, len(p.lines))
	out := slices.Clone(p.lines[start:end])
	if sel < 0 || sel >= len(p.rows) {
		return out
	}
	r := p.rows[sel]
	for i := max(r.at, start); i < min(r.at+r.n, end); i++ {
		plain := escapes.ReplaceAllString(p.lines[i], "")
		if i == r.at && strings.HasPrefix(plain, "  ") {
			plain = "> " + plain[2:]
		}
		out[i-start] = stSel.Render(pad(plain, width(plain)))
	}
	return out
}

// page is the lines and rows of the Status screen, or of the policy violations of the Overview.
func (m *app) page(scr screen, w int) *textPage {
	if c := m.cache[scr]; c.snap == m.data && c.w == w && c.page != nil {
		return c.page
	}
	if scr == scrStatus {
		return renderStatus(m.data.Status, m.data.At, w, projectNames(m.data))
	}
	return renderViolations(m.violations(), append(slices.Clone(m.data.Status.Warnings), m.data.Warnings...), w)
}

func projectNames(sn *snapshot) []string {
	var out []string
	for _, p := range sn.Projects {
		out = append(out, p.Name)
	}
	return out
}

// projectIn is the project, of those given, that the text names as a word.
func projectIn(text string, names []string) string {
	best := ""
	for _, n := range names {
		if len(n) > len(best) && regexp.MustCompile(`(^|[^A-Za-z0-9_-])`+regexp.QuoteMeta(n)+`($|[^A-Za-z0-9_-])`).MatchString(text) {
			best = n
		}
	}
	return best
}

// selected is the row of the page under the selection.
func (m *app) selectedRow() (pageRow, bool) {
	if m.data == nil || m.scr >= numScreens {
		return pageRow{}, false
	}
	w, _ := m.size()
	rows := m.page(m.scr, w).rows
	i := m.pageSel[m.scr].at()
	if i < 0 || i >= len(rows) {
		return pageRow{}, false
	}
	return rows[i], true
}

// pageMove is the movement of a page with rows: up and down select a row,
// the other keys scroll. Without rows every key scrolls.
func (m *app) pageMove(key string) bool {
	vp := &m.pageSel[m.scr]
	switch key {
	case "up", "k", "down", "j":
		if vp.n > 0 {
			vp.handle(key)
			if r, ok := m.selectedRow(); ok {
				m.txt[m.scr].show(r.at)
				if end := r.at + r.n - 1; end >= m.txt[m.scr].at()+m.txt[m.scr].room {
					m.txt[m.scr].show(end)
				}
			}
			return true
		}
	}
	return m.txt[m.scr].handle(key)
}

// pageEnter acts on the selected row.
func (m *app) pageEnter() tea.Cmd {
	r, ok := m.selectedRow()
	switch {
	case !ok:
		return nil
	case r.tgt.kind != tgNone:
		return m.goTo(r.tgt)
	}
	m.nt = &notice{title: r.title, text: r.info}
	return nil
}

// clickPage selects the row drawn on the given body line; a click on the
// selected one acts on it.
func (m *app) clickPage(line int) tea.Cmd {
	if m.data == nil {
		return nil
	}
	w, _ := m.size()
	at := m.txt[m.scr].at() + line
	for i, r := range m.page(m.scr, w).rows {
		if at >= r.at && at < r.at+r.n {
			if i == m.pageSel[m.scr].at() {
				return m.pageEnter()
			}
			m.pageSel[m.scr].to(i)
			return nil
		}
	}
	return nil
}

// notice is a popup that shows a text in full until it is closed.
type notice struct {
	title string
	text  string
}

func (n *notice) view(w int) []string {
	out := []string{stBold.Render(trunc(oneLine(n.title), w))}
	out = append(out, clip(indentWrap("  ", oneLine(n.text), w), 6)...)
	return append(out, stMuted.Render(trunc("  enter or esc: close", w)))
}
