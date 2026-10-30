package tui

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ops"
)

const (
	docReport   = "report"
	docEvidence = "evidence pack"
)

// docView is a markdown document shown over the page of an issue, in the
// same frame: the report, or the evidence pack. It is plain scrolling text.
type docView struct {
	kind    string
	text    string
	loading bool
	vp      viewport
	lines   []string // text laid out for width lw
	lw      int
	stale   bool // text changed since lines were made
}

func newDoc(kind, text string, loading bool) *docView {
	return &docView{kind: kind, text: text, loading: loading, vp: scrolling(), stale: true}
}

func (v *docView) set(text string) {
	v.text, v.loading, v.stale = text, false, true
}

// layout is the text broken into lines of w cells. Indentation is kept, so
// lists and tables keep their shape as far as they fit.
func (v *docView) layout(w int) []string {
	if !v.stale && v.lw == w && v.lines != nil {
		return v.lines
	}
	v.lw, v.stale = w, false
	if v.loading {
		v.lines = []string{stMuted.Render("Loading the " + v.kind + "...")}
		v.stale = true // the text is not there yet
		return v.lines
	}
	v.lines = wrapDoc(v.text, w)
	return v.lines
}

func (v *docView) view(w, h int) []string {
	lines := v.layout(w)
	start, end := v.vp.window(h)
	return lines[min(start, len(lines)):min(end, len(lines))]
}

var listMarker = regexp.MustCompile(`^(?:[-*] |\d+\. )`)

// wrapDoc cleans the markdown (it holds text from feeds and people) and wraps
// every line to w cells under its own indentation. Headings are bold.
func wrapDoc(text string, w int) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(clean(raw), " ")
		if line == "" {
			out = append(out, "")
			continue
		}
		body := strings.TrimLeft(line, " ")
		ind := strings.Repeat(" ", min(len(line)-len(body), w/2))
		if mk := listMarker.FindString(body); mk != "" { // a wrapped item hangs under its text
			ind, body = ind+mk, body[len(mk):]
		}
		for _, l := range indentWrap(ind, body, w) {
			if strings.HasPrefix(line, "#") {
				l = stBold.Render(l)
			}
			out = append(out, l)
		}
	}
	return out
}

// ---- keys ----

// openReport shows the report of the open issue.
func (m *app) openReport() tea.Cmd {
	d := m.fnd.det
	if d == nil || d.loading || d.err != nil || d.md == "" {
		m.fail("the report is not loaded yet")
		return nil
	}
	d.doc = newDoc(docReport, d.md, false)
	return nil
}

// openEvidence reads the evidence pack of the open issue and shows it.
func (m *app) openEvidence() tea.Cmd {
	d := m.fnd.det
	if d == nil || d.loading || d.err != nil {
		m.fail("the issue is not loaded yet")
		return nil
	}
	d.doc = newDoc(docEvidence, "", true)
	cmd := m.start("loading the evidence pack...", "evidence "+d.id, 0, nil, evidenceCmd(m.b, d.id))
	if cmd == nil {
		d.doc = nil
	}
	return cmd
}

func (m *app) closeDoc() tea.Cmd {
	if d := m.fnd.det; d != nil {
		d.doc = nil
	}
	return nil
}

type evidenceMsg struct {
	id   string
	text string
	err  error
}

// evidenceCmd renders the evidence pack as markdown.
func evidenceCmd(b Backend, id string) tea.Cmd {
	return func() tea.Msg {
		m := evidenceMsg{id: id}
		m.err = b.Read(func(s *ops.Session) error {
			p, err := s.Evidence(id)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err := p.WriteMarkdown(&buf); err != nil {
				return err
			}
			m.text = buf.String()
			return nil
		})
		return m
	}
}

func (m *app) evidenceLoaded(msg evidenceMsg) outcome {
	d := m.fnd.det
	if d == nil || d.doc == nil || d.id != msg.id || d.doc.kind != docEvidence {
		return outcome{} // closed or left meanwhile
	}
	if msg.err != nil {
		d.doc = nil
		return outcome{err: fmt.Errorf("evidence pack: %w", msg.err)}
	}
	d.doc.set(msg.text)
	return outcome{}
}
