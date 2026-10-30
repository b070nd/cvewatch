package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

// techAssist is what the add-techs step offers for words the catalog did not take; the text changing drops it
type techAssist struct {
	rows  []assistRow
	vp    viewport
	focus bool // the cursor is on the rows, so enter picks one
}

type assistRow struct {
	term   string // the typed word the row is about
	name   string // a catalog name to put in its place; empty for the rows that keep the word
	label  string
	detail string
	all    []string // the row that keeps every one of these words as the person's own keyword
}

func termsOf(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

// buildAssist lists what can be done about the typed words the catalog lacks; +words are the flow's
func (f *form) buildAssist() {
	f.ta = nil
	if f.step.ID != "add-techs" || f.flow == nil {
		return
	}
	var rows []assistRow
	var bare []string
	for _, term := range termsOf(f.in.String()) {
		if strings.HasPrefix(term, "+") {
			continue
		}
		lk := f.flow.Lookup(term)
		if lk.Found {
			continue
		}
		for _, t := range lk.Suggest {
			rows = append(rows, assistRow{term: term, name: t.Name, label: fmt.Sprintf("%q: use %s", term, t.Name), detail: t.Title})
		}
		rows = append(rows, assistRow{term: term, label: fmt.Sprintf("%q: add as my own keyword", term), detail: "asks for more keywords and a category"})
		if len(lk.Suggest) == 0 {
			bare = append(bare, term)
		}
	}
	if len(bare) > 1 {
		rows = append(rows, assistRow{all: bare, label: fmt.Sprintf("add all %d words without a close match as my own keywords", len(bare)), detail: strings.Join(bare, ", ")})
	}
	if len(rows) == 0 {
		return
	}
	f.ta = &techAssist{rows: rows, vp: viewport{}}
	f.ta.vp.reset(len(rows))
	f.ta.vp.fit(len(rows))
}

// replaceTerm swaps one typed word for another; with an empty to the word goes.
func replaceTerm(text, from, to string) string {
	var out []string
	for _, t := range termsOf(text) {
		switch {
		case t != from:
			out = append(out, t)
		case to != "":
			out = append(out, to)
		}
	}
	return strings.Join(out, " ")
}

// plusTerms writes a plus before each of the words, so the flow keeps them as the person's own keywords.
func plusTerms(text string, words []string) string {
	var out []string
	for _, t := range termsOf(text) {
		if slices.Contains(words, t) {
			t = "+" + t
		}
		out = append(out, t)
	}
	return strings.Join(out, " ")
}

func onAddTechs(m *app) bool { return m.frm != nil && m.frm.step.ID == "add-techs" }

func hasAssist(m *app) bool { return m.frm != nil && m.frm.ta != nil && len(m.frm.ta.rows) > 0 }

func assistFocused(m *app) bool { return hasAssist(m) && m.frm.ta.focus }

// formTyped is a key into the answer text; the rows were about the old text, so a change drops them
func (m *app) formTyped(k tea.KeyMsg) bool {
	f := m.frm
	before := f.in.String()
	used := f.in.key(k)
	if f.ta != nil && f.in.String() != before {
		f.ta = nil
	}
	return used
}

// assistMove moves the cursor over the rows; the first press goes onto them.
func (m *app) assistMove(k tea.KeyMsg) tea.Cmd {
	ta := m.frm.ta
	switch {
	case !ta.focus:
		ta.focus = true
		ta.vp.to(0)
		if k.String() == "up" {
			ta.vp.to(len(ta.rows) - 1)
		}
	case k.String() == "up" && ta.vp.at() == 0, k.String() == "down" && ta.vp.at() == len(ta.rows)-1:
		ta.focus = false // past the ends the cursor goes back to the text
	default:
		ta.vp.handle(k.String())
	}
	return nil
}

func (m *app) assistLeave() tea.Cmd {
	m.frm.ta.focus = false
	return nil
}

// assistPick does what the row under the cursor says.
func (m *app) assistPick() tea.Cmd {
	f := m.frm
	r := f.ta.rows[f.ta.vp.at()]
	switch {
	case len(r.all) > 0:
		f.in.set(plusTerms(f.in.String(), r.all))
	case r.name != "":
		f.in.set(replaceTerm(f.in.String(), r.term, r.name))
	default:
		return m.assistOwn()
	}
	f.buildAssist()
	if f.ta != nil {
		f.ta.focus = true
	}
	return nil
}

// assistOwn asks what an own keyword needs, for the word under the cursor or else the first unknown one
func (m *app) assistOwn() tea.Cmd {
	f := m.frm
	term := ""
	if f.ta != nil && f.ta.focus {
		term = f.ta.rows[f.ta.vp.at()].term
	}
	if term == "" {
		for _, t := range termsOf(f.in.String()) {
			if !strings.HasPrefix(t, "+") && !f.flow.Lookup(t).Found {
				term = t
				break
			}
		}
	}
	if term == "" {
		m.fail("nothing to add: type a word the catalog does not have, then press ctrl+o")
		return nil
	}
	m.ownTechForForm(term)
	return nil
}

// flowOwnTech stages t in the flow; term is the typed word it answers
func (m *app) flowOwnTech(term string, t model.Tech) (tea.Cmd, error) {
	f := m.frm
	if f == nil || f.waiting() || f.saving { // a preview or save is reading the flow right now
		return nil, errors.New("the preview is still loading: try again in a moment")
	}
	if err := f.flow.AddCustom(t); err != nil {
		return nil, err
	}
	name := catalog.Slug(t.Name)
	if !strings.EqualFold(term, name) && f.step.ID == "review" {
		_ = f.flow.ReplaceTech(term, name) // the unknown spelling the project listed gives way to the keyword
	}
	m.prm = nil
	f.touched = true
	f.step = f.flow.Current()
	m.say("added " + oneLine(name) + " as your own keyword; techs.yaml is written when you save the project")
	if f.step.ID == "add-techs" {
		f.in.set(replaceTerm(f.in.String(), term, ""))
		f.buildAssist()
		return nil, nil
	}
	return f.enter(m), nil
}

// assistRows draws the rows under the answer text.
func (f *form) assistRows(w, room int) []string {
	if f.ta == nil || len(f.ta.rows) == 0 || room < 3 {
		return nil
	}
	hint := "down selects one, enter takes it, ctrl+o adds the first word as your own keyword"
	if f.ta.focus {
		hint = "enter takes the selected row, esc goes back to the text"
	}
	out := []string{"", section("Not in the catalog") + stMuted.Render("  "+trunc(hint, max(w-22, 1)))}
	start, end := f.ta.vp.window(max(room-2, 1))
	for i := start; i < end; i++ {
		r := f.ta.rows[i]
		line := oneLine(r.label)
		if d := oneLine(r.detail); d != "" {
			if rm := w - width(line) - 8; rm > 6 {
				line += stMuted.Render("  - " + trunc(d, rm))
			}
		}
		if f.ta.focus && i == f.ta.vp.at() {
			out = append(out, stSel.Render(pad("> "+oneLine(r.label), w)))
		} else {
			out = append(out, "  "+line)
		}
	}
	return out
}

// withWhen limits a binding to the states where when holds.
func withWhen(b binding, when func(m *app) bool) binding {
	b.when = when
	return b
}
