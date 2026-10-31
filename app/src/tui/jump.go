package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/confdoc"
)

// jumpBox is the popup that takes the user to an issue or a project by name.
// It suggests as the text is typed: what starts with it first, then what
// contains it.
type jumpBox struct {
	in    input
	vp    viewport
	items []jumpItem
}

type jumpItem struct {
	label  string
	detail string
	tgt    target
}

// maxSuggestions bounds the list, which is only ever a few screens long.
const maxSuggestions = 50

func jumpRows(th int) int { return clamp((th-4)/3, 1, 6) }

func (m *app) openJump() tea.Cmd {
	m.jmp = &jumpBox{vp: viewport{}}
	m.jmp.refit(m)
	return nil
}

func (j *jumpBox) refit(m *app) {
	j.items = m.suggestions(j.in.String())
	j.vp.reset(len(j.items))
	j.vp.refit(len(j.items), nil)
}

// suggestions are the issues and projects that match text.
func (m *app) suggestions(text string) []jumpItem {
	q := strings.ToLower(strings.TrimSpace(text))
	var ranked [2][]jumpItem // starts with the text, contains it
	add := func(it jumpItem, names ...string) {
		rank := -1
		for _, n := range names {
			switch n = strings.ToLower(n); {
			case q == "" || strings.HasPrefix(n, q):
				rank = 0
			case strings.Contains(n, q) && rank < 0:
				rank = 1
			}
			if rank == 0 {
				break
			}
		}
		if rank >= 0 && len(ranked[0])+len(ranked[1]) < maxSuggestions {
			ranked[rank] = append(ranked[rank], it)
		}
	}
	// projects come before issues at equal rank: there are fewer of them
	var issues []jumpItem
	var issueNames [][]string
	if m.data != nil {
		for _, p := range m.data.Projects {
			add(jumpItem{label: oneLine(p.Name), detail: "project", tgt: projectTarget(p.Name, "")}, p.Name)
		}
		for _, name := range m.tenantNames() { // only what is open in the context
			for _, is := range m.data.ByProject[name] {
				detail := sevWord(is.Severity) + " " + oneLine(is.Untrusted.Title)
				if m.tenant.multi() {
					detail = oneLine(m.projectLabelOf(name)) + "  " + detail
				}
				issues = append(issues, jumpItem{label: oneLine(is.ID), detail: detail, tgt: issueIn(name, is.ID, true)})
				issueNames = append(issueNames, append([]string{is.ID}, is.Aliases...))
			}
		}
	}
	for i, it := range issues {
		add(it, issueNames[i]...)
	}
	// settings come last: there are many of them, and they match on a word of a label
	if m.set.ready() && q != "" {
		for _, r := range m.set.mdl.candidates() {
			path := confdoc.FormatPath(r.segs)
			add(jumpItem{label: path, detail: "setting " + r.f.Section + " > " + oneLine(r.f.Label), tgt: settingTarget(path)}, path, r.f.Label, r.f.Section+" "+r.f.Label)
		}
	}
	return append(ranked[0], ranked[1]...)
}

// jumpEnter goes to the selected suggestion. Text that matches nothing but
// looks like an issue id is tried as one: the issue may be closed already.
func (m *app) jumpEnter() tea.Cmd {
	j := m.jmp
	text := strings.TrimSpace(j.in.String())
	var t target
	switch i := j.vp.at(); {
	case len(j.items) > 0 && i >= 0 && i < len(j.items):
		t = j.items[i].tgt
	case strings.Contains(text, "-") && strings.ContainsAny(text, "0123456789") && !strings.ContainsAny(text, " \t"):
		t = issueTarget(strings.ToUpper(text), true)
	default:
		m.fail("nothing matches " + oneLine(text) + ": type an issue id or a project name")
		return nil
	}
	m.jmp = nil
	return m.goTo(t)
}

// jumpComplete puts the selected suggestion into the text.
func (m *app) jumpComplete() tea.Cmd {
	j := m.jmp
	if i := j.vp.at(); i >= 0 && i < len(j.items) {
		j.in.set(j.items[i].label)
		j.refit(m)
	}
	return nil
}

func (j *jumpBox) view(w, th int) []string {
	lines := []string{stBold.Render("Go to an issue or a project, or a setting"), "> " + j.in.view(w-2, true)}
	start, end := j.vp.window(jumpRows(th))
	for i := start; i < end; i++ {
		it := j.items[i]
		mark := "  "
		if i == j.vp.at() {
			mark = "> "
		}
		line := mark + pad(it.label, 22) + " " + it.detail
		if i == j.vp.at() {
			lines = append(lines, stSel.Render(pad(trunc(line, w), w)))
		} else {
			lines = append(lines, trunc(mark+pad(it.label, 22), w)+stMuted.Render(trunc(" "+it.detail, max(w-width(mark)-23, 0))))
		}
	}
	switch {
	case len(j.items) == 0:
		lines = append(lines, stMuted.Render("  no issue or project matches; enter tries the text as an issue id"))
	case len(j.items) > end-start:
		lines = append(lines, stMuted.Render(fmt.Sprintf("  %d of %d", j.vp.at()+1, len(j.items))))
	}
	return lines
}
