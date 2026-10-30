package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// hints are advice, not errors; H works through them

func hintFields(hs []projectfile.Hint) map[string]bool {
	out := map[string]bool{}
	for _, h := range hs {
		out[h.Field] = true
	}
	return out
}

// hintLines is one hint as lines: its level as a word, its field and its message.
func hintLines(h projectfile.Hint, w int) []string {
	lvl := pad(oneLine(h.Level), 5)
	ls := indentWrap("  "+lvl+" ", oneLine(h.Field)+": "+oneLine(h.Message), w)
	st := stMuted
	if h.Level == "warn" {
		st = sevStyles[2]
	}
	ls[0] = "  " + st.Render(lvl) + strings.TrimPrefix(ls[0], "  "+lvl)
	return ls
}

// hintRows is the section of hints under a preview or a project.
func hintRows(hs []projectfile.Hint, w int) []string {
	if len(hs) == 0 {
		return nil
	}
	out := []string{"", section("Hints") + stMuted.Render("  H works through them")}
	for _, h := range hs {
		out = append(out, hintLines(h, w)...)
	}
	return out
}

// projectHintLines is the Hints section of the project page: the first few, the rest counted
func projectHintLines(p projectRow, w int) []string {
	if len(p.Hints) == 0 {
		return nil
	}
	const shown = 4
	out := []string{"", section("Hints") + stMuted.Render("  "+hintSummary(p.Hints)+"   H works through them")}
	for _, h := range p.Hints[:min(len(p.Hints), shown)] {
		out = append(out, clip(hintLines(h, w), 2)...)
	}
	if more := len(p.Hints) - shown; more > 0 {
		out = append(out, stMuted.Render(fmt.Sprintf("  ... and %d more", more)))
	}
	return out
}

func hintSummary(hs []projectfile.Hint) string {
	warns := 0
	for _, h := range hs {
		if h.Level == "warn" {
			warns++
		}
	}
	return plural(len(hs), "hint", "hints") + fmt.Sprintf(", %d to look at first", warns)
}

// hintBadge is the count of hints in the list of projects, in words.
func hintBadge(p projectRow) string {
	if len(p.Hints) == 0 || p.Broken != "" || p.Disabled {
		return "-"
	}
	return plural(len(p.Hints), "hint", "hints")
}

// formHints are the hints of the preview on the review step.
func (m *app) formHints() []projectfile.Hint {
	f := m.frm
	if f == nil || f.step.ID != "review" || f.prev == nil || f.saving {
		return nil
	}
	return f.prev.Hints
}

func (m *app) hintsHere() []projectfile.Hint {
	if m.frm != nil {
		return m.formHints()
	}
	if p, ok := m.selectedProject(); ok && p.Broken == "" && !p.Disabled {
		return p.Hints
	}
	return nil
}

func hasHints(m *app) bool { return len(m.hintsHere()) > 0 }

// hintAction says in a few words what enter does with a hint.
func hintAction(h projectfile.Hint) string {
	switch {
	case h.Keyword != "" && len(h.Suggest) > 0:
		return "choose: " + strings.Join(h.Suggest, ", ") + ", or keep it as your own keyword"
	case h.Keyword != "":
		return "add it as your own keyword"
	case len(h.Fix) > 0:
		return "apply the fix"
	case len(h.Suggest) > 0:
		return "choose a more specific one"
	}
	switch {
	case h.Field == "since":
		return "set the date"
	case strings.HasSuffix(h.Field, ".version"):
		return "set the version"
	case strings.HasPrefix(h.Field, "lockfiles"):
		return "add a lockfile"
	}
	return "go to the step"
}

// openHints lists the hints to work through; enter acts on the selected one.
func (m *app) openHints() tea.Cmd {
	hs := m.hintsHere()
	if len(hs) == 0 {
		m.note("no hints: nothing to point out")
		return nil
	}
	pk := &picker{title: "Hints", hint: "enter acts on the selected hint; nothing is written before you have seen the change", crumb: "hints"}
	for i, h := range hs {
		pk.items = append(pk.items, pickItem{value: strconv.Itoa(i), label: pad(oneLine(h.Level), 4) + " " + oneLine(h.Field) + ": " + shortMessage(h.Message), detail: hintAction(h)})
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		i, err := strconv.Atoi(vals[0])
		if err != nil || i < 0 || i >= len(hs) {
			return nil
		}
		m.chs = nil
		return m.applyHint(hs[i])
	}
	m.choose(pk)
	return nil
}

// applyHint acts on a hint in the form being filled, else on the selected project
func (m *app) applyHint(h projectfile.Hint) tea.Cmd {
	if m.frm != nil {
		return m.applyHintForm(h)
	}
	p, ok := m.selectedProject()
	if !ok {
		return nil
	}
	switch {
	case h.Keyword != "" && len(h.Suggest) > 0:
		m.replaceOrKeep(h, func(m *app, name string) tea.Cmd { return m.renameTech(p, h.Keyword, name) }, func(m *app) { m.ownTechForProject(p, h.Keyword) })
	case h.Keyword != "":
		m.ownTechForProject(p, h.Keyword)
	case len(h.Fix) > 0:
		return m.previewEdit(p.Name, p.Problems, trunc(oneLine("fix for "+h.Field+": "+h.Message), 70), h.Fix, "", nil)
	case len(h.Suggest) > 0:
		old := techOfField(h.Field, techNamesOf(p))
		if old == "" {
			m.note(h.Message)
			return nil
		}
		m.replaceOrKeep(h, func(m *app, name string) tea.Cmd { return m.renameTech(p, old, name) }, nil)
	case h.Field == "since":
		m.promptSince(p)
	case strings.HasSuffix(h.Field, ".version"):
		if old := techOfField(h.Field, techNamesOf(p)); old != "" {
			m.promptTechVersion(p, old)
		}
	case strings.HasPrefix(h.Field, "lockfiles"):
		m.startLockPath(p.Name)
	default:
		m.note(h.Message)
	}
	return nil
}

func techNamesOf(p projectRow) []string {
	var out []string
	for _, t := range p.Techs {
		out = append(out, t.Name)
	}
	return out
}

var techFieldRE = regexp.MustCompile(`^techs\[(\d+)\]`)

// techOfField is the technology a field such as techs[2].version points at.
func techOfField(field string, names []string) string {
	m := techFieldRE.FindStringSubmatch(field)
	if m == nil {
		return ""
	}
	if i, err := strconv.Atoi(m[1]); err == nil && i < len(names) {
		return names[i]
	}
	return ""
}

// renameTech previews the project using another catalog name for a technology.
func (m *app) renameTech(p projectRow, old, to string) tea.Cmd {
	edits := []projectfile.Op{{Kind: "remove_tech", Tech: old}}
	label := fmt.Sprintf("use technology name %q instead of %q", to, old)
	if p.techNamed(to) == "" {
		edits = append(edits, projectfile.Op{Kind: "set_tech", Tech: to, Version: p.techVersion(old)})
	} else {
		label = fmt.Sprintf("remove technology %q, %q is already listed", old, to)
	}
	return m.previewEdit(p.Name, p.Problems, label, edits, "", nil)
}

// replaceOrKeep offers the close names of a hint instead of the word and, with keep, the word as an own keyword
func (m *app) replaceOrKeep(h projectfile.Hint, use func(m *app, name string) tea.Cmd, keep func(m *app)) {
	pk := &picker{title: "Instead of " + oneLine(h.Keyword), hint: "enter chooses; esc leaves everything as it is", crumb: "replace"}
	if keep == nil {
		pk.title = "More specific than " + oneLine(techFieldOr(h))
	}
	for _, name := range h.Suggest {
		pk.items = append(pk.items, pickItem{value: "use:" + name, label: "use " + oneLine(name)})
	}
	if keep != nil {
		pk.items = append(pk.items, pickItem{value: "own", label: "keep " + oneLine(h.Keyword) + " as my own keyword", detail: "asks for more keywords and a category"})
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		if name, ok := strings.CutPrefix(vals[0], "use:"); ok {
			return use(m, name)
		}
		keep(m)
		return nil
	}
	m.choose(pk)
}

func techFieldOr(h projectfile.Hint) string {
	if h.Keyword != "" {
		return h.Keyword
	}
	return h.Field
}

// ---- in the project form ----

func (m *app) applyHintForm(h projectfile.Hint) tea.Cmd {
	f := m.frm
	names := func() []string { // the hints count the technologies in the order of the file the preview made
		var out []string
		if f.prev != nil {
			for _, t := range f.prev.Result.Techs {
				out = append(out, t.Name)
			}
		}
		return out
	}
	replace := func(m *app, old, name string) tea.Cmd {
		if err := f.flow.ReplaceTech(old, name); err != nil {
			m.fail(err.Error())
			return nil
		}
		f.touched = true
		f.step = f.flow.Current()
		m.say("using " + oneLine(name) + " instead of " + oneLine(old))
		return f.enter(m)
	}
	switch {
	case h.Keyword != "" && len(h.Suggest) > 0:
		m.replaceOrKeep(h, func(m *app, name string) tea.Cmd { return replace(m, h.Keyword, name) }, func(m *app) { m.ownTechForForm(h.Keyword) })
	case h.Keyword != "":
		m.ownTechForForm(h.Keyword)
	case len(h.Suggest) > 0:
		old := techOfField(h.Field, names())
		if old == "" {
			return m.hintSection(h)
		}
		m.replaceOrKeep(h, func(m *app, name string) tea.Cmd { return replace(m, old, name) }, nil)
	default:
		return m.hintSection(h)
	}
	return nil
}

// hintSection goes to the step of the form that settles what the hint is about.
func (m *app) hintSection(h projectfile.Hint) tea.Cmd {
	f := m.frm
	id := ""
	switch {
	case h.Field == "envs" || strings.HasPrefix(h.Field, "envs"):
		id = "envs"
	case strings.HasPrefix(h.Field, "lockfiles"):
		return m.formLockPrompt() // the step lists lockfiles only when there are some
	case strings.HasSuffix(h.Field, ".version") || strings.HasPrefix(h.Field, "environments"):
		id = "versions"
	case strings.HasPrefix(h.Field, "techs"):
		id = "techs"
	}
	if id == "" {
		m.note(h.Field + " is set once the project is saved: Projects, c, " + h.Field)
		return nil
	}
	if err := f.flow.Revisit(id); err != nil {
		m.note(oneLine(h.Message))
		return nil
	}
	f.load()
	return f.enter(m)
}

func (m *app) ownTechForForm(term string) {
	m.ownTechPrompt("Add "+term+" as your own keyword", model.Tech{Name: term}, false, func(m *app, t model.Tech) (tea.Cmd, error) {
		return m.flowOwnTech(term, t)
	})
}

// shortMessage is the first part of a message, up to its first comma or semicolon.
func shortMessage(msg string) string {
	msg = oneLine(msg)
	for _, cut := range []string{", ", "; ", ". ", ": "} {
		if i := strings.Index(msg, cut); i > 12 {
			msg = msg[:i]
		}
	}
	return trunc(msg, 70)
}
