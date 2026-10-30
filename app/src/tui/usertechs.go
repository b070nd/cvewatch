package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// Technologies of the person's own: every way of adding one asks the same questions, here

func splitList(s string) []string {
	var out []string
	for _, w := range strings.Split(s, ",") {
		if w = strings.TrimSpace(w); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// ownTechPrompt asks for a technology of your own; with edit the name is fixed, act gets the answer
func (m *app) ownTechPrompt(title string, t model.Tech, edit bool, act func(m *app, t model.Tech) (tea.Cmd, error)) {
	fields := []field{
		{label: "Name", hint: "what the project lists: lowercase letters, digits, - and _; other characters turn into dashes"},
		{label: "Keywords", hint: "the words advisories are matched on, separated by commas; empty uses the name"},
		{label: "Category", hint: "optional, one of: " + strings.Join(catalog.Categories, ", ")},
		{label: "CPE", hint: "optional vendor:product names from NVD, separated by commas; they let versions be checked"},
	}
	fields[0].in.set(t.Name)
	fields[1].in.set(strings.Join(t.Aliases, ", "))
	fields[2].in.set(t.Category)
	fields[3].in.set(strings.Join(t.CPE, ", "))
	hint := "writes config/techs.yaml; enter goes to the next field, the last one adds it"
	if edit {
		hint = "changes the entry in config/techs.yaml; the name stays"
	}
	m.prm = &prompt{kind: pkTech, title: oneLine(title), hint: hint, fields: fields,
		act: func(m *app, vals []string) (tea.Cmd, error) {
			got := model.Tech{Name: vals[0], Aliases: splitList(vals[1]), Category: vals[2], CPE: splitList(vals[3]), Title: t.Title, Vendor: t.Vendor, Excludes: t.Excludes}
			if got.Name == "" {
				return nil, errors.New("give the technology a name")
			}
			if got.Category != "" && !slices.Contains(catalog.Categories, got.Category) {
				return nil, fmt.Errorf("unknown category %q: use one of %s", got.Category, strings.Join(catalog.Categories, ", "))
			}
			if edit && !strings.EqualFold(got.Name, t.Name) {
				return nil, errors.New("the name cannot be changed here: remove the technology and add it again")
			}
			return act(m, got)
		}}
}

// storable is t as techs.yaml keeps it: a slug for a name, the typed words as default keywords
func storable(t model.Tech) model.Tech {
	typed := strings.TrimSpace(t.Name)
	t.Name = catalog.Slug(typed)
	if len(t.Aliases) == 0 {
		t.Aliases = []string{t.Name}
		if low := strings.ToLower(typed); low != t.Name && !strings.Contains(low, ",") {
			t.Aliases = []string{low, t.Name}
		}
	}
	return t
}

// techAddedMsg is the end of adding a technology to techs.yaml.
type techAddedMsg struct {
	name    string
	project string
	edits   []projectfile.Op // what the project still needs, to name the technology as it is now called
	label   string
	err     error
}

func techAddCmd(b Backend, t model.Tech, project string, edits []projectfile.Op, label string) tea.Cmd {
	return func() tea.Msg {
		err := b.Write(func(s *ops.Session) error {
			_, e := s.AddTech(ops.TechChange{Tech: t, Save: true})
			return e
		})
		return techAddedMsg{name: t.Name, project: project, edits: edits, label: label, err: err}
	}
}

func (m *app) techAdded(msg techAddedMsg) outcome {
	if msg.err != nil {
		return outcome{err: msg.err}
	}
	out := outcome{note: "added " + oneLine(msg.name) + " to techs.yaml; advisories that name its keywords now match it"}
	if len(msg.edits) > 0 {
		var known []projectfile.Issue
		if p, ok := m.selectedProject(); ok && p.Name == msg.project {
			known = p.Problems
		}
		out.then = m.previewEdit(msg.project, known, msg.label, msg.edits, "", nil)
	}
	return out
}

// ownTechForProject adds the technology to techs.yaml at once; a project that spelled it otherwise then previews the rename
func (m *app) ownTechForProject(p projectRow, term string) {
	m.ownTechPrompt("Add "+term+" as your own keyword", model.Tech{Name: term}, false, func(m *app, t model.Tech) (tea.Cmd, error) {
		t = storable(t)
		if err := catalog.CheckName(t.Name); err != nil {
			return nil, err
		}
		var edits []projectfile.Op
		label := ""
		if listed := p.techNamed(term); listed != "" && listed != t.Name {
			edits = []projectfile.Op{{Kind: "remove_tech", Tech: listed}}
			if p.techNamed(t.Name) == "" {
				edits = append(edits, projectfile.Op{Kind: "set_tech", Tech: t.Name, Version: p.techVersion(listed)})
			}
			label = fmt.Sprintf("use technology name %q instead of %q", t.Name, listed)
		}
		return m.start("saving...", "tech "+t.Name, reList, m.prm, techAddCmd(m.b, t, p.Name, edits, label)), nil
	})
}

// techNamed is the spelling the project uses for a technology, "" when it has none called so.
func (p projectRow) techNamed(name string) string {
	for _, t := range p.Techs {
		if strings.EqualFold(t.Name, name) {
			return t.Name
		}
	}
	return ""
}

// fieldOwnTech is K: an own technology added to techs.yaml and the project in one previewed change
func (m *app) fieldOwnTech() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok || ed.open != fldTechs {
		return nil
	}
	m.ownTechPrompt("Add your own technology to "+p.Name, model.Tech{}, false, func(m *app, t model.Tech) (tea.Cmd, error) {
		t = storable(t)
		if err := catalog.CheckName(t.Name); err != nil {
			return nil, err
		}
		if p.techNamed(t.Name) != "" {
			return nil, fmt.Errorf("%s is already in the project", t.Name)
		}
		edits := []projectfile.Op{{Kind: "set_tech", Tech: t.Name}}
		return m.previewEditTechs(p.Name, p.Problems, "add your own technology "+t.Name, edits, []model.Tech{t}, m.prm), nil
	})
	return nil
}

// previewEditTechs is previewEdit for a change that also adds technologies to techs.yaml
func (m *app) previewEditTechs(project string, known []projectfile.Issue, label string, edits []projectfile.Op, techs []model.Tech, prm *prompt) tea.Cmd {
	fx := &fixState{project: project, fix: projectfile.Fix{Label: label, Ops: edits}, seq: 1, vp: scrolling(), edit: true, techs: techs}
	seen := map[string]bool{}
	for _, i := range known {
		seen[problemID(i)] = true
	}
	return m.start("checking...", "edit "+project, 0, prm, editCheckCmd(m.b, fx, project, edits, seen))
}

func canOwnTech(m *app) bool {
	_, ed, ok := m.fieldCtx()
	return ok && ed.open == fldTechs
}

// ---- the Settings screen ----

func isTechList(n setNode) bool { return n.f.Doc == confdoc.KindTechs && n.f.Path == "techs" }

// onTechItem is whether the cursor is on one of the technologies of techs.yaml.
func onTechItem(m *app) bool {
	r, ok := m.set.row()
	return ok && r.kind == rowItem && r.doc == confdoc.IDTechs && len(r.segs) == 2 && r.segs[0] == "techs"
}

// setTechAdd asks for a technology of your own and shows the change to techs.yaml.
func (m *app) setTechAdd() tea.Cmd {
	m.ownTechPrompt("Add a technology of your own", model.Tech{}, false, func(m *app, t model.Tech) (tea.Cmd, error) {
		t = storable(t)
		return m.previewTech("add "+t.Name+" to Technologies", func(ss *ops.SettingsSession, save bool) (ops.SettingsPreview, error) {
			return ss.AddTech(ops.TechChange{Tech: t, Save: save})
		}), nil
	})
	return nil
}

func (m *app) setTechRemove() tea.Cmd {
	r, _ := m.set.row()
	name := itemName(r.segs[1])
	return m.previewTech("remove "+oneLine(name)+" from Technologies", func(ss *ops.SettingsSession, save bool) (ops.SettingsPreview, error) {
		return ss.RemoveTech(ops.TechChange{Tech: model.Tech{Name: name}, Save: save})
	})
}

type techLoadedMsg struct {
	tech model.Tech
	err  error
}

// setTechEdit reads the entry, then asks for its keywords, category and CPE.
func (m *app) setTechEdit() tea.Cmd {
	r, _ := m.set.row()
	if !m.setMayEdit() || !m.setDocOK(r.doc) {
		return nil
	}
	name, b := itemName(r.segs[1]), m.b
	return m.start("reading...", "tech "+name, 0, nil, func() tea.Msg {
		var out techLoadedMsg
		out.err = b.Settings(func(ss *ops.SettingsSession) error {
			mine, err := ss.UserTechs()
			if err != nil {
				return err
			}
			for _, t := range mine {
				if strings.EqualFold(t.Name, name) {
					out.tech = t
					return nil
				}
			}
			return fmt.Errorf("%s is not one of your technologies", name)
		})
		return out
	})
}

func (m *app) techLoaded(msg techLoadedMsg) outcome {
	if msg.err != nil {
		return outcome{err: msg.err}
	}
	m.ownTechPrompt("Change "+msg.tech.Name, msg.tech, true, func(m *app, t model.Tech) (tea.Cmd, error) {
		t.Name = msg.tech.Name
		return m.previewTech("change "+t.Name+" in Technologies", func(ss *ops.SettingsSession, save bool) (ops.SettingsPreview, error) {
			return ss.EditTech(ops.TechChange{Tech: t, Save: save})
		}), nil
	})
	return outcome{}
}

// previewTech shows a change to techs.yaml that ops makes, for saving.
func (m *app) previewTech(label string, run func(ss *ops.SettingsSession, save bool) (ops.SettingsPreview, error)) tea.Cmd {
	rv := &setReview{label: label, crumb: "Technologies", run: run, vp: scrolling()}
	return m.start("checking...", "settings", 0, m.prm, settingsPreviewCmd(m.b, rv, nil))
}
