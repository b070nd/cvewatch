package tui

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// OpKinds are the kinds of project file edit the TUI's field editor builds,
// for the test that keeps the front ends in step with projectfile.
var OpKinds = []string{
	"set_envs", "set_tech", "remove_tech", "set_env_tech", "remove_env_tech",
	"set_image", "add_lockfile", "remove_lockfile", "set_lockfile_dev", "set_since",
	"add_env", "remove_env", "rename_env",
}

// landing is where the Projects screen settles once the snapshot that follows
// a change is in: on the project the change made or renamed, at the level it
// was started from.
type landing struct {
	project string
	deep    bool
}

// landOn puts the screen on l, or on the list when the project is gone.
func (m *app) landOn(l landing) {
	m.prj.fix, m.prj.life, m.prj.ed, m.prj.deep = nil, nil, nil, false
	m.prj.sec.focus = false
	for i, p := range m.data.Projects {
		if p.Name == l.project {
			before := m.prj.proj.id()
			m.prj.proj.to(i)
			m.refitProjects(before)
			m.prj.deep = l.deep && p.Broken == "" && !p.Disabled
		}
	}
}

// settle is what follows the save of a change that made a project.
func (fx *fixState) settle(m *app) tea.Cmd {
	if fx.land == "" {
		return nil
	}
	return loadLandCmd(m.b, &landing{project: fx.land})
}

// The fields of a project file the editor changes.
const (
	fldEnvs     = "envs"
	fldTechs    = "techs"
	fldLocks    = "locks"
	fldVersions = "versions"
	fldImages   = "images"
	fldSince    = "since"
)

var fieldLabels = map[string]string{
	fldEnvs: "Environments", fldTechs: "Technologies", fldLocks: "Lockfiles",
	fldVersions: "Versions per environment", fldImages: "Image per environment", fldSince: "Since",
}

var fieldHeads = map[string][]string{
	"":          {"FIELD", "VALUE"},
	fldEnvs:     {"ENVIRONMENT", "USED BY"},
	fldTechs:    {"TECHNOLOGY", "VERSION"},
	fldLocks:    {"TYPE", "PATH", "ENV", "DEV"},
	fldVersions: {"ENV", "TECHNOLOGY", "DEPLOYED", "PROJECT"},
	fldImages:   {"ENV", "IMAGE"},
}

var fieldHints = map[string]string{
	"":          "enter changes a field or opens its list; every change is previewed before it is saved",
	fldEnvs:     "enter or r renames (its findings move along), + adds an environment, - or x removes it (after asking); the names are free",
	fldTechs:    "enter changes the version, + adds a technology, - or x removes it (after asking)",
	fldLocks:    "enter or d toggles dev (development packages count in every environment), + adds a lockfile by its file, - or x removes it (after asking)",
	fldVersions: "enter sets the version deployed in that environment (empty removes it), - or x removes the override",
	fldImages:   "enter sets the image tag or digest of the environment (empty clears it), - or x clears it",
}

// fieldRow is one row of the field list or of the list inside a field.
type fieldRow struct {
	id    string
	name  string // what the breadcrumb calls it
	cells []string
	add   bool // the row that adds an item
	set   bool // there is a value to remove
	tech  string
	env   model.Env
	lock  model.Lockfile
}

// fieldEditor is the project level with the focus on its fields: the list of
// fields, and inside one of them the list of its items.
type fieldEditor struct {
	project string
	top     viewport
	sub     viewport
	open    string // the field whose items are listed, "" for the list of fields
	pick    *picker
}

func (ed *fieldEditor) cur() *viewport {
	if ed.open == "" {
		return &ed.top
	}
	return &ed.sub
}

// techNames are the technologies of the project, then those only an
// environment pins a version for.
func (p projectRow) techNames() []string {
	var out, extra []string
	for _, t := range p.Techs {
		if !slices.Contains(out, t.Name) {
			out = append(out, t.Name)
		}
	}
	for _, ec := range p.Environments {
		for name := range ec.Techs {
			if !slices.Contains(out, name) && !slices.Contains(extra, name) {
				extra = append(extra, name)
			}
		}
	}
	slices.Sort(extra)
	return append(out, extra...)
}

func (p projectRow) techVersion(name string) string {
	for _, t := range p.Techs {
		if t.Name == name {
			return t.Version
		}
	}
	return ""
}

// lockfiles are the project's lockfiles as the file spells them.
func (p projectRow) lockfiles() []ops.LockEntry {
	if p.HasFile {
		return p.Written
	}
	return p.Lockfiles
}

func (p projectRow) lockID(l ops.LockEntry) string {
	return "lock:" + l.Type + "|" + l.Path + "|" + l.Env
}

// topRows are the fields, each with what it holds.
func topRows(p projectRow) []fieldRow {
	versions, images := 0, []string{}
	for _, env := range slices.SortedFunc(maps.Keys(p.Environments), model.EnvCompare) {
		versions += len(p.Environments[env].Techs)
		if img := p.Environments[env].Image; img != "" {
			images = append(images, string(env)+": "+img)
		}
	}
	locks := plural(len(p.lockfiles()), "lockfile", "lockfiles")
	if len(p.lockfiles()) == 0 {
		locks = "none"
	}
	vs := "none set"
	if versions > 0 {
		vs = plural(versions, "version", "versions") + " set"
	}
	img := "none set"
	if len(images) > 0 {
		img = strings.Join(images, ", ")
	}
	since := "not set"
	if p.Since != "" {
		since = p.Since
	}
	row := func(id, value string) fieldRow { return fieldRow{id: id, cells: []string{fieldLabels[id], value}} }
	return []fieldRow{
		row(fldEnvs, envList(p)), row(fldTechs, techList(p)), row(fldLocks, locks),
		row(fldVersions, vs), row(fldImages, img), row(fldSince, since),
	}
}

// envList is the environments as the field list shows them; a file without
// envs says so, since the names then come from the old default.
func envList(p projectRow) string {
	if p.EnvsUnset {
		return "not set (old default: " + strings.Join(p.Envs, ", ") + ")"
	}
	return strings.Join(p.Envs, ", ")
}

// envUse says what in the file hangs on an environment, so that removing or
// renaming it is no surprise.
func envUse(p projectRow, env model.Env) string {
	var parts []string
	if n := len(p.Environments[env].Techs); n > 0 {
		parts = append(parts, plural(n, "version", "versions"))
	}
	if p.Environments[env].Image != "" {
		parts = append(parts, "image")
	}
	n := 0
	for _, l := range p.lockfiles() {
		if l.Env == string(env) {
			n++
		}
	}
	if n > 0 {
		parts = append(parts, plural(n, "lockfile", "lockfiles"))
	}
	return orDash(strings.Join(parts, ", "))
}

// subRows are the items of one field.
func subRows(p projectRow, field string) []fieldRow {
	var out []fieldRow
	switch field {
	case fldEnvs:
		for _, e := range p.Envs {
			out = append(out, fieldRow{id: "env:" + e, name: e, cells: []string{oneLine(e), envUse(p, model.Env(e))}, env: model.Env(e), set: true})
		}
		out = append(out, fieldRow{id: "+", name: "add an environment", cells: []string{"+ add an environment"}, add: true})
	case fldTechs:
		for _, t := range p.Techs {
			out = append(out, fieldRow{id: "tech:" + t.Name, name: t.Name, cells: []string{oneLine(t.Name), orDash(oneLine(t.Version))}, tech: t.Name, set: true})
		}
		out = append(out, fieldRow{id: "+", name: "add a technology", cells: []string{"+ add a technology"}, add: true})
	case fldLocks:
		for _, l := range p.lockfiles() {
			dev := "-"
			if l.Dev {
				dev = "dev"
			}
			out = append(out, fieldRow{id: p.lockID(l), name: l.Path, cells: []string{oneLine(l.Type), oneLine(l.Path), orDash(oneLine(l.Env)), dev}, set: true,
				lock: model.Lockfile{Type: l.Type, Path: l.Path, Env: model.Env(l.Env), Dev: l.Dev}})
		}
		out = append(out, fieldRow{id: "+", name: "add a lockfile", cells: []string{"+ add a lockfile"}, add: true})
	case fldVersions:
		for _, e := range p.Envs {
			env := model.Env(e)
			for _, name := range p.techNames() {
				dep := p.Environments[env].Techs[name]
				out = append(out, fieldRow{id: "ver:" + e + ":" + name, name: e + " " + name, cells: []string{e, oneLine(name), orDash(oneLine(dep)), orDash(oneLine(p.techVersion(name)))},
					env: env, tech: name, set: dep != ""})
			}
		}
	case fldImages:
		for _, e := range p.Envs {
			env := model.Env(e)
			img := p.Environments[env].Image
			out = append(out, fieldRow{id: "img:" + e, name: e, cells: []string{e, orDash(oneLine(img))}, env: env, set: img != ""})
		}
	}
	return out
}

func (ed *fieldEditor) rows(p projectRow) []fieldRow {
	if ed.open == "" {
		return topRows(p)
	}
	return subRows(p, ed.open)
}

// row is the row under the cursor.
func (ed *fieldEditor) row(p projectRow) (fieldRow, bool) {
	rows := ed.rows(p)
	if i := ed.cur().at(); i >= 0 && i < len(rows) {
		return rows[i], true
	}
	return fieldRow{}, false
}

// fieldHead is the number of lines above the first row: title, hint, column heads.
const fieldHead = 3

func (ed *fieldEditor) layout(p projectRow, w, h int) {
	rows := subRows(p, ed.open)
	ed.sub.refit(len(rows), func(i int) string { return rows[i].id })
	room := max(h-fieldHead-2, 1)
	ed.top.fit(room)
	ed.sub.fit(room)
	if ed.pick != nil {
		ed.pick.vp.fit(max(h-pickHead-2, 1))
	}
}

// table draws rows under heads, the cursor row marked; the last column takes
// what the others leave.
func table(heads []string, rows []fieldRow, vp *viewport, w, room int) []string {
	widths := make([]int, len(heads))
	for i, h := range heads {
		widths[i] = width(h)
	}
	for _, r := range rows {
		if r.add {
			continue
		}
		for i, c := range r.cells {
			if i < len(widths)-1 {
				widths[i] = max(widths[i], min(width(c), 30))
			}
		}
	}
	line := func(cells []string) string {
		var b strings.Builder
		used := 2
		for i, c := range cells {
			if i == len(widths)-1 {
				b.WriteString(trunc(c, max(w-used, 1)))
				break
			}
			b.WriteString(pad(c, widths[i]) + " ")
			used += widths[i] + 1
		}
		return strings.TrimRight(b.String(), " ")
	}
	out := []string{stHead.Render(trunc("  "+line(heads), w))}
	start, end := vp.window(room)
	for i := start; i < end; i++ {
		cells := rows[i].cells
		if rows[i].add {
			cells = cells[:1]
		}
		text := line(cells)
		if rows[i].add {
			text = cells[0]
		}
		if i == vp.at() {
			out = append(out, stSel.Render(pad("> "+text, w)))
		} else {
			out = append(out, trunc("  "+text, w))
		}
	}
	return out
}

func (ed *fieldEditor) title(p projectRow) string {
	if ed.open == "" {
		return "Edit fields of " + oneLine(p.Name)
	}
	return "Edit " + strings.ToLower(fieldLabels[ed.open]) + " of " + oneLine(p.Name)
}

func (ed *fieldEditor) hint(p projectRow) string {
	if ed.open == fldEnvs && p.EnvsUnset {
		return "envs is not set, so the old default counts; f writes it into the file or picks local; the other keys edit it (the first edit writes the list)"
	}
	return fieldHints[ed.open]
}

// view draws the field list, or the items of the open field.
func (ed *fieldEditor) view(p projectRow, w, h int) []string {
	room := max(h-fieldHead-2, 1)
	rows := ed.rows(p)
	out := []string{stBold.Render(trunc(ed.title(p), w)), stMuted.Render(trunc(ed.hint(p), w))}
	if len(rows) == 0 {
		out = append(out, stHead.Render(trunc("  "+strings.Join(fieldHeads[ed.open], " "), w)))
		return append(out, stMuted.Render("  nothing to list: add a technology to the project first"))
	}
	out = append(out, table(fieldHeads[ed.open], rows, ed.cur(), w, room)...)
	if n := len(p.Problems); n > 0 {
		out = append(out, "", stMuted.Render(trunc(fmt.Sprintf("the file has %s; esc goes back to them", plural(n, "problem", "problems")), w)))
	}
	return out
}

// ---- opening and leaving ----

// openFields puts the focus on the fields of the selected project.
func (m *app) openFields() tea.Cmd {
	p, ok := m.selectedProject()
	switch {
	case !ok:
	case p.Broken != "":
		m.fail("the file of " + p.Name + " does not load; press E to edit it")
	case p.Disabled:
		m.fail(p.Name + " is disabled; press Z to enable it before editing it")
	case !p.HasFile:
		m.fail("project " + p.Name + " has no file under config/projects")
	default:
		m.prj.deep = true
		m.prj.ed = &fieldEditor{project: p.Name}
		m.prj.ed.top.reset(len(topRows(p)))
	}
	return nil
}

func (m *app) fieldCtx() (projectRow, *fieldEditor, bool) {
	p, ok := m.selectedProject()
	ed := m.prj.ed
	return p, ed, ok && ed != nil && p.Name == ed.project
}

func (m *app) closeFields() tea.Cmd { m.prj.ed = nil; return nil }

func (m *app) closeFieldList() tea.Cmd {
	if ed := m.prj.ed; ed != nil {
		ed.open = ""
	}
	return nil
}

// clickField selects the row drawn on the given body line; a second click on it opens it.
func (m *app) clickField(line int) tea.Cmd {
	_, ed, ok := m.fieldCtx()
	if !ok {
		return nil
	}
	i := rowAt(ed.cur(), line-fieldHead)
	switch {
	case i < 0:
		return nil
	case i == ed.cur().at():
		return m.fieldOpen()
	}
	ed.cur().to(i)
	return nil
}

// fieldOpen is enter: change the field, open its list, or change the item.
func (m *app) fieldOpen() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok {
		return nil
	}
	row, ok := ed.row(p)
	if !ok {
		return nil
	}
	if ed.open == "" {
		switch row.id {
		case fldSince:
			m.promptSince(p)
		default:
			ed.open = row.id
			ed.sub.reset(len(subRows(p, row.id)))
		}
		return nil
	}
	switch ed.open {
	case fldEnvs:
		if row.add {
			m.promptAddEnv(p)
		} else {
			m.promptRenameEnv(p, row.env)
		}
	case fldTechs:
		if row.add {
			m.promptAddTech(p)
		} else {
			m.promptTechVersion(p, row.tech)
		}
	case fldLocks:
		if row.add {
			m.startLockPath(p.Name)
		} else {
			return m.fieldDev()
		}
	case fldVersions:
		m.promptEnvVersion(p, row)
	case fldImages:
		m.promptImage(p, row)
	}
	return nil
}

func (m *app) fieldAdd() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok {
		return nil
	}
	switch ed.open {
	case fldEnvs:
		m.promptAddEnv(p)
	case fldTechs:
		m.promptAddTech(p)
	case fldLocks:
		m.startLockPath(p.Name)
	}
	return nil
}

// fieldRename is r on an environment.
func (m *app) fieldRename() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok || ed.open != fldEnvs {
		return nil
	}
	if row, ok := ed.row(p); ok && !row.add {
		m.promptRenameEnv(p, row.env)
	}
	return nil
}

// fieldEnvsFix is f on a project without envs: write the old default into the
// file, or start from local.
func (m *app) fieldEnvsFix() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok || ed.open != fldEnvs || !p.EnvsUnset {
		return nil
	}
	pk := &picker{title: "Environments of " + oneLine(p.Name), hint: "the file has no envs; enter chooses, esc leaves it as it is", crumb: "environments",
		items: []pickItem{
			{value: "keep", label: "Keep the old default", detail: "write " + strings.Join(p.Envs, ", ") + " into the file"},
			{value: "local", label: "Only local", detail: "the project runs in local alone; add prod and others later"},
		}}
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		envs, label := slices.Clone(model.LegacyEnvs), "write the old default environments into the file"
		if vals[0] == "local" {
			envs, label = []model.Env{model.EnvLocal}, "set environments to local"
		}
		return m.previewEdit(p.Name, p.Problems, label, []projectfile.Op{{Kind: "set_envs", Envs: envs}}, "", nil)
	}
	m.choose(pk)
	return nil
}

// fieldDev flips the dev flag of the selected lockfile.
func (m *app) fieldDev() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok || ed.open != fldLocks {
		return nil
	}
	row, ok := ed.row(p)
	if !ok || row.add {
		return nil
	}
	l := row.lock
	l.Dev = !l.Dev
	label := "mark lockfile " + oneLine(l.Path) + " as a dev lockfile"
	if !l.Dev {
		label = "mark lockfile " + oneLine(l.Path) + " as not dev"
	}
	return m.previewEdit(p.Name, p.Problems, label, []projectfile.Op{{Kind: "set_lockfile_dev", Lockfile: l}}, "", nil)
}

// fieldRemove removes the selected item.
func (m *app) fieldRemove() tea.Cmd {
	p, ed, ok := m.fieldCtx()
	if !ok {
		return nil
	}
	row, ok := ed.row(p)
	if !ok || row.add || !row.set {
		m.fail("nothing to remove here")
		return nil
	}
	var label, ask string
	var op projectfile.Op
	switch ed.open {
	case fldEnvs:
		if len(p.Envs) == 1 {
			m.fail("a project needs at least one environment: add another before removing " + oneLine(row.name))
			return nil
		}
		label, op = "remove environment "+oneLine(row.name), projectfile.Op{Kind: "remove_env", Env: row.env}
		ask = "Remove environment " + oneLine(row.name) + " from " + oneLine(p.Name) + "? Versions and lockfiles that name it stay and are reported."
	case fldTechs:
		label, op = "remove technology "+oneLine(row.tech), projectfile.Op{Kind: "remove_tech", Tech: row.tech}
		ask = "Remove technology " + oneLine(row.tech) + " from " + oneLine(p.Name) + "?"
	case fldLocks:
		label, op = "remove lockfile "+oneLine(row.lock.Path), projectfile.Op{Kind: "remove_lockfile", Lockfile: row.lock}
		ask = "Remove lockfile " + oneLine(row.lock.Path) + " from " + oneLine(p.Name) + "?"
	case fldVersions:
		label, op = fmt.Sprintf("remove the %s version of %s", row.env, oneLine(row.tech)), projectfile.Op{Kind: "remove_env_tech", Env: row.env, Tech: row.tech}
		ask = fmt.Sprintf("Remove the %s version of %s from %s?", row.env, oneLine(row.tech), oneLine(p.Name))
	case fldImages:
		label, op = fmt.Sprintf("clear the %s image", row.env), projectfile.Op{Kind: "set_image", Env: row.env}
		ask = fmt.Sprintf("Clear the %s image of %s?", row.env, oneLine(p.Name))
	default:
		return nil
	}
	m.cfm = &confirm{ask: ask, yes: func(m *app) tea.Cmd {
		return m.previewEdit(p.Name, p.Problems, label, []projectfile.Op{op}, "", nil)
	}}
	return nil
}

// ---- the editors ----

// editPrompt opens a prompt whose answers build the ops of one change.
func (m *app) editPrompt(p projectRow, title, hint string, fields []field, build func(vals []string) (string, []projectfile.Op, error)) {
	m.prm = &prompt{kind: pkEdit, title: oneLine(title), hint: hint, fields: fields, project: p.Name, known: p.Problems, build: build}
}

func (m *app) promptSince(p projectRow) {
	f := field{label: "Since"}
	f.in.set(p.Since)
	m.editPrompt(p, "Since date of "+p.Name, "a day, YYYY-MM-DD: vulnerabilities published before it are not checked; empty clears it", []field{f},
		func(v []string) (string, []projectfile.Op, error) {
			label := "set since to " + v[0]
			if v[0] == "" {
				label = "clear since"
			}
			return label, []projectfile.Op{{Kind: "set_since", Since: v[0]}}, nil
		})
}

func (m *app) promptTechVersion(p projectRow, tech string) {
	f := field{label: "Version"}
	f.in.set(p.techVersion(tech))
	m.editPrompt(p, "Version of "+tech+" in "+p.Name, "the version the project runs, such as 8.2; empty leaves the technology without a version", []field{f},
		func(v []string) (string, []projectfile.Op, error) {
			label := fmt.Sprintf("set %s to version %s", tech, v[0])
			if v[0] == "" {
				label = "clear the version of " + tech
			}
			return label, []projectfile.Op{{Kind: "set_tech", Tech: tech, Version: v[0]}}, nil
		})
}

func (m *app) promptAddTech(p projectRow) {
	m.editPrompt(p, "Add a technology to "+p.Name, "a name from the technology catalog, such as php or nginx; the version is optional",
		[]field{{label: "Name"}, {label: "Version"}},
		func(v []string) (string, []projectfile.Op, error) {
			switch {
			case v[0] == "":
				return "", nil, errors.New("give the name of a technology")
			case slices.ContainsFunc(p.Techs, func(t ops.TechPin) bool { return strings.EqualFold(t.Name, v[0]) }):
				return "", nil, fmt.Errorf("%s is already in the project: select it to change its version", v[0])
			}
			label := "add technology " + v[0]
			if v[1] != "" {
				label += " " + v[1]
			}
			return label, []projectfile.Op{{Kind: "set_tech", Tech: v[0], Version: v[1]}}, nil
		})
}

func (m *app) promptEnvVersion(p projectRow, row fieldRow) {
	if row.tech == "" {
		return
	}
	f := field{label: "Deployed"}
	f.in.set(p.Environments[row.env].Techs[row.tech])
	m.editPrompt(p, fmt.Sprintf("Deployed version of %s in %s", row.tech, row.env), "the version running in "+string(row.env)+", such as 8.2.30; empty removes the override", []field{f},
		func(v []string) (string, []projectfile.Op, error) {
			if v[0] == "" {
				if !row.set {
					return "", nil, errors.New("no version is set here; type one")
				}
				return fmt.Sprintf("remove the %s version of %s", row.env, row.tech), []projectfile.Op{{Kind: "remove_env_tech", Env: row.env, Tech: row.tech}}, nil
			}
			return fmt.Sprintf("set %s in %s to %s", row.tech, row.env, v[0]), []projectfile.Op{{Kind: "set_env_tech", Env: row.env, Tech: row.tech, Version: v[0]}}, nil
		})
}

func (m *app) promptImage(p projectRow, row fieldRow) {
	f := field{label: "Image"}
	f.in.set(p.Environments[row.env].Image)
	m.editPrompt(p, fmt.Sprintf("Image of %s in %s", p.Name, row.env), "an image tag or digest, recorded only; empty clears it", []field{f},
		func(v []string) (string, []projectfile.Op, error) {
			label := fmt.Sprintf("set the %s image to %s", row.env, v[0])
			if v[0] == "" {
				label = fmt.Sprintf("clear the %s image", row.env)
			}
			return label, []projectfile.Op{{Kind: "set_image", Env: row.env, Image: v[0]}}, nil
		})
}

// envName reads one environment name as typed: the project file wants it lowercase.
func envName(text string) (model.Env, error) {
	e := model.Env(strings.ToLower(strings.TrimSpace(text)))
	if !e.Valid() {
		return "", fmt.Errorf("%q is not a valid environment name (lowercase letters, digits, - and _, starting with a letter)", oneLine(text))
	}
	return e, nil
}

func (m *app) promptAddEnv(p projectRow) {
	var left []string
	for _, e := range model.SuggestedEnvs {
		if !slices.Contains(p.Envs, string(e)) {
			left = append(left, string(e))
		}
	}
	hint := "local is the default; add prod and others you deploy to; names are free: letters, digits, - and _; several with commas"
	if len(left) > 0 {
		hint = "suggested: " + strings.Join(left, ", ") + "; " + hint
	}
	m.editPrompt(p, "Add an environment to "+p.Name, hint, []field{{label: "Name"}},
		func(v []string) (string, []projectfile.Op, error) {
			var list []projectfile.Op
			var names []string
			for _, tok := range strings.FieldsFunc(v[0], func(r rune) bool { return r == ',' || r == ' ' }) {
				e, err := envName(tok)
				switch {
				case err != nil:
					return "", nil, err
				case slices.Contains(p.Envs, string(e)):
					return "", nil, fmt.Errorf("%s is already an environment of the project", e)
				case slices.Contains(names, string(e)):
					continue
				}
				names = append(names, string(e))
				list = append(list, projectfile.Op{Kind: "add_env", Env: e})
			}
			if len(list) == 0 {
				return "", nil, errors.New("give the name of an environment")
			}
			return "add environment " + strings.Join(names, ", "), list, nil
		})
}

func (m *app) promptRenameEnv(p projectRow, env model.Env) {
	f := field{label: "New name"}
	f.in.set(string(env))
	m.editPrompt(p, fmt.Sprintf("Rename environment %s of %s", env, p.Name), "its findings, versions, image and lockfiles move to the new name; the preview counts the findings", []field{f},
		func(v []string) (string, []projectfile.Op, error) {
			to, err := envName(v[0])
			switch {
			case err != nil:
				return "", nil, err
			case to == env:
				return "", nil, errors.New("that is the name it has: type another")
			case slices.Contains(p.Envs, string(to)):
				return "", nil, fmt.Errorf("%s is already an environment of the project", to)
			}
			return fmt.Sprintf("rename environment %s to %s", env, to), []projectfile.Op{{Kind: "rename_env", Env: env, To: to}}, nil
		})
}

// lockPicked takes the file chosen in the lockfile box: its type comes from
// its name, and a name that tells nothing asks for the type.
func (m *app) lockPicked(p *prompt) tea.Cmd {
	typed := p.box.chosen()
	refuse := func(why string) tea.Cmd { p.problem = why; return nil }
	if typed == "" {
		return refuse("no lockfile given: type the path of a lockfile")
	}
	abs, err := expandTyped(typed)
	if err != nil {
		return refuse(oneLine(err.Error()))
	}
	switch fi, err := os.Stat(abs); {
	case err != nil:
		return refuse("no such file: " + oneLine(typed))
	case fi.IsDir():
		return refuse("that is a folder, not a lockfile: tab opens it, then pick a lockfile")
	case !fi.Mode().IsRegular():
		return refuse("that is not a file")
	}
	m.prm = nil
	if typ, ok := matrix.DetectType(filepath.Base(abs)); ok {
		return m.lockTyped(p.project, abs, typ)
	}
	pk := &picker{title: "Type of " + oneLine(filepath.Base(abs)), hint: "the name does not tell the format, and the format decides how the file is read", crumb: "lockfile type"}
	for _, t := range matrix.Types() {
		pk.items = append(pk.items, pickItem{value: t, label: t})
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		return m.lockTyped(p.project, abs, vals[0])
	}
	m.choose(pk)
	return nil
}

// lockTyped adds the lockfile to the project being set up, or asks for the
// environment and the dev flag of one added to a project file.
func (m *app) lockTyped(project, abs, typ string) tea.Cmd {
	if project == "" {
		return m.addFormLock(typ, abs)
	}
	p, ok := m.selectedProject()
	if !ok || p.Name != project || m.data == nil {
		return nil
	}
	path := relPath(m.data.Root, abs)
	m.editPrompt(p, "Add a "+typ+" lockfile to "+p.Name,
		path+": env empty means every environment; dev is yes or no",
		[]field{{label: "Env"}, {label: "Dev"}},
		func(v []string) (string, []projectfile.Op, error) {
			dev := false
			switch strings.ToLower(v[1]) {
			case "", "n", "no", "false":
			case "y", "yes", "true":
				dev = true
			default:
				return "", nil, errors.New("dev is yes or no")
			}
			l := model.Lockfile{Type: typ, Path: path, Env: model.Env(v[0]), Dev: dev}
			return "add " + typ + " lockfile " + l.Path, []projectfile.Op{{Kind: "add_lockfile", Lockfile: l}}, nil
		})
	return nil
}

// relPath spells a file as the project file does: relative to the config folder.
func relPath(root, p string) string {
	real := func(s string) string {
		if r, err := filepath.EvalSymlinks(s); err == nil {
			return r
		}
		return s
	}
	r, err := filepath.Abs(root)
	if err != nil {
		return filepath.ToSlash(p)
	}
	rel, err := filepath.Rel(real(r), real(p))
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

func (m *app) openPicker(pk *picker) {
	pk.vp.reset(len(pk.items))
	m.prj.ed.pick = pk
}

// ---- the preview of a change ----

type editCheckedMsg struct {
	fx   *fixState
	prev ops.ProjectPreview
	seen map[string]bool // the problems the file had before the change
	err  error
}

func editCheckCmd(b Backend, fx *fixState, project string, edits []projectfile.Op, seen map[string]bool) tea.Cmd {
	techs := fx.techs
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Read(func(s *ops.Session) (e error) {
			p, e = s.EditProject(ops.ProjectChange{Project: project, Ops: edits, NewTechs: techs})
			return e
		})
		return editCheckedMsg{fx: fx, prev: p, seen: seen, err: err}
	}
}

// previewEdit asks ops what the edits would do. If they cannot be applied, or
// make the file worse than it was, the prompt that asked stays open with its
// text and the reason; otherwise the change is shown for saving.
func (m *app) previewEdit(project string, known []projectfile.Issue, label string, edits []projectfile.Op, land string, prm *prompt) tea.Cmd {
	fx := &fixState{project: project, fix: projectfile.Fix{Label: label, Ops: edits}, seq: 1, vp: scrolling(), edit: true, land: land}
	seen := map[string]bool{}
	for _, i := range known {
		seen[problemID(i)] = true
	}
	return m.start("checking...", "edit "+project, 0, prm, editCheckCmd(m.b, fx, project, edits, seen))
}

func (m *app) editChecked(msg editCheckedMsg) outcome {
	if msg.err != nil {
		return outcome{err: msg.err}
	}
	for _, is := range msg.prev.Issues {
		if is.Level == "error" && !msg.seen[problemID(is)] {
			return outcome{err: fmt.Errorf("%s: %s", is.Field, is.Message)}
		}
	}
	p := msg.prev
	msg.fx.prev = &p
	m.prj.fix = msg.fx
	if m.prj.ed != nil {
		m.prj.ed.pick = nil // the choice is made; esc from the preview comes back to the list
	}
	return outcome{}
}

// submitNew previews a new project with no folder scanned: a name, and
// optionally the environments it runs in.
func (m *app) submitNew(p *prompt, name, envText string) tea.Cmd {
	if name == "" {
		p.problem = "give the project a name"
		return nil
	}
	if m.data != nil && slices.ContainsFunc(m.data.Projects, func(r projectRow) bool { return r.Name == name }) {
		p.problem = fmt.Sprintf("a project named %q already exists", name)
		return nil
	}
	var edits []projectfile.Op
	if envs := strings.FieldsFunc(envText, func(r rune) bool { return r == ',' || r == ' ' }); len(envs) > 0 {
		var es []model.Env
		for _, e := range envs {
			if !model.Env(e).Valid() {
				p.problem = fmt.Sprintf("%q is not a valid environment name (lowercase letters, digits, - and _)", e)
				return nil
			}
			es = append(es, model.Env(e))
		}
		edits = append(edits, projectfile.Op{Kind: "set_envs", Envs: es})
	} else {
		edits = append(edits, projectfile.Op{Kind: "set_envs", Envs: []model.Env{model.EnvLocal}})
	}
	return m.previewEdit(name, nil, "create project "+name, edits, name, p)
}
