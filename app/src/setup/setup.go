// Package setup is the one module behind every setup front end (a prompt
// wizard, a TUI, an MCP agent). It owns the questions, their order, defaults,
// validation and the translation of the answers into project-file edits. A
// front end renders the current Step and passes an answer back; it never
// decides what to ask next. The package does no terminal I/O, writes no files
// and uses no network: saving is the caller's job, with the Ops returned here.
package setup

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// Kind is the shape of an answer.
type Kind string

const (
	KindText    Kind = "text"    // free text, may be empty
	KindChoice  Kind = "choice"  // one option value
	KindMulti   Kind = "multi"   // option values joined by ","; empty means none
	KindConfirm Kind = "confirm" // "yes" or "no"
)

// maxText bounds every answer: they come from terminals and agents.
const maxText = 200

// Option is one choice. Detail carries evidence, as plain text.
type Option struct {
	Value, Label, Detail string
	Selected             bool
}

// Step is one question.
type Step struct {
	ID, Title, Help string
	Kind            Kind
	Options         []Option
	Default         string // text or choice value
	Problem         string // why the last answer was rejected, empty otherwise
}

// Draft is the state being edited.
type Draft struct {
	Project  model.Project
	Existing *model.Project // nil when creating
	Dir      string         // repository folder, may be empty
	Evidence map[string][]discovery.Evidence
}

// discovered is a lockfile a scan found, with its absolute path.
type discovered struct {
	lf   model.Lockfile
	pkgs int
}

// Flow walks the questions. Create one with NewFlow.
type Flow struct {
	// NameTaken, when set, rejects project names that already exist.
	NameTaken func(string) bool

	cat      *catalog.Catalog
	draft    model.Project
	existing *model.Project
	dir      string
	evidence map[string][]discovery.Evidence
	props    []discovery.TechProposal // every proposal, one per tech
	locks    []discovered
	notes    []string
	src      []byte // existing file text, for Review

	hist       []string // step ids; the last one is current
	problem    string
	done       bool
	asked      map[string]bool // versions asked in this pass, by lowercase tech
	versionAll bool            // ask every tech, not only those without a version
	revisit    string          // the section being changed from the review; the flow returns to the review after it
	added      []string        // techs added by name, for the help text
	differing  []model.Env     // the environments whose differences are being asked, in order

	base   *catalog.Catalog // the catalog as given; cat adds the staged custom techs to it
	custom []model.Tech     // techs of the person's own, staged until the project is saved
	own    []string         // names already in the person's techs.yaml
}

// NewFlow starts a flow with an empty draft. existing is copied; nil means create.
func NewFlow(cat *catalog.Catalog, existing *model.Project) *Flow {
	if cat == nil {
		cat = catalog.New(nil)
	}
	f := &Flow{cat: cat, base: cat, evidence: map[string][]discovery.Evidence{}, asked: map[string]bool{}}
	first := "name"
	if existing != nil {
		p := cloneProject(*existing)
		f.existing, f.draft = &p, cloneProject(*existing)
		first = "menu"
	} else {
		f.draft.Envs = []model.Env{model.EnvLocal}
	}
	f.hist = []string{first}
	return f
}

// SetExistingBytes gives Review the text of the file being edited.
func (f *Flow) SetExistingBytes(b []byte) { f.src = slices.Clone(b) }

// UseDiscovery merges a scan: High and Medium techs join the draft (never
// changing the version of one already there), Low ones are only offered.
// Lockfile paths are stored absolute (dir joined); the caller relativises.
func (f *Flow) UseDiscovery(dir string, res discovery.Result) {
	f.dir = dir
	for _, p := range res.Techs {
		if !plainName(p.Tech) {
			continue
		}
		low := strings.ToLower(p.Tech)
		f.evidence[low] = append(f.evidence[low], p.Evidence...)
		i := slices.IndexFunc(f.props, func(q discovery.TechProposal) bool { return strings.EqualFold(q.Tech, p.Tech) })
		switch {
		case i < 0:
			f.props = append(f.props, p)
		case rank(p.Confidence) > rank(f.props[i].Confidence):
			f.props[i].Confidence = p.Confidence
			if p.Version != "" {
				f.props[i].Version = p.Version
			}
		}
	}
	for _, p := range f.props {
		if rank(p.Confidence) >= 2 && techIndex(f.draft.Techs, p.Tech) < 0 {
			f.draft.Techs = append(f.draft.Techs, model.ProjectTech{Name: p.Tech, Version: p.Version})
		}
	}
	for _, l := range res.Lockfiles {
		if l.Type == "" || l.Path == "" {
			continue
		}
		path := l.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, filepath.FromSlash(path))
		}
		lf := model.Lockfile{Type: l.Type, Path: path}
		if !slices.ContainsFunc(f.locks, func(d discovered) bool { return f.sameLock(d.lf, lf) }) {
			f.locks = append(f.locks, discovered{lf, l.Packages})
		}
		if f.findLock(lf) < 0 {
			f.draft.Lockfiles = append(f.draft.Lockfiles, lf)
		}
	}
	for _, n := range res.Notes {
		if n = plain(n); n != "" && !slices.Contains(f.notes, n) {
			f.notes = append(f.notes, n)
		}
	}
}

func rank(c discovery.Confidence) int {
	switch c {
	case discovery.High:
		return 3
	case discovery.Medium:
		return 2
	}
	return 1
}

// Current is the step to show now; a finished flow returns Step{ID: "done"}.
func (f *Flow) Current() Step {
	if f.done {
		return Step{ID: "done", Title: "Done"}
	}
	id := f.hist[len(f.hist)-1]
	def, arg := lookup(id)
	st := def.ask(f, arg)
	st.ID, st.Problem = id, f.problem
	return st
}

// Answer checks value against the current step and moves on. A rejected
// answer sets Step.Problem and leaves the flow where it is.
func (f *Flow) Answer(value string) error {
	if f.done {
		return errors.New("setup is finished")
	}
	id := f.hist[len(f.hist)-1]
	def, arg := lookup(id)
	v, err := cleanText(value)
	if err == nil {
		v, err = normalize(def.ask(f, arg), v)
	}
	if err == nil {
		err = def.apply(f, arg, v)
	}
	if err != nil {
		f.problem = err.Error()
		return err
	}
	f.problem = ""
	next := def.next(f, arg, v)
	switch {
	case next == "":
		f.done = true
	case f.revisit != "":
		if !f.inSection(next) {
			next, f.revisit = "review", ""
		}
		f.hist = append(f.hist, next) // a plain path: Back retraces it
	default:
		f.goTo(next)
	}
	return nil
}

// Back returns to the previous step. Answers already given are kept.
func (f *Flow) Back() {
	f.problem = ""
	if f.done {
		f.done = false
		return
	}
	if len(f.hist) > 1 {
		f.hist = f.hist[:len(f.hist)-1]
	}
	if f.hist[len(f.hist)-1] == "review" {
		f.revisit = ""
	}
}

// Section is a part of the project the review can send the user back to.
type Section struct{ ID, Title string }

// Sections lists what Revisit accepts now.
func (f *Flow) Sections() []Section {
	var out []Section
	if !f.editing() {
		out = append(out, Section{"name", "Project name"})
	}
	out = append(out, Section{"techs", "Technologies"}, Section{"add-techs", "Add technologies by name"})
	if len(f.draft.Techs) > 0 {
		out = append(out, Section{"versions", "Versions"})
	}
	if len(f.lockCands()) > 0 {
		out = append(out, Section{"lockfiles", "Lockfiles"})
	}
	out = append(out, Section{"envs", "Environments"})
	if len(f.draft.EffectiveEnvs()) > 1 {
		out = append(out, Section{"differ", "Differences per environment"})
	}
	return out
}

// Revisit goes from the review to one of its sections. Once that section is
// answered the flow is at the review again, not at the steps after it.
func (f *Flow) Revisit(id string) error {
	if f.done || f.hist[len(f.hist)-1] != "review" {
		return errors.New("only the review can go back to a section")
	}
	if !slices.ContainsFunc(f.Sections(), func(s Section) bool { return s.ID == id }) {
		return fmt.Errorf("no section %q to go back to", id)
	}
	to := id
	if id == "versions" {
		f.startVersions(true)
		to = f.nextVersionID()
	}
	f.problem, f.revisit = "", id
	f.hist = append(f.hist, to)
	return nil
}

// inSection says whether step id still belongs to the section being revisited.
func (f *Flow) inSection(id string) bool {
	base, _, _ := strings.Cut(id, ":")
	switch f.revisit {
	case "techs", "add-techs":
		return base == "add-techs" || base == "version"
	case "versions":
		return base == "version"
	case "envs":
		return base == "envs-other"
	case "differ":
		return strings.HasPrefix(base, "differ") || strings.HasPrefix(base, "diff-")
	}
	return false
}

// Done reports whether the review was confirmed.
func (f *Flow) Done() bool { return f.done }

// Draft returns a copy of the state being edited.
func (f *Flow) Draft() Draft {
	d := Draft{Project: cloneProject(f.draft), Dir: f.dir, Evidence: map[string][]discovery.Evidence{}}
	if f.existing != nil {
		p := cloneProject(*f.existing)
		d.Existing = &p
	}
	for k, v := range f.evidence {
		d.Evidence[k] = slices.Clone(v)
	}
	return d
}

// goTo makes id current. Going to a step already in the history cuts the
// history back to it, so Back never replays a stale path.
func (f *Flow) goTo(id string) {
	if i := slices.Index(f.hist, id); i >= 0 {
		f.hist = f.hist[:i+1]
		return
	}
	f.hist = append(f.hist, id)
}

func (f *Flow) editing() bool { return f.existing != nil }

// ---- step table ----

// stepDef is one kind of step. ask builds the question, apply stores a
// validated answer, next names the step to go to ("" finishes the flow).
// Steps with an argument have ids like "version:php".
type stepDef struct {
	id    string
	ask   func(f *Flow, arg string) Step
	apply func(f *Flow, arg, v string) error
	next  func(f *Flow, arg, v string) string
}

var stepTable = []stepDef{
	{"menu", askMenu, noApply, nextMenu},
	{"name", askName, applyName, func(*Flow, string, string) string { return "techs" }},
	{"techs", askTechs, applyTechs, nextTechs},
	{"add-techs", askAddTechs, applyAddTechs, nextAddTechs},
	{"version", askVersion, applyVersion, nextVersion},
	{"lockfiles", askLockfiles, applyLockfiles, nextLockfiles},
	{"envs", askEnvs, applyEnvs, nextEnvs},
	{"envs-other", askEnvsOther, applyEnvsOther, func(f *Flow, _, _ string) string { return f.afterSection(f.differOrReview()) }},
	{"differ", askDiffer, applyDiffer, nextDiffer},
	{"differ-envs", askDifferEnvs, applyDifferEnvs, nextDifferEnvs},
	{"diff-techs", askDiffTechs, applyDiffTechs, func(f *Flow, env, _ string) string { return f.afterDiffTechs(env) }},
	{"diff-exclude", askDiffExclude, applyDiffExclude, func(_ *Flow, env, _ string) string { return "diff-image:" + env }},
	{"diff-image", askDiffImage, applyDiffImage, func(f *Flow, env, _ string) string { return f.afterDiffEnv(env) }},
	{"review", askReview, noApply, nextReview},
}

func lookup(id string) (stepDef, string) {
	base, arg, _ := strings.Cut(id, ":")
	for _, d := range stepTable {
		if d.id == base {
			return d, arg
		}
	}
	panic("setup: unknown step " + id)
}

func noApply(*Flow, string, string) error { return nil }

// afterSection is where a finished section goes: the menu when editing,
// otherwise the next step of the create path.
func (f *Flow) afterSection(createNext string) string {
	if f.editing() {
		return "menu"
	}
	return createNext
}

// ---- menu (edit mode) ----

func askMenu(f *Flow, _ string) Step {
	opts := []Option{
		{Value: "techs", Label: "Technologies"},
		{Value: "add-techs", Label: "Add technologies by name"},
		{Value: "versions", Label: "Versions"},
	}
	if len(f.lockCands()) > 0 {
		opts = append(opts, Option{Value: "lockfiles", Label: "Lockfiles"})
	}
	opts = append(opts, Option{Value: "envs", Label: "Environments"})
	if len(f.draft.EffectiveEnvs()) > 1 {
		opts = append(opts, Option{Value: "differ", Label: "Differences per environment"})
	}
	opts = append(opts, Option{Value: "review", Label: "Review and save"})
	return Step{Title: "What do you want to change?", Help: "Pick a section. Each one returns here when answered.",
		Kind: KindChoice, Options: opts, Default: "review"}
}

func nextMenu(f *Flow, _, v string) string {
	if v == "versions" {
		f.startVersions(true)
		if n := f.nextVersionID(); n != "" {
			return n
		}
		return "menu"
	}
	return v
}

// ---- name ----

func (f *Flow) defaultName() string {
	if f.draft.Name != "" {
		return f.draft.Name
	}
	return FolderName(f.dir)
}

// FolderName turns a folder into a valid project name.
func FolderName(dir string) string {
	if dir == "" {
		return "project"
	}
	var b strings.Builder
	dash := true // no leading dash
	for _, r := range strings.ToLower(filepath.Base(filepath.Clean(dir))) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		return "project"
	}
	return s
}

func askName(f *Flow, _ string) Step {
	return Step{Title: "Project name", Kind: KindText, Default: f.defaultName(),
		Help: "Lowercase letters, digits and dashes, at most 63 characters. Empty uses the default."}
}

func applyName(f *Flow, _, v string) error {
	if v == "" {
		v = f.defaultName()
	}
	if _, err := projectfile.New(v); err != nil { // projectfile owns the name rules
		return fmt.Errorf("invalid project name %q: use lowercase letters, digits and dashes, at most 63 characters", v)
	}
	if f.NameTaken != nil && f.NameTaken(v) {
		return errors.New("a project with that name already exists")
	}
	f.draft.Name = v
	return nil
}

// ---- techs ----

func askTechs(f *Flow, _ string) Step {
	help := "Select every technology this project runs. Unselected ones were only suggested."
	if len(f.notes) > 0 {
		help += " Scan notes: " + strings.Join(f.notes[:min(len(f.notes), 5)], "; ")
	}
	return Step{Title: "Technologies", Help: help, Kind: KindMulti, Options: f.techOptions()}
}

// techOptions is every draft tech plus every proposal, nothing else.
func (f *Flow) techOptions() []Option {
	var opts []Option
	seen := map[string]bool{}
	add := func(name string, sel bool) {
		if low := strings.ToLower(name); !seen[low] && plainName(name) {
			seen[low] = true
			opts = append(opts, Option{Value: name, Label: f.label(name), Detail: f.detail(name), Selected: sel})
		}
	}
	for _, t := range f.draft.Techs {
		add(t.Name, true)
	}
	for _, p := range f.props {
		add(p.Tech, false)
	}
	return opts
}

func (f *Flow) proposal(name string) (discovery.TechProposal, bool) {
	i := slices.IndexFunc(f.props, func(p discovery.TechProposal) bool { return strings.EqualFold(p.Tech, name) })
	if i < 0 {
		return discovery.TechProposal{}, false
	}
	return f.props[i], true
}

func (f *Flow) label(name string) string {
	if t, ok := f.cat.Get(name); ok && t.Title != "" {
		return plain(t.Title)
	}
	if p, ok := f.proposal(name); ok && p.Title != "" {
		return plain(p.Title)
	}
	return name
}

// detail summarises the evidence for a tech, e.g. "high: package php in composer.lock".
func (f *Flow) detail(name string) string {
	p, ok := f.proposal(name)
	if !ok {
		if f.existing != nil && techIndex(f.existing.Techs, name) >= 0 {
			return "already in the project"
		}
		return ""
	}
	ev := f.evidence[strings.ToLower(name)]
	if len(ev) == 0 {
		return string(p.Confidence)
	}
	text := ev[0].Detail
	if text == "" {
		text = ev[0].File
	}
	s := string(p.Confidence) + ": " + plain(text)
	if n := len(ev) - 1; n > 0 {
		s += fmt.Sprintf(" (+%d more)", n)
	}
	return s
}

// applyTechs replaces the tech set, keeping the versions of ones that stay.
func applyTechs(f *Flow, _, v string) error {
	sel := valueSet(v)
	var techs []model.ProjectTech
	for _, o := range f.techOptions() {
		if !sel[o.Value] {
			continue
		}
		if i := techIndex(f.draft.Techs, o.Value); i >= 0 {
			techs = append(techs, f.draft.Techs[i])
			continue
		}
		t := model.ProjectTech{Name: o.Value}
		if p, ok := f.proposal(o.Value); ok {
			t.Version = p.Version
		}
		techs = append(techs, t)
	}
	for _, t := range f.draft.Techs {
		if techIndex(techs, t.Name) < 0 {
			f.dropEnvTech(t.Name)
		}
	}
	f.draft.Techs = techs
	f.forgetCustom()
	return nil
}

// dropEnvTech forgets per-environment versions of a removed tech.
func (f *Flow) dropEnvTech(name string) {
	for e, cfg := range f.draft.Environments {
		for n := range cfg.Techs {
			if strings.EqualFold(n, name) {
				delete(cfg.Techs, n)
			}
		}
		cfg.Exclude = slices.DeleteFunc(cfg.Exclude, func(x string) bool { return strings.EqualFold(x, name) })
		f.draft.Environments[e] = cfg
		if len(cfg.Techs) == 0 && len(cfg.Exclude) == 0 && cfg.Image == "" {
			delete(f.draft.Environments, e)
		}
	}
}

func nextTechs(f *Flow, _, _ string) string { return f.afterSection("add-techs") }

// ---- add-techs ----

func askAddTechs(f *Flow, _ string) Step {
	help := "Type technology names to search the catalog, for example: redis postgres. " +
		"A name the catalog does not have can be added as your own keyword by writing it with a plus, for example: +algolia (advisories that name it will match). Leave empty when done."
	if len(f.added) > 0 {
		help += " Added so far: " + strings.Join(f.added, ", ") + "."
	}
	return Step{Title: "Add other technologies", Help: help, Kind: KindText}
}

// applyAddTechs resolves every term or changes nothing. A term written with a
// plus (+algolia) that the catalog does not know is staged as the person's own
// keyword.
func applyAddTechs(f *Flow, _, v string) error {
	if addTechsDone(v) {
		return nil
	}
	var found []model.Tech
	var custom []model.Tech
	var problems []string
	for _, term := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		typed, own := strings.CutPrefix(term, "+")
		if lk := f.Lookup(typed); lk.Found {
			found = append(found, lk.Tech)
			continue
		} else if own {
			c, err := f.newCustom(model.Tech{Name: typed})
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			custom = append(custom, c)
			continue
		} else if len(lk.Suggest) == 0 {
			problems = append(problems, fmt.Sprintf("%q is not in the catalog; write +%s to add it as your own keyword", plain(term), plain(term)))
		} else {
			var names []string
			for _, t := range lk.Suggest {
				names = append(names, t.Name)
			}
			problems = append(problems, fmt.Sprintf("%q is not in the catalog. Did you mean: %s? (or write +%s to add it as your own keyword)",
				plain(term), strings.Join(names, ", "), plain(term)))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	for _, t := range found {
		if techIndex(f.draft.Techs, t.Name) < 0 {
			f.draft.Techs = append(f.draft.Techs, model.ProjectTech{Name: t.Name})
			f.added = append(f.added, t.Name)
		}
	}
	for _, c := range custom {
		f.stage(c)
	}
	return nil
}

func addTechsDone(v string) bool { return v == "" || strings.EqualFold(v, "done") }

func nextAddTechs(f *Flow, _, v string) string {
	if !addTechsDone(v) {
		return "add-techs" // ask again until the answer is empty
	}
	if f.editing() {
		return "menu"
	}
	f.startVersions(false)
	return f.nextVersionOrAfter()
}

// ---- versions ----

var versionRE = regexp.MustCompile(`^v?\d`)

func (f *Flow) startVersions(all bool) {
	f.asked, f.versionAll = map[string]bool{}, all
}

// nextVersionID is the next tech to ask about, or "".
func (f *Flow) nextVersionID() string {
	for _, t := range f.draft.Techs {
		if !f.asked[strings.ToLower(t.Name)] && (f.versionAll || t.Version == "") {
			return "version:" + t.Name
		}
	}
	return ""
}

func (f *Flow) nextVersionOrAfter() string {
	if n := f.nextVersionID(); n != "" {
		return n
	}
	if f.editing() {
		return "menu"
	}
	if len(f.lockCands()) > 0 {
		return "lockfiles"
	}
	return "envs"
}

func askVersion(f *Flow, tech string) Step {
	cur := ""
	if i := techIndex(f.draft.Techs, tech); i >= 0 {
		cur = f.draft.Techs[i].Version
	}
	return Step{Title: "Version of " + f.label(tech), Kind: KindText, Default: cur,
		Help: "Which version of " + tech + " does this project run? A series like 8.2 is fine. " +
			"Empty means unknown: the project is then judged by name only."}
}

func applyVersion(f *Flow, tech, v string) error {
	i := techIndex(f.draft.Techs, tech)
	if i < 0 {
		return fmt.Errorf("%s is not in the project", tech)
	}
	if v != "" && !versionRE.MatchString(v) {
		return errors.New("a version starts with a digit, or v and a digit, for example 8.2")
	}
	f.draft.Techs[i].Version = v
	f.asked[strings.ToLower(tech)] = true
	return nil
}

func nextVersion(f *Flow, _, _ string) string { return f.nextVersionOrAfter() }

// ---- lockfiles ----

// lockCand is a lockfile that can be switched on or off.
type lockCand struct {
	lf    model.Lockfile
	pkgs  int
	found bool // seen by a scan
	sel   bool // in the draft
}

// lockCands is every discovered lockfile plus every other one in the draft.
// Its order only depends on the state, so Current and Answer agree on indexes.
func (f *Flow) lockCands() []lockCand {
	var out []lockCand
	used := make([]bool, len(f.draft.Lockfiles))
	for _, d := range f.locks {
		c := lockCand{lf: d.lf, pkgs: d.pkgs, found: true}
		if i := f.findLock(d.lf); i >= 0 {
			c.lf, c.sel, used[i] = f.draft.Lockfiles[i], true, true
		}
		out = append(out, c)
	}
	for i, l := range f.draft.Lockfiles {
		if !used[i] {
			out = append(out, lockCand{lf: l, sel: true})
		}
	}
	return out
}

func (f *Flow) resolvePath(p string) string {
	if !filepath.IsAbs(p) && f.dir != "" {
		p = filepath.Join(f.dir, p)
	}
	return filepath.Clean(p)
}

func (f *Flow) sameLock(a, b model.Lockfile) bool {
	return a.Type == b.Type && a.Env == b.Env && f.resolvePath(a.Path) == f.resolvePath(b.Path)
}

func (f *Flow) findLock(l model.Lockfile) int {
	return slices.IndexFunc(f.draft.Lockfiles, func(d model.Lockfile) bool { return f.sameLock(d, l) })
}

func askLockfiles(f *Flow, _ string) Step {
	var opts []Option
	for i, c := range f.lockCands() {
		label := c.lf.Type + " " + f.displayPath(c.lf.Path)
		if c.lf.Env != "" {
			label += " (" + string(c.lf.Env) + ")"
		}
		detail := "already in the project"
		if c.found {
			detail = fmt.Sprintf("%d packages", c.pkgs)
		}
		opts = append(opts, Option{Value: fmt.Sprint(i), Label: plain(label), Detail: detail, Selected: c.sel})
	}
	return Step{Title: "Inventory sources", Kind: KindMulti, Options: opts,
		Help: "Lockfiles are read on every run so the tech matrix follows the repository. Select the ones to use."}
}

func (f *Flow) displayPath(p string) string {
	if f.dir != "" && filepath.IsAbs(p) {
		if rel, err := filepath.Rel(f.dir, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return p
}

func applyLockfiles(f *Flow, _, v string) error {
	sel := valueSet(v)
	var locks []model.Lockfile
	for i, c := range f.lockCands() {
		if sel[fmt.Sprint(i)] {
			locks = append(locks, c.lf)
		}
	}
	f.draft.Lockfiles = locks
	return nil
}

func nextLockfiles(f *Flow, _, _ string) string { return f.afterSection("envs") }

// ---- envs ----

// otherEnv is the value of the "other..." option of the envs step; it is not a valid name.
const otherEnv = "+"

// envChoices are the suggested names, then the project's own.
func (f *Flow) envChoices() []model.Env {
	out := slices.Clone(model.SuggestedEnvs)
	for _, e := range f.draft.EffectiveEnvs() {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func askEnvs(f *Flow, _ string) Step {
	on := map[model.Env]bool{}
	for _, e := range f.draft.EffectiveEnvs() {
		on[e] = true
	}
	var opts []Option
	for _, e := range f.envChoices() {
		opts = append(opts, Option{Value: string(e), Label: string(e), Selected: on[e]})
	}
	opts = append(opts, Option{Value: otherEnv, Label: "other..."})
	return Step{Title: "Environments", Kind: KindMulti, Options: opts,
		Help: "Where does the project run? Names are free: pick from the list or choose other... to type your own. " +
			"local is enough to start; add prod (and others) if you deploy there. At least one."}
}

// applyEnvs stores the choice; names typed under other... follow in envs-other.
func applyEnvs(f *Flow, _, v string) error {
	sel := valueSet(v)
	var envs []model.Env
	for _, e := range f.envChoices() {
		if sel[string(e)] {
			envs = append(envs, e)
		}
	}
	if len(envs) == 0 && !sel[otherEnv] {
		return errors.New("select at least one environment")
	}
	model.SortEnvs(envs)
	f.draft.Envs = envs
	return nil
}

func nextEnvs(f *Flow, _, v string) string {
	if valueSet(v)[otherEnv] {
		return "envs-other"
	}
	return f.afterSection(f.differOrReview())
}

func askEnvsOther(f *Flow, _ string) Step {
	return Step{Title: "Other environments", Kind: KindText,
		Help: "Names separated by commas: lowercase letters, digits, - and _, starting with a letter, such as qa or demo-eu."}
}

func applyEnvsOther(f *Flow, _, v string) error {
	envs := slices.Clone(f.draft.Envs)
	for _, tok := range strings.Split(v, ",") {
		e := model.Env(strings.ToLower(strings.TrimSpace(tok)))
		switch {
		case e == "":
			continue
		case !e.Valid():
			return fmt.Errorf("%q is not a valid environment name (lowercase letters, digits, - and _, starting with a letter)", plain(tok))
		case !slices.Contains(envs, e):
			envs = append(envs, e)
		}
	}
	if len(envs) == 0 {
		return errors.New("select at least one environment")
	}
	model.SortEnvs(envs)
	f.draft.Envs = envs
	return nil
}

// EnvHints are the notes on the environments of the draft: the old default in use, no prod.
func (f *Flow) EnvHints() []projectfile.EnvHint { return projectfile.EnvHints(f.draft) }

// ---- review ----

func askReview(f *Flow, _ string) Step {
	help := f.summary()
	if diff, issues, err := f.Review(nil); err == nil {
		help = "Changes to save:\n" + diff
		for _, is := range issues {
			help += fmt.Sprintf("\n%s: %s: %s", is.Level, is.Field, plain(is.Message))
		}
		if lines := DifferenceLines(f.draft); len(lines) > 0 {
			help += "\nDifferences per environment: " + plain(strings.Join(lines, "; "))
		}
	}
	return Step{Title: "Save this project?", Help: help, Kind: KindConfirm, Default: "yes"}
}

func nextReview(f *Flow, _, v string) string {
	switch {
	case v == "yes":
		return ""
	case f.editing():
		return "menu"
	}
	return "techs"
}

// summary is the review text when no diff can be built.
func (f *Flow) summary() string {
	var techs []string
	for _, t := range f.draft.Techs {
		techs = append(techs, strings.TrimSpace(t.Name+" "+t.Version))
	}
	var envs []string
	for _, e := range f.draft.EffectiveEnvs() {
		envs = append(envs, string(e))
	}
	out := fmt.Sprintf("Project %s: technologies: %s; lockfiles: %d; environments: %s.",
		f.draft.Name, strings.Join(techs, ", "), len(f.draft.Lockfiles), strings.Join(envs, ", "))
	if lines := DifferenceLines(f.draft); len(lines) > 0 {
		out += " Differences per environment: " + strings.Join(lines, "; ") + "."
	}
	return out
}

// ---- ops and review ----

// Ops is the edit list that turns Existing (or an empty file) into the draft,
// in a fixed order: envs, tech removals, tech sets, the environments a tech is
// limited to, lockfile removals and additions, then per environment the
// differences: tech versions, excluded techs and the image.
func (f *Flow) Ops() []projectfile.Op {
	var base model.Project
	if f.existing != nil {
		base = *f.existing
	}
	cur := f.draft
	var ops []projectfile.Op

	if !sameEnvs(base.EffectiveEnvs(), cur.EffectiveEnvs()) {
		ops = append(ops, projectfile.Op{Kind: "set_envs", Envs: slices.Clone(cur.Envs)}) // none clears the key
	}

	// set_tech cannot clear a version, so a cleared one is removed and set again.
	changed, reset := map[string]bool{}, map[string]bool{}
	for _, b := range base.Techs {
		i := techIndex(cur.Techs, b.Name)
		switch {
		case i < 0 || b.Version != "" && cur.Techs[i].Version == "":
			ops = append(ops, projectfile.Op{Kind: "remove_tech", Tech: b.Name})
			reset[strings.ToLower(b.Name)] = true // removing drops the limit to some environments with it
		case b.Version != cur.Techs[i].Version:
			changed[strings.ToLower(b.Name)] = true
		}
	}
	for _, c := range cur.Techs {
		i := techIndex(base.Techs, c.Name)
		if i < 0 || changed[strings.ToLower(c.Name)] || base.Techs[i].Version != "" && c.Version == "" {
			ops = append(ops, projectfile.Op{Kind: "set_tech", Tech: c.Name, Version: c.Version})
		}
	}

	for _, c := range cur.Techs {
		var was []model.Env
		if i := techIndex(base.Techs, c.Name); i >= 0 {
			was = base.Techs[i].Envs
		}
		if !sameEnvs(was, c.Envs) || reset[strings.ToLower(c.Name)] && len(c.Envs) > 0 {
			ops = append(ops, projectfile.Op{Kind: "set_tech_envs", Tech: c.Name, Envs: slices.Clone(c.Envs)}) // none lifts the limit
		}
	}

	key := func(l model.Lockfile) string { return l.Type + "\x00" + l.Path + "\x00" + string(l.Env) }
	has := func(list []model.Lockfile, l model.Lockfile) bool {
		return slices.ContainsFunc(list, func(o model.Lockfile) bool { return key(o) == key(l) })
	}
	for _, l := range base.Lockfiles {
		if !has(cur.Lockfiles, l) {
			ops = append(ops, projectfile.Op{Kind: "remove_lockfile", Lockfile: l})
		}
	}
	for _, l := range cur.Lockfiles {
		if !has(base.Lockfiles, l) {
			ops = append(ops, projectfile.Op{Kind: "add_lockfile", Lockfile: l})
		}
	}

	for _, e := range envKeys(base.Environments, cur.Environments) {
		b, c := base.Environments[e], cur.Environments[e]
		names := map[string]bool{}
		for n := range b.Techs {
			names[n] = true
		}
		for n := range c.Techs {
			names[n] = true
		}
		for _, n := range slices.Sorted(mapKeys(names)) {
			bv, cv := b.Techs[n], c.Techs[n]
			switch {
			case cv == "" && bv != "":
				ops = append(ops, projectfile.Op{Kind: "remove_env_tech", Env: e, Tech: n})
			case cv != "" && cv != bv:
				ops = append(ops, projectfile.Op{Kind: "set_env_tech", Env: e, Tech: n, Version: cv})
			}
		}
		for _, x := range b.Exclude {
			if !slices.ContainsFunc(c.Exclude, func(o string) bool { return strings.EqualFold(o, x) }) {
				ops = append(ops, projectfile.Op{Kind: "include_env_tech", Env: e, Tech: x})
			}
		}
		for _, x := range c.Exclude {
			if !slices.ContainsFunc(b.Exclude, func(o string) bool { return strings.EqualFold(o, x) }) {
				ops = append(ops, projectfile.Op{Kind: "exclude_env_tech", Env: e, Tech: x})
			}
		}
		if b.Image != c.Image {
			ops = append(ops, projectfile.Op{Kind: "set_image", Env: e, Image: c.Image})
		}
	}
	return ops
}

func mapKeys(m map[string]bool) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func sameEnvs(a, b []model.Env) bool {
	for _, e := range a {
		if !slices.Contains(b, e) {
			return false
		}
	}
	for _, e := range b {
		if !slices.Contains(a, e) {
			return false
		}
	}
	return true
}

// envKeys is every environment either map names, in display order.
func envKeys(maps ...map[model.Env]model.EnvConfig) []model.Env {
	var out []model.Env
	for _, m := range maps {
		for e := range m {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	model.SortEnvs(out)
	return out
}

// Review applies Ops to the file text and returns the diff and the validation
// issues, without writing anything. cat may be nil to use the flow's catalog.
func (f *Flow) Review(cat *catalog.Catalog) (string, []projectfile.Issue, error) {
	if cat == nil {
		cat = f.cat
	}
	var file *projectfile.File
	var err error
	switch {
	case f.src != nil:
		file, err = projectfile.Parse(f.src)
	case f.existing != nil:
		return "", nil, errors.New("setup: the text of the existing file is needed for a preview")
	default:
		file, err = projectfile.New(f.draft.Name)
	}
	if err != nil {
		return "", nil, err
	}
	before, err := file.Bytes()
	if err != nil {
		return "", nil, err
	}
	if err := file.Apply(f.Ops()...); err != nil {
		return "", nil, err
	}
	after, err := file.Bytes()
	if err != nil {
		return "", nil, err
	}
	return projectfile.Diff(before, after), file.Validate(cat.Has), nil
}

// ---- helpers ----

// cleanText trims an answer and rejects what a terminal or an agent should
// not be sending: too long, invalid UTF-8 or control characters.
func cleanText(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("the answer is not valid text")
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxText {
		return "", fmt.Errorf("the answer is too long (at most %d characters)", maxText)
	}
	if strings.ContainsFunc(s, unicode.IsControl) {
		return "", errors.New("the answer contains control characters")
	}
	return s, nil
}

// normalize checks an answer against the step's options and returns it in
// canonical form: the option's own spelling, "yes"/"no", or values joined by ",".
func normalize(st Step, v string) (string, error) {
	find := func(s string) (string, bool) {
		for _, o := range st.Options {
			if strings.EqualFold(o.Value, s) {
				return o.Value, true
			}
		}
		return "", false
	}
	values := func() string {
		var vs []string
		for _, o := range st.Options {
			vs = append(vs, o.Value)
		}
		return strings.Join(vs, ", ")
	}
	switch st.Kind {
	case KindChoice:
		if v == "" {
			v = st.Default
		}
		if c, ok := find(v); ok {
			return c, nil
		}
		return "", fmt.Errorf("choose one of: %s", values())
	case KindConfirm:
		if v = strings.ToLower(v); v == "" {
			v = st.Default
		}
		if v != "yes" && v != "no" {
			return "", errors.New(`answer "yes" or "no"`)
		}
	case KindMulti:
		var out []string
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok == "" {
				continue
			}
			c, ok := find(tok)
			if !ok {
				return "", fmt.Errorf("%q is not one of: %s", tok, values())
			}
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
		return strings.Join(out, ","), nil
	}
	return v, nil
}

func valueSet(v string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(v, ",") {
		m[s] = true
	}
	return m
}

// plain makes untrusted text safe to show: control characters become spaces
// and the length is capped. It is never interpreted.
func plain(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxText {
		s = string(r[:maxText]) + "..."
	}
	return s
}

// plainName says whether a tech name can be an option value.
func plainName(s string) bool {
	return s != "" && s == strings.TrimSpace(s) && !strings.ContainsFunc(s, func(r rune) bool { return r == ',' || unicode.IsControl(r) })
}

func techIndex(techs []model.ProjectTech, name string) int {
	return slices.IndexFunc(techs, func(t model.ProjectTech) bool { return strings.EqualFold(t.Name, name) })
}

func cloneProject(p model.Project) model.Project {
	p.Envs = slices.Clone(p.Envs)
	p.Techs = slices.Clone(p.Techs)
	for i := range p.Techs {
		p.Techs[i].Envs = slices.Clone(p.Techs[i].Envs)
	}
	p.Lockfiles = slices.Clone(p.Lockfiles)
	if p.Environments != nil {
		m := make(map[model.Env]model.EnvConfig, len(p.Environments))
		for e, c := range p.Environments {
			if c.Techs != nil {
				t := make(map[string]string, len(c.Techs))
				for k, v := range c.Techs {
					t[k] = v
				}
				c.Techs = t
			}
			c.Exclude = slices.Clone(c.Exclude)
			m[e] = c
		}
		p.Environments = m
	}
	return p
}
