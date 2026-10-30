package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// ProjectChange is a set of edits to one project file. A project that has no
// file yet is created. Without Save the change is only previewed.
type ProjectChange struct {
	Project string
	Ops     []projectfile.Op
	Save    bool
	// NewTechs are technologies of your own that the project names and that are
	// not in the catalog yet. They count as known while the change is checked
	// and are written to techs.yaml, before the project, when it is saved.
	NewTechs []model.Tech
}

// ProjectPreview is what a change does, so callers can show it before saving.
type ProjectPreview struct {
	Project string              `json:"project"`
	Path    string              `json:"path"`
	Created bool                `json:"created"`
	Saved   bool                `json:"saved"`
	Diff    string              `json:"diff"`
	Issues  []projectfile.Issue `json:"issues"`
	Hints   []projectfile.Hint  `json:"hints"` // what may not be covered or cause trouble; not errors
	Result  ProjectView         `json:"result"`

	NewTechs  []string `json:"new_techs,omitempty"`  // your own technologies the change adds to techs.yaml
	TechsDiff string   `json:"techs_diff,omitempty"` // what that does to techs.yaml

	Moved []EnvMove `json:"moved,omitempty"` // findings that follow a renamed environment
}

// EnvMove is the findings of one environment that a rename_env carries to the new name.
type EnvMove struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Findings int    `json:"findings"`
}

// ProjectView is a project as shown to people and agents.
type ProjectView struct {
	Name      string      `json:"name"`
	Envs      []string    `json:"envs"`
	Techs     []TechPin   `json:"techs"`
	Lockfiles []LockEntry `json:"lockfiles"`
	Since     string      `json:"since,omitempty"` // YYYY-MM-DD
}

type TechPin struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type LockEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Env  string `json:"env,omitempty"`
	Dev  bool   `json:"dev,omitempty"`
}

// ViewOf copies the parts of a project worth showing.
func ViewOf(p model.Project) ProjectView {
	v := ProjectView{Name: p.Name, Envs: []string{}, Techs: []TechPin{}, Lockfiles: []LockEntry{}}
	for _, e := range p.Envs {
		v.Envs = append(v.Envs, string(e))
	}
	for _, t := range p.Techs {
		v.Techs = append(v.Techs, TechPin{t.Name, t.Version})
	}
	for _, l := range p.Lockfiles {
		v.Lockfiles = append(v.Lockfiles, LockEntry{l.Type, l.Path, string(l.Env), l.Dev})
	}
	if !p.Since.IsZero() {
		v.Since = p.Since.Format(projectfile.SinceLayout)
	}
	return v
}

// Blocked reports whether the change has errors and so cannot be saved.
func (p ProjectPreview) Blocked() bool {
	for _, i := range p.Issues {
		if i.Level == "error" {
			return true
		}
	}
	return false
}

func (s *Session) projectsDir() string { return filepath.Join(s.Cfg.Root, "config", "projects") }

// mayRead checks that the actor may see one project.
func (s *Session) mayRead(project string) error {
	projects, _, open := s.Cfg.Allowed(baseActor(s.Actor))
	if open || slices.Contains(projects, project) {
		return nil
	}
	return fmt.Errorf("%w: %s has no access to project %q", ErrDenied, s.Actor, project)
}

// ProjectNames lists the projects the actor may see that have a file. A
// project is named by the `name:` in its file, whatever the file is called.
func (s *Session) ProjectNames() ([]string, error) {
	files, err := s.projectFiles()
	if err != nil {
		return nil, err
	}
	names := slices.Sorted(maps.Keys(files))
	projects, _, open := s.Cfg.Allowed(baseActor(s.Actor))
	if open {
		return names, nil
	}
	return slices.DeleteFunc(names, func(n string) bool { return !slices.Contains(projects, n) }), nil
}

// projectFiles maps the name of every project file in the projects folder to
// its path. The loaded configuration says which file declared which name; a
// file it has not seen (written since) is read for its name, and a file that
// cannot be read goes by its file name.
func (s *Session) projectFiles() (map[string]string, error) {
	dir := s.projectsDir()
	stems, err := projectfile.List(dir)
	if err != nil {
		return nil, err
	}
	known := map[string]string{}
	for name, path := range s.Cfg.ProjectFiles() {
		known[absPath(path)] = name
	}
	out := map[string]string{}
	for _, stem := range stems {
		path := filepath.Join(dir, stem+".yaml")
		name, ok := known[absPath(path)]
		if !ok {
			name = declaredName(path, stem)
		}
		if _, dup := out[name]; !dup {
			out[name] = path
		}
	}
	return out, nil
}

// ProjectFile is the file of a project. A name no file declares is a project
// to be created, and its file is <name>.yaml; it is an error when that file
// belongs to another project.
func (s *Session) ProjectFile(name string) (string, error) {
	files, err := s.projectFiles()
	if err != nil {
		return "", err
	}
	if path, ok := files[name]; ok {
		return path, nil
	}
	path, err := projectfile.Path(s.projectsDir(), name)
	if err != nil {
		return "", err
	}
	for owner, p := range files {
		if p == path {
			return "", fmt.Errorf("%s is the file of project %q, not %q", filepath.Base(path), owner, name)
		}
	}
	return path, nil
}

// disabledFiles maps the name of every switched-off project to its file.
func (s *Session) disabledFiles() (map[string]string, error) {
	dir := s.projectsDir()
	stems, err := projectfile.ListDisabled(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, stem := range stems {
		path := filepath.Join(dir, stem+".yaml.disabled")
		if name := declaredName(path, stem); out[name] == "" {
			out[name] = path
		}
	}
	return out, nil
}

// declaredName is the name a project file declares, or the fallback when the
// file cannot be read or has none.
func declaredName(path, fallback string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	f, err := projectfile.Parse(data)
	if err != nil || f.Project().Name == "" {
		return fallback
	}
	return f.Project().Name
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// EditProject previews a change and, with Save, validates and writes it. The
// file keeps its comments and layout, the old content is backed up, and the
// edit is recorded in the audit log before anything is written. Creating a
// project needs access to every project.
func (s *Session) EditProject(c ProjectChange) (ProjectPreview, error) {
	name := strings.TrimSpace(c.Project)
	path, err := s.ProjectFile(name)
	if err != nil {
		return ProjectPreview{}, err
	}
	out := ProjectPreview{Project: name, Path: path}
	old, err := os.ReadFile(path)
	var f *projectfile.File
	switch {
	case err == nil:
		if err := s.mayRead(name); err != nil {
			return out, err
		}
		if f, err = projectfile.Parse(old); err != nil {
			return out, err
		}
	case errors.Is(err, fs.ErrNotExist):
		out.Created = true
		if _, _, open := s.Cfg.Allowed(baseActor(s.Actor)); !open {
			return out, fmt.Errorf("%w: %s may not create projects", ErrDenied, s.Actor)
		}
		if f, err = projectfile.New(name); err != nil {
			return out, err
		}
	default:
		return out, err
	}
	if err := f.Apply(c.Ops...); err != nil {
		return out, err
	}
	data, err := f.Bytes()
	if err != nil {
		return out, err
	}
	out.Diff = projectfile.Diff(old, data)
	cat := s.Cfg.Catalog
	var own []string
	if mine, err := s.UserTechs(); err == nil {
		for _, t := range mine {
			own = append(own, t.Name)
		}
	}
	if len(c.NewTechs) > 0 {
		var err error
		if cat, err = s.previewNewTechs(&out, c.NewTechs); err != nil {
			return out, err
		}
		own = append(own, out.NewTechs...)
	}
	out.Issues = append(out.Issues, f.Validate(cat.Has)...)
	out.Hints = f.Hints(projectfile.HintOptions{Catalog: cat, Root: s.Cfg.Root, Own: own})
	if out.Hints == nil {
		out.Hints = []projectfile.Hint{}
	}
	out.Result = ViewOf(f.Project())
	if !out.Created {
		moved, warns, err := s.planEnvRenames(name, c.Ops)
		if err != nil {
			return out, err
		}
		out.Moved = moved
		out.Issues = append(out.Issues, warns...)
	}
	if !c.Save {
		return out, nil
	}
	if !out.Created {
		if err := s.mayWrite(name); err != nil {
			return out, err
		}
	} else if err := s.mayWrite(""); err != nil {
		return out, err
	}
	if out.Blocked() {
		return out, errors.New("the project has errors; fix them before saving")
	}
	if string(old) == string(data) {
		return out, nil
	}
	if len(c.NewTechs) > 0 {
		if _, err := s.AddTechs(c.NewTechs, true); err != nil {
			return out, err
		}
	}
	verb := "edited"
	if out.Created {
		verb = "created"
	}
	ev := audit.Event{Time: s.Now(), Actor: s.Actor, Action: "project", Project: name,
		Note: fmt.Sprintf("%s project file: %d change(s)", verb, len(c.Ops))}
	for _, m := range out.Moved {
		ev.Note += fmt.Sprintf("; environment %s renamed to %s, %d finding(s) moved", m.From, m.To, m.Findings)
	}
	if err := s.Audit.Append(ev); err != nil {
		return out, fmt.Errorf("audit log: %w", err) // never change anything without a record
	}
	if err := s.moveEnvFindings(name, out.Moved); err != nil {
		return out, err
	}
	if err := projectfile.Write(path, data, filepath.Join(s.Cfg.DataDir, "project-backups"), s.Now()); err != nil {
		s.moveEnvFindings(name, reverseMoves(out.Moved)) // best effort: the file did not change
		return out, err
	}
	out.Saved = true
	return out, nil
}

// planEnvRenames says what the rename_env ops of a change carry along: the
// findings of the environment. It fails if the new name already has one of the
// same vulnerabilities, and warns about settings that still name the old one.
func (s *Session) planEnvRenames(project string, list []projectfile.Op) ([]EnvMove, []projectfile.Issue, error) {
	var moved []EnvMove
	var warns []projectfile.Issue
	for _, op := range list {
		if op.Kind != "rename_env" {
			continue
		}
		n, err := s.Ledger.EnvMove(project, op.Env, op.To)
		if err != nil {
			return nil, nil, err
		}
		moved = append(moved, EnvMove{From: string(op.Env), To: string(op.To), Findings: n})
		for _, r := range s.Cfg.Policy.Rules {
			if r.Env == op.Env {
				warns = append(warns, projectfile.Issue{Level: "warning", Field: "envs", Message: fmt.Sprintf("policy rule %q still names environment %s", r.Name, op.Env)})
			}
		}
		if s.Cfg.Notify.Digest.Env == op.Env {
			warns = append(warns, projectfile.Issue{Level: "warning", Field: "envs", Message: fmt.Sprintf("notify.digest.env still names environment %s", op.Env)})
		}
	}
	return moved, warns, nil
}

func reverseMoves(moves []EnvMove) []EnvMove {
	out := make([]EnvMove, len(moves))
	for i, m := range moves {
		out[len(moves)-1-i] = EnvMove{From: m.To, To: m.From, Findings: m.Findings}
	}
	return out
}

// moveEnvFindings renames the environment of a project's findings, in order, and stores the ledger.
func (s *Session) moveEnvFindings(project string, moves []EnvMove) error {
	if len(moves) == 0 {
		return nil
	}
	return s.commitLedger(func() error {
		for _, m := range moves {
			if _, err := s.Ledger.RenameEnv(project, model.Env(m.From), model.Env(m.To)); err != nil {
				return err
			}
		}
		return nil
	})
}

// previewNewTechs checks the technologies a change adds, records them in out
// and returns the catalog as it will be once they are saved. What blocks them
// is an error of the preview.
func (s *Session) previewNewTechs(out *ProjectPreview, techs []model.Tech) (*catalog.Catalog, error) {
	p, err := s.Settings().AddTechs(techs, false)
	if err != nil {
		return nil, err
	}
	out.TechsDiff = p.Diff
	for _, is := range p.Issues {
		if is.Level == confdoc.LevelError && !is.Existing {
			out.Issues = append(out.Issues, projectfile.Issue{Level: "error", Field: "techs", Message: is.Message})
		}
	}
	all := s.Cfg.Catalog.All()
	for _, t := range techs {
		t, _ = cleanTech(t) // AddTechs has accepted them
		out.NewTechs = append(out.NewTechs, t.Name)
		all = append(all, t)
	}
	return catalog.New(all), nil
}
