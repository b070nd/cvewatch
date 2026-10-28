package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// ProjectChange is a set of edits to one project file. A project that has no
// file yet is created. Without Save the change is only previewed.
type ProjectChange struct {
	Project string
	Ops     []projectfile.Op
	Save    bool
}

// ProjectPreview is what a change does, so callers can show it before saving.
type ProjectPreview struct {
	Project string              `json:"project"`
	Path    string              `json:"path"`
	Created bool                `json:"created"`
	Saved   bool                `json:"saved"`
	Diff    string              `json:"diff"`
	Issues  []projectfile.Issue `json:"issues"`
	Result  ProjectView         `json:"result"`
}

// ProjectView is a project as shown to people and agents.
type ProjectView struct {
	Name      string      `json:"name"`
	Envs      []string    `json:"envs"`
	Techs     []TechPin   `json:"techs"`
	Lockfiles []LockEntry `json:"lockfiles"`
}

type TechPin struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type LockEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Env  string `json:"env,omitempty"`
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
		v.Lockfiles = append(v.Lockfiles, LockEntry{l.Type, l.Path, string(l.Env)})
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

// ProjectNames lists the project files the actor may see.
func (s *Session) ProjectNames() ([]string, error) {
	names, err := projectfile.List(s.projectsDir())
	if err != nil {
		return nil, err
	}
	projects, _, open := s.Cfg.Allowed(baseActor(s.Actor))
	if open {
		return names, nil
	}
	return slices.DeleteFunc(names, func(n string) bool { return !slices.Contains(projects, n) }), nil
}

// EditProject previews a change and, with Save, validates and writes it. The
// file keeps its comments and layout, the old content is backed up, and the
// edit is recorded in the audit log before anything is written. Creating a
// project needs access to every project.
func (s *Session) EditProject(c ProjectChange) (ProjectPreview, error) {
	name := strings.TrimSpace(c.Project)
	path, err := projectfile.Path(s.projectsDir(), name)
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
	out.Issues = f.Validate(s.Cfg.Catalog.Has)
	out.Result = ViewOf(f.Project())
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
	verb := "edited"
	if out.Created {
		verb = "created"
	}
	ev := audit.Event{Time: s.Now(), Actor: s.Actor, Action: "project", Project: name,
		Note: fmt.Sprintf("%s project file: %d change(s)", verb, len(c.Ops))}
	if err := s.Audit.Append(ev); err != nil {
		return out, fmt.Errorf("audit log: %w", err) // never change anything without a record
	}
	if err := projectfile.Write(path, data, filepath.Join(s.Cfg.DataDir, "project-backups"), s.Now()); err != nil {
		return out, err
	}
	out.Saved = true
	return out, nil
}
