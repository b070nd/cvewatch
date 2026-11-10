package ops

import (
	"os"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/status"
)

// Workspace is everything an interactive front end shows, read in one go:
// the projects the actor may see with what is wrong with them, their open
// issues, the health of the tool and the policy violations. A front end draws
// it and decides nothing: what is visible is settled here.
type Workspace struct {
	At         time.Time
	Root       string
	Horizon    config.Horizon           // which publication dates are judged and alerted
	Issues     map[string][]query.Issue // the open issues of each project, most urgent first; no row mixes projects
	Status     status.Report
	Violations []priority.Violation
	Projects   []WorkspaceProject // by vendor when any project has one, else in configuration order
	Warnings   []string           // parts that could not be read; the rest is still there
}

// WorkspaceProject is one project of a Workspace: loaded, broken or switched off.
type WorkspaceProject struct {
	ProjectView
	HasFile  bool                // has its own file under config/projects, so it can be edited
	File     string              // that file
	Broken   string              // why the file does not load; only the name is known then
	Problems []projectfile.Issue // what is wrong with the file, errors first
	Hints    []projectfile.Hint  // what may not be covered or cause trouble; not errors
	// Written are the lockfiles as the file spells them (the loaded ones have
	// resolved paths), which is what an edit has to name.
	Written      []LockEntry
	Disabled     bool                          // the file is switched off (<name>.yaml.disabled): listed, not loaded
	Environments map[model.Env]model.EnvConfig // deployed versions and image per environment
	EnvsUnset    bool                          // the file has no envs: Envs is the old default
}

// Workspace reads the workspace of the session's actor. Only the issue list
// is essential (it fails on a refusal or missing state); every other part
// that cannot be read becomes a warning.
func (s *Session) Workspace() (Workspace, error) {
	if _, err := s.scope(query.Filter{}); err != nil {
		return Workspace{}, err
	}
	w := Workspace{At: s.Now(), Root: s.Cfg.Root, Horizon: s.Cfg.Horizon, Issues: map[string][]query.Issue{}}
	warn := func(what string, err error) { w.Warnings = append(w.Warnings, what+": "+query.Clip(err.Error(), 300)) }
	var err error
	if w.Status, err = s.Status(); err != nil {
		warn("status", err)
	}
	if w.Violations, err = s.Violations(); err != nil {
		warn("policy", err)
	}
	files, err := s.ProjectNames()
	if err != nil {
		warn("project files", err)
	}
	problems, err := s.ProjectProblems("")
	if err != nil {
		warn("project problems", err)
	}
	problemsOf := map[string][]projectfile.Issue{}
	for _, i := range problems {
		problemsOf[i.Project] = append(problemsOf[i.Project], i)
	}
	hints, err := s.ProjectHints("")
	if err != nil {
		warn("project hints", err)
	}
	hintsOf := map[string][]projectfile.Hint{}
	for _, h := range hints {
		hintsOf[h.Project] = append(hintsOf[h.Project], h.Hint)
	}

	for _, p := range s.Cfg.Projects {
		if s.mayRead(p.Name) != nil {
			continue
		}
		v := ViewOf(p)
		v.Envs = v.Envs[:0]
		for _, e := range p.EffectiveEnvs() {
			v.Envs = append(v.Envs, string(e))
		}
		row := WorkspaceProject{ProjectView: v, HasFile: slices.Contains(files, p.Name), Problems: problemsOf[p.Name], Hints: hintsOf[p.Name],
			Environments: p.Environments, EnvsUnset: len(p.Envs) == 0}
		row.File, _ = s.ProjectFile(p.Name)
		if row.HasFile {
			row.Written = writtenLockfiles(row.File)
		}
		w.Projects = append(w.Projects, row)
	}
	for _, br := range s.Cfg.Broken {
		if s.mayRead(br.Name) != nil {
			continue
		}
		// the parse error is already in Broken; the file-level issue would say it twice
		rest := slices.DeleteFunc(slices.Clone(problemsOf[br.Name]), func(i projectfile.Issue) bool { return i.Field == "file" })
		w.Projects = append(w.Projects, WorkspaceProject{ProjectView: ProjectView{Name: br.Name}, HasFile: true, File: br.File,
			Broken: strings.TrimPrefix(br.Err, br.File+": "), Problems: rest})
	}
	off, err := s.DisabledProjects()
	if err != nil {
		warn("disabled projects", err)
	}
	for _, name := range off {
		if slices.ContainsFunc(w.Projects, func(p WorkspaceProject) bool { return p.Name == name }) {
			continue // a live file of the same name wins; the disabled one is a leftover
		}
		file, _ := s.DisabledFile(name)
		w.Projects = append(w.Projects, WorkspaceProject{ProjectView: ProjectView{Name: name}, HasFile: true, File: file, Disabled: true})
	}
	byVendor(w.Projects)
	for _, p := range w.Projects {
		if p.Disabled {
			continue
		}
		issues, err := s.List(query.Filter{Project: p.Name})
		if err != nil {
			return Workspace{}, err
		}
		if len(issues) > 0 {
			w.Issues[p.Name] = issues
		}
	}
	return w, nil
}

// byVendor lists the projects of one vendor together, the vendors in
// alphabetical order and the projects without a vendor last. Without any
// vendor the order stays as it was.
func byVendor(ps []WorkspaceProject) {
	if !slices.ContainsFunc(ps, func(p WorkspaceProject) bool { return p.Vendor != "" }) {
		return
	}
	rank := func(p WorkspaceProject) string {
		if p.Vendor == "" {
			return "\xff"
		}
		return p.Vendor
	}
	slices.SortStableFunc(ps, func(a, b WorkspaceProject) int { return strings.Compare(rank(a), rank(b)) })
}

// writtenLockfiles reads the lockfiles of a project file as they are written
// there; nil when the file does not parse.
func writtenLockfiles(path string) []LockEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	f, err := projectfile.Parse(data)
	if err != nil {
		return nil
	}
	return ViewOf(f.Project()).Lockfiles
}
