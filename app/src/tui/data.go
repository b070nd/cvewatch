package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/setup"
	"github.com/b070nd/cvewatch/app/src/status"
)

// snapshot is everything the screens show, read in one go from a read-only
// session. Screens only ever see this copy, never the session.
type snapshot struct {
	At         time.Time
	Root       string
	Issues     []query.Issue // open issues, most urgent first
	Status     status.Report
	Violations []priority.Violation
	Projects   []projectRow
	Warnings   []string // parts that could not be read; the rest is still shown
}

type projectRow struct {
	ops.ProjectView
	HasFile bool // has its own file under config/projects, so it can be edited here
}

// loadSnapshot reads the issue list (fatal when it fails: access denied, no
// state) and the rest best-effort.
func loadSnapshot(s *ops.Session) (*snapshot, error) {
	issues, err := s.List(query.Filter{})
	if err != nil {
		return nil, err
	}
	sn := &snapshot{At: s.Now(), Root: s.Cfg.Root, Issues: issues}
	warn := func(what string, err error) { sn.Warnings = append(sn.Warnings, what+": "+oneLine(err.Error())) }
	if sn.Status, err = s.Status(); err != nil {
		warn("status", err)
	}
	if sn.Violations, err = s.Violations(); err != nil {
		warn("policy", err)
	}
	files, err := s.ProjectNames()
	if err != nil {
		warn("project files", err)
	}
	allowed, _, open := s.Cfg.Allowed(audit.Actor())
	for _, p := range s.Cfg.Projects {
		if !open && !slices.Contains(allowed, p.Name) {
			continue
		}
		v := ops.ViewOf(p)
		v.Envs = v.Envs[:0]
		for _, e := range p.EffectiveEnvs() {
			v.Envs = append(v.Envs, string(e))
		}
		sn.Projects = append(sn.Projects, projectRow{ProjectView: v, HasFile: slices.Contains(files, p.Name)})
	}
	return sn, nil
}

// counts is the overview's arithmetic, kept apart so it can be tested.
type counts struct {
	Issues   int
	Findings int
	BySev    map[int]int // by severity rank, open issues
	ByEnv    map[model.Env]int
	KEV      int
	ProdOpen int
	Overdue  int
}

func countsOf(issues []query.Issue) counts {
	c := counts{BySev: map[int]int{}, ByEnv: map[model.Env]int{}, Issues: len(issues)}
	for _, is := range issues {
		c.BySev[is.Severity.Rank()]++
		if is.KEV != nil {
			c.KEV++
		}
		if is.ProdOpen {
			c.ProdOpen++
		}
		for _, t := range is.Targets {
			if t.Status != model.StatusOpen {
				continue
			}
			c.Findings++
			c.ByEnv[t.Env]++
			if t.Overdue {
				c.Overdue++
			}
		}
	}
	return c
}

// ---- messages ----

type (
	tickMsg struct{}
	dataMsg struct {
		snap *snapshot
		err  error
	}
	detailMsg struct {
		id    string
		is    query.Issue
		ex    *ops.Explanation
		exErr error
		err   error
	}
	actionMsg struct {
		info string
		warn error // the change landed but a follow-up step failed
		err  error
	}
	flowMsg struct {
		flow     *setup.Flow
		creating bool
		name     string
		note     string
		err      error
	}
	scanMsg struct {
		res discovery.Result
		err error
	}
	previewMsg struct {
		f    *form
		seq  int
		prev ops.ProjectPreview
		err  error
	}
	savedMsg struct {
		f    *form
		prev ops.ProjectPreview
		err  error
	}
)

// ---- commands: every Backend call runs here, never in Update ----

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return tickMsg{} })
}

func loadCmd(b Backend) tea.Cmd {
	return func() tea.Msg {
		var sn *snapshot
		err := b.Read(func(s *ops.Session) (e error) { sn, e = loadSnapshot(s); return e })
		return dataMsg{snap: sn, err: err}
	}
}

func detailCmd(b Backend, id string) tea.Cmd {
	return func() tea.Msg {
		m := detailMsg{id: id}
		m.err = b.Read(func(s *ops.Session) (e error) {
			if m.is, _, e = s.Show(id); e != nil {
				return e
			}
			ex, xe := s.Explain(id)
			if xe != nil {
				m.exErr = xe
			} else {
				m.ex = &ex
			}
			return nil
		})
		return m
	}
}

var changeWords = map[model.Status]string{
	model.StatusFixed: "marked fixed", model.StatusIgnored: "ignored",
	model.StatusNotAffected: "marked not affected", model.StatusOpen: "reopened",
}

func where(project string, env model.Env) string {
	if env == "" {
		return project + " (all environments)"
	}
	return project + "/" + string(env)
}

// resolveCmd applies a status change in one short write session. Resolve can
// save the change and still fail afterwards (the report file); that is a
// warning, not a failure.
func resolveCmd(b Backend, c ops.Change) tea.Cmd {
	return func() tea.Msg {
		var n int
		var late error
		err := b.Write(func(s *ops.Session) error {
			var e error
			if n, e = s.Resolve(c); n > 0 {
				late = e
				return nil
			}
			return e
		})
		if err != nil {
			return actionMsg{err: err}
		}
		return actionMsg{info: fmt.Sprintf("%s %s in %s (%s)", c.ID, changeWords[c.Status], where(c.Project, c.Env), plural(n, "finding", "findings")), warn: late}
	}
}

func assignCmd(b Backend, a ops.Assignment) tea.Cmd {
	return func() tea.Msg {
		var n int
		var late error
		err := b.Write(func(s *ops.Session) error {
			var e error
			if n, e = s.Assign(a); n > 0 {
				late = e
				return nil
			}
			return e
		})
		if err != nil {
			return actionMsg{err: err}
		}
		return actionMsg{info: fmt.Sprintf("%s assigned in %s (%s)", a.ID, where(a.Project, a.Env), plural(n, "finding", "findings")), warn: late}
	}
}

// catalogOf is the catalog a session offers, never nil.
func catalogOf(s *ops.Session) *catalog.Catalog {
	if s.Cfg.Catalog != nil {
		return s.Cfg.Catalog
	}
	return catalog.New(s.Cfg.Techs)
}

// expand resolves a typed path: ~ is the home folder.
func expand(p string) string {
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(filepath.Separator)) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// startFlowCmd builds a setup flow: for a new project when name is empty,
// otherwise for editing the named one. A folder is scanned first and merged
// in. The flow is handed to Update only once it is complete, so no goroutine
// shares it.
func startFlowCmd(b Backend, name, dir string) tea.Cmd {
	return func() tea.Msg {
		var out flowMsg
		out.err = b.Read(func(s *ops.Session) error {
			cat := catalogOf(s)
			files, err := s.ProjectNames()
			if err != nil {
				return err
			}
			if name == "" {
				taken := map[string]bool{}
				for _, n := range files {
					taken[n] = true
				}
				for _, p := range s.Cfg.Projects {
					taken[p.Name] = true
				}
				out.flow = setup.NewFlow(cat, nil)
				out.flow.NameTaken = func(n string) bool { return taken[n] }
				out.creating = true
			} else {
				i := slices.IndexFunc(s.Cfg.Projects, func(p model.Project) bool { return p.Name == name })
				if i < 0 || !slices.Contains(files, name) {
					return fmt.Errorf("project %q has no file under config/projects, so it cannot be edited here", name)
				}
				if _, err := s.EditProject(ops.ProjectChange{Project: name}); err != nil { // access check, nothing changes
					return err
				}
				// config/projects is where ops keeps project files.
				path, err := projectfile.Path(filepath.Join(s.Cfg.Root, "config", "projects"), name)
				if err != nil {
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				existing := s.Cfg.Projects[i]
				out.flow = setup.NewFlow(cat, &existing)
				out.flow.SetExistingBytes(data)
				out.name = name
			}
			if dir != "" {
				res, err := discovery.Scan(expand(dir), cat, discovery.Options{})
				if err != nil {
					return err
				}
				out.flow.UseDiscovery(res.Root, res)
				out.note = scanNote(res)
			}
			return nil
		})
		return out
	}
}

func scanNote(res discovery.Result) string {
	s := fmt.Sprintf("scanned %s: %s, %s", clean(res.Root), plural(len(res.Techs), "technology", "technologies"), plural(len(res.Lockfiles), "lockfile", "lockfiles"))
	if res.Truncated {
		s += " (scan stopped early)"
	}
	return s
}

// scanCmd scans a folder for merging into a running flow. The merge itself
// happens in Update.
func scanCmd(b Backend, dir string) tea.Cmd {
	return func() tea.Msg {
		var m scanMsg
		m.err = b.Read(func(s *ops.Session) (e error) {
			m.res, e = discovery.Scan(expand(dir), catalogOf(s), discovery.Options{})
			return e
		})
		return m
	}
}

// relativize makes lockfile paths relative to the app root before they are
// saved, as the wizard does: discovery yields absolute paths.
func relativize(root string, edits []projectfile.Op) []projectfile.Op {
	out := slices.Clone(edits)
	for i, o := range out {
		if o.Kind == "add_lockfile" && root != "" && filepath.IsAbs(o.Lockfile.Path) {
			if rel, err := filepath.Rel(root, o.Lockfile.Path); err == nil {
				out[i].Lockfile.Path = filepath.ToSlash(rel)
			}
		}
	}
	return out
}

// previewCmd asks ops what the edits would do, without saving.
func previewCmd(b Backend, f *form, seq int, name string, edits []projectfile.Op) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Read(func(s *ops.Session) (e error) {
			p, e = s.EditProject(ops.ProjectChange{Project: name, Ops: relativize(s.Cfg.Root, edits)})
			return e
		})
		return previewMsg{f: f, seq: seq, prev: p, err: err}
	}
}

// saveCmd writes the project file in one short write session.
func saveCmd(b Backend, f *form, name string, edits []projectfile.Op) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Write(func(s *ops.Session) (e error) {
			p, e = s.EditProject(ops.ProjectChange{Project: name, Ops: relativize(s.Cfg.Root, edits), Save: true})
			return e
		})
		return savedMsg{f: f, prev: p, err: err}
	}
}
