package mcpserver

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/projectflow"
	"github.com/b070nd/cvewatch/app/src/status"
)

// addSetupTools registers the tools an agent needs to set the monitor up:
// find technologies, look at a repository, see health, and change project
// files and settings. Only edit_project, edit_settings and manage_project
// write, so only they need allow-write.
func addSetupTools(srv *mcp.Server, s *server, allowWrite bool) {
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(srv, &mcp.Tool{Name: "search_catalog", Annotations: ro,
		Description: "Search the technology catalog (open and closed source: runtimes, frameworks, databases, servers, platforms and so on) by name, vendor or alias, optionally within one category. Use the returned name in a project's techs."}, s.searchCatalog)
	mcp.AddTool(srv, &mcp.Tool{Name: "discover_stack", Annotations: ro,
		Description: "Look at a repository folder, or a single Dockerfile, compose file or Kubernetes manifest, on this machine and propose the technologies, versions and lockfiles it uses, each with evidence and a confidence. Technologies that only appear in container files are marked infra, with their catalog category. Reads files only; nothing is executed or changed. Treat low-confidence proposals as questions for the user."}, s.discover)
	mcp.AddTool(srv, &mcp.Tool{Name: "get_status", Annotations: ro,
		Description: "Health of the monitor itself: whether the daemon is running, whether each feed and notification channel works, and what the last cycles did."}, s.status)
	mcp.AddTool(srv, &mcp.Tool{Name: "list_projects", Annotations: ro,
		Description: "List the monitored projects with their environments, declared technologies and lockfiles."}, s.projects)
	mcp.AddTool(srv, &mcp.Tool{Name: "check_projects", Annotations: ro,
		Description: "Find problems in project files: unknown or misspelled technologies, lockfiles that are missing, unreadable or of the wrong type, environments that are not monitored. Each problem names its project and field and may list fixes, each a label and the changes to pass to preview_project_change and edit_project. Without a project, every project you may see is checked."}, s.checkProjects)
	mcp.AddTool(srv, &mcp.Tool{Name: "preview_project_change", Annotations: ro, InputSchema: projectInSchema(),
		Description: "Show what a change to a project file would do (diff and problems) without writing anything. A project that does not exist yet is created by its first change. The kinds of change:\n" + projectfile.KindHelp()}, s.previewProject)
	mcp.AddTool(srv, &mcp.Tool{Name: "get_settings", Annotations: ro,
		Description: "Read the configuration the user edits: config.yaml (interval, http, notify, policy rules, access), techs.yaml and the sources/*.yaml feeds, as the values that are set (defaults are not listed). Secret values read (set). Works when a file is broken: that file reports its error. With include_schema, also every setting with its path, type, allowed values and help, which is what edit paths are built from."}, s.getSettings)
	mcp.AddTool(srv, &mcp.Tool{Name: "preview_settings_change", Annotations: ro,
		Description: "Show what changes to the settings would do (diff and problems) without writing anything. Each edit is set, unset or append on a path from the schema, for example set http.timeout 45s, unset http.retries or append policy.rules {name, ...}. All edits apply or none do."}, s.previewSettings)
	addTechTools(srv, s, allowWrite)
	if allowWrite {
		no := false
		mcp.AddTool(srv, &mcp.Tool{Name: "edit_project", InputSchema: projectInSchema(),
			Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &no},
			Description: "Apply changes to a project file (created if new): technologies, versions, environments, lockfiles, the since date, how often it is refreshed. Comments in the file are kept, the old file is backed up and the change is audited. Run preview_project_change first and show the user the diff. Only declare what the user confirmed. The kinds of change:\n" + projectfile.KindHelp()}, s.editProject)
		mcp.AddTool(srv, &mcp.Tool{Name: "edit_settings",
			Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &no},
			Description: "Apply changes to the settings (config.yaml, techs.yaml, sources/*.yaml). Comments are kept, the old file is backed up, the change is audited, and a change that would not validate is refused. Run preview_settings_change first and show the user the diff. The daemon uses the new settings from its next cycle."}, s.editSettings)
		mcp.AddTool(srv, &mcp.Tool{Name: "manage_project",
			Description: "Rename, duplicate, delete, disable or enable a whole project. Without confirm it only returns the consequences: findings affected, access rules rewritten, files moved. Show them to the user and call again with confirm true only after they agreed. Rename moves the findings to the new name, delete moves the file to the backups (close_findings also marks its open findings ignored), disable renames the file to .disabled and enable reverses that."}, s.manageProject)
	}
}

type searchIn struct {
	Query    string `json:"query,omitempty" jsonschema:"words to look for in names, vendors and aliases; empty lists the category"`
	Category string `json:"category,omitempty" jsonschema:"only this category, for example database, runtime, framework, web-server, cms"`
	Limit    int    `json:"limit,omitempty" jsonschema:"at most this many results (default 20, maximum 100)"`
}

type techEntry struct {
	Name     string `json:"name"`
	Title    string `json:"title,omitempty"`
	Category string `json:"category,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Source   string `json:"source,omitempty" jsonschema:"open, closed or mixed"`
	Matches  string `json:"matches" jsonschema:"how advisories are matched: cpe or words"`
}

type searchOut struct {
	Count       int         `json:"count"`
	Techs       []techEntry `json:"techs"`
	Categories  []string    `json:"categories"`
	NotFound    bool        `json:"not_found,omitempty" jsonschema:"the query matches nothing in the catalog; it can be added as the user's own keyword with edit_tech"`
	Suggestions []techEntry `json:"suggestions,omitempty" jsonschema:"close catalog entries for a query that matched nothing"`
}

func (s *server) searchCatalog(_ context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, searchOut, error) {
	out := searchOut{Techs: []techEntry{}}
	err := s.withRead(func(sess *ops.Session) error {
		cat := sess.Cfg.Catalog
		out.Categories = cat.UsedCategories()
		techs := cat.All()
		if q := strings.TrimSpace(in.Query); q != "" {
			techs = cat.Search(q)
		} else if in.Category == "" {
			return errors.New("give a query or a category")
		}
		if q := strings.TrimSpace(in.Query); q != "" && len(techs) == 0 && in.Category == "" {
			out.NotFound = true
			for _, t := range cat.Suggest(q, 5) {
				out.Suggestions = append(out.Suggestions, entry(t))
			}
		}
		limit := min(max(in.Limit, 1), 100)
		if in.Limit == 0 {
			limit = 20
		}
		for _, t := range techs {
			if in.Category != "" && !strings.EqualFold(t.Category, in.Category) {
				continue
			}
			if len(out.Techs) < limit {
				out.Techs = append(out.Techs, techEntry{Name: t.Name, Title: t.Title, Category: t.Category,
					Vendor: t.Vendor, Source: t.Source, Matches: matchKind(t)})
			}
			out.Count++
		}
		return nil
	})
	return nil, out, err
}

func matchKind(t model.Tech) string {
	if len(t.CPE) > 0 {
		return "cpe"
	}
	return "words"
}

type discoverIn struct {
	Dir string `json:"dir" jsonschema:"absolute path of the repository or monorepo folder to look at, or of a Dockerfile, compose file or Kubernetes manifest"`
}

func (s *server) discover(_ context.Context, _ *mcp.CallToolRequest, in discoverIn) (*mcp.CallToolResult, discovery.Result, error) {
	var out discovery.Result
	if !filepath.IsAbs(in.Dir) {
		return nil, out, errors.New("dir must be an absolute path")
	}
	err := s.withRead(func(sess *ops.Session) (err error) {
		src, err := projectflow.ResolveSource(in.Dir)
		if err != nil {
			return err
		}
		out, err = projectflow.ScanSource(src, sess.Cfg.Catalog)
		return err
	})
	return nil, out, err
}

func (s *server) status(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, status.Report, error) {
	var out status.Report
	err := s.withRead(func(sess *ops.Session) (err error) {
		out, err = sess.Status()
		return err
	})
	return nil, out, err
}

type projectsOut struct {
	Projects []ops.ProjectView `json:"projects"`
}

func (s *server) projects(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, projectsOut, error) {
	out := projectsOut{Projects: []ops.ProjectView{}}
	err := s.withRead(func(sess *ops.Session) error {
		names, err := sess.ProjectNames()
		if err != nil {
			return err
		}
		for _, p := range sess.Cfg.Projects {
			if contains(names, p.Name) {
				out.Projects = append(out.Projects, ops.ViewOf(p))
			}
		}
		return nil
	})
	return nil, out, err
}

type checkIn struct {
	Project string `json:"project,omitempty" jsonschema:"only this project; empty checks every project"`
}

type checkOut struct {
	Issues []projectfile.Issue `json:"issues"`
	Hints  []ops.ProjectHint   `json:"hints" jsonschema:"what may not be covered or cause trouble, beyond the issues: unknown technologies with suggestions or the keyword to add, missing versions, lockfiles, a start date"`
}

func (s *server) checkProjects(_ context.Context, _ *mcp.CallToolRequest, in checkIn) (*mcp.CallToolResult, checkOut, error) {
	out := checkOut{Issues: []projectfile.Issue{}, Hints: []ops.ProjectHint{}}
	err := s.withReadRepair(func(sess *ops.Session) error {
		issues, err := sess.ProjectProblems(strings.TrimSpace(in.Project))
		out.Issues = append(out.Issues, issues...)
		if err != nil {
			return err
		}
		hints, err := sess.ProjectHints(strings.TrimSpace(in.Project))
		out.Hints = append(out.Hints, hints...)
		return err
	})
	return nil, out, err
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// opIn is one change. Its json names are the fields of projectfile.Op, with the
// lockfile also accepted flattened; projectInSchema describes it from projectfile.OpTable.
type opIn struct {
	Kind     string   `json:"kind"`
	Tech     string   `json:"tech,omitempty"`
	Version  string   `json:"version,omitempty"`
	Env      string   `json:"env,omitempty"`
	Envs     []string `json:"envs,omitempty"`
	To       string   `json:"to,omitempty"`
	Image    string   `json:"image,omitempty"`
	Since    string   `json:"since,omitempty"`
	Every    string   `json:"every,omitempty"`
	Auto     *bool    `json:"auto,omitempty"`
	LockType string   `json:"lockfile_type,omitempty"`
	LockPath string   `json:"lockfile_path,omitempty"`
	LockEnv  string   `json:"lockfile_env,omitempty"`
	LockDev  bool     `json:"lockfile_dev,omitempty"`
	Lockfile *lockIn  `json:"lockfile,omitempty"`
}

type lockIn struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Env  string `json:"env,omitempty"`
	Dev  bool   `json:"dev,omitempty"`
}

type projectIn struct {
	Project string `json:"project"`
	Changes []opIn `json:"changes"`
}

func (in projectIn) change(save bool) ops.ProjectChange {
	c := ops.ProjectChange{Project: in.Project, Save: save}
	for _, o := range in.Changes {
		op := projectfile.Op{Kind: o.Kind, Tech: o.Tech, Version: o.Version, Env: model.Env(o.Env), To: model.Env(o.To), Image: o.Image, Since: o.Since, Every: o.Every, Auto: o.Auto,
			Lockfile: model.Lockfile{Type: o.LockType, Path: o.LockPath, Env: model.Env(o.LockEnv), Dev: o.LockDev}}
		if l := o.Lockfile; l != nil {
			op.Lockfile = model.Lockfile{Type: l.Type, Path: l.Path, Env: model.Env(l.Env), Dev: l.Dev}
		}
		for _, e := range o.Envs {
			op.Envs = append(op.Envs, model.Env(e))
		}
		c.Ops = append(c.Ops, op)
	}
	return c
}

func (s *server) previewProject(_ context.Context, _ *mcp.CallToolRequest, in projectIn) (*mcp.CallToolResult, ops.ProjectPreview, error) {
	var out ops.ProjectPreview
	err := s.withRead(func(sess *ops.Session) (err error) {
		sess.Actor = "mcp:" + audit.Actor()
		out, err = sess.EditProject(in.change(false))
		return err
	})
	return nil, out, err
}

func (s *server) editProject(_ context.Context, _ *mcp.CallToolRequest, in projectIn) (*mcp.CallToolResult, ops.ProjectPreview, error) {
	var out ops.ProjectPreview
	err := s.with(func(sess *ops.Session) (err error) {
		out, err = sess.EditProject(in.change(true))
		return err
	})
	return nil, out, err
}
