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
	"github.com/b070nd/cvewatch/app/src/status"
)

// addSetupTools registers the tools an agent needs to set the monitor up:
// find technologies, look at a repository, see health, and change project
// files. Only edit_project writes, so only it needs allow-write.
func addSetupTools(srv *mcp.Server, s *server, allowWrite bool) {
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(srv, &mcp.Tool{Name: "search_catalog", Annotations: ro,
		Description: "Search the technology catalog (open and closed source: runtimes, frameworks, databases, servers, platforms and so on) by name, vendor or keyword, optionally within one category. Use the returned name in a project's techs."}, s.searchCatalog)
	mcp.AddTool(srv, &mcp.Tool{Name: "discover_stack", Annotations: ro,
		Description: "Look at a repository folder on this machine and propose the technologies, versions and lockfiles it uses, each with evidence and a confidence. Reads files only; nothing is executed or changed. Treat low-confidence proposals as questions for the user."}, s.discover)
	mcp.AddTool(srv, &mcp.Tool{Name: "get_status", Annotations: ro,
		Description: "Health of the monitor itself: whether the daemon is running, whether each feed and notification channel works, and what the last cycles did."}, s.status)
	mcp.AddTool(srv, &mcp.Tool{Name: "list_projects", Annotations: ro,
		Description: "List the monitored projects with their environments, declared technologies and lockfiles."}, s.projects)
	mcp.AddTool(srv, &mcp.Tool{Name: "preview_project_change", Annotations: ro,
		Description: "Show what a change to a project file would do (diff and problems) without writing anything. A project that does not exist yet is created by its first change."}, s.previewProject)
	if allowWrite {
		no := false
		mcp.AddTool(srv, &mcp.Tool{Name: "edit_project",
			Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &no},
			Description: "Apply changes to a project file (created if new): technologies, versions, environments, lockfiles. Comments in the file are kept, the old file is backed up and the change is audited. Run preview_project_change first and show the user the diff. Only declare what the user confirmed."}, s.editProject)
	}
}

type searchIn struct {
	Query    string `json:"query,omitempty" jsonschema:"words to look for in names, vendors and keywords; empty lists the category"`
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
	Count      int         `json:"count"`
	Techs      []techEntry `json:"techs"`
	Categories []string    `json:"categories"`
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
	Dir string `json:"dir" jsonschema:"absolute path of the repository or monorepo folder to look at"`
}

func (s *server) discover(_ context.Context, _ *mcp.CallToolRequest, in discoverIn) (*mcp.CallToolResult, discovery.Result, error) {
	var out discovery.Result
	if !filepath.IsAbs(in.Dir) {
		return nil, out, errors.New("dir must be an absolute path")
	}
	err := s.withRead(func(sess *ops.Session) (err error) {
		out, err = discovery.Scan(in.Dir, sess.Cfg.Catalog, discovery.Options{})
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

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type opIn struct {
	Kind     string   `json:"kind" jsonschema:"set_tech, remove_tech, set_envs, set_env_tech, remove_env_tech, set_image, add_lockfile or remove_lockfile"`
	Tech     string   `json:"tech,omitempty" jsonschema:"catalog name, for the *_tech kinds"`
	Version  string   `json:"version,omitempty" jsonschema:"version or series such as 8.2; for set_tech empty means unknown"`
	Env      string   `json:"env,omitempty" jsonschema:"dev, int, staging or prod, for set_env_tech, remove_env_tech and set_image"`
	Envs     []string `json:"envs,omitempty" jsonschema:"for set_envs; empty means all four"`
	Image    string   `json:"image,omitempty" jsonschema:"image tag or digest, for set_image; empty clears"`
	LockType string   `json:"lockfile_type,omitempty" jsonschema:"composer, npm, go, pip and so on, for the lockfile kinds"`
	LockPath string   `json:"lockfile_path,omitempty" jsonschema:"path of the lockfile on the monitor's machine"`
	LockEnv  string   `json:"lockfile_env,omitempty" jsonschema:"only this environment; empty means all"`
}

type projectIn struct {
	Project string `json:"project" jsonschema:"project name; letters, digits, dash and underscore"`
	Changes []opIn `json:"changes" jsonschema:"the edits, applied in order; none are applied if one fails"`
}

func (in projectIn) change(save bool) ops.ProjectChange {
	c := ops.ProjectChange{Project: in.Project, Save: save}
	for _, o := range in.Changes {
		op := projectfile.Op{Kind: o.Kind, Tech: o.Tech, Version: o.Version, Env: model.Env(o.Env), Image: o.Image,
			Lockfile: model.Lockfile{Type: o.LockType, Path: o.LockPath, Env: model.Env(o.LockEnv)}}
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
