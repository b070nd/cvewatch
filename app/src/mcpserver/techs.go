package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// addTechTools registers the tools for technologies of the user's own: a
// suggestion lookup anyone may use, a preview, and the write tool behind allow-write.
func addTechTools(srv *mcp.Server, s *server, allowWrite bool) {
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(srv, &mcp.Tool{Name: "suggest_tech", Annotations: ro,
		Description: "Find which catalog technology a typed term means, tolerating typos (rabbitMW finds rabbitmq). When nothing is close, found is false and suggestions is empty: the term is not in the catalog, and add_tech can add it as the user's own keyword."}, s.suggestTech)
	mcp.AddTool(srv, &mcp.Tool{Name: "preview_tech_change", Annotations: ro,
		Description: "Show what adding, editing or removing one of the user's own technologies would do to techs.yaml (diff and problems) without writing anything. Same input as edit_tech."}, s.previewTech)
	if allowWrite {
		no := false
		mcp.AddTool(srv, &mcp.Tool{Name: "edit_tech",
			Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &no},
			Description: "Add, edit or remove a technology of the user's own in techs.yaml, for something the catalog does not have. Advisories match it when their title or text names one of its keywords as a whole word (default: the name); cpe names make it match NVD product data too. The change is audited and the old file is backed up. Run preview_tech_change first and show the user the diff. Only the user's own entries can be edited or removed."}, s.editTech)
	}
}

type suggestIn struct {
	Term  string `json:"term" jsonschema:"what the user typed, for example rabbitMW or algolia"`
	Limit int    `json:"limit,omitempty" jsonschema:"at most this many suggestions (default 5)"`
}

type suggestOut struct {
	Found       bool        `json:"found" jsonschema:"the term is a catalog name or alias"`
	Tech        *techEntry  `json:"tech,omitempty"`
	Suggestions []techEntry `json:"suggestions" jsonschema:"close catalog entries, best first; empty when the term is not in the catalog"`
}

func entry(t model.Tech) techEntry {
	return techEntry{Name: t.Name, Title: t.Title, Category: t.Category, Vendor: t.Vendor, Source: t.Source, Matches: matchKind(t)}
}

func (s *server) suggestTech(_ context.Context, _ *mcp.CallToolRequest, in suggestIn) (*mcp.CallToolResult, suggestOut, error) {
	out := suggestOut{Suggestions: []techEntry{}}
	err := s.withRead(func(sess *ops.Session) error {
		cat := sess.Cfg.Catalog
		if t, ok := cat.ForTerm(in.Term); ok {
			e := entry(t)
			out.Found, out.Tech = true, &e
			return nil
		}
		for _, t := range cat.Suggest(in.Term, min(max(in.Limit, 1), 20)) {
			out.Suggestions = append(out.Suggestions, entry(t))
		}
		return nil
	})
	return nil, out, err
}

type techIn struct {
	Action   string   `json:"action" jsonschema:"add, edit or remove"`
	Name     string   `json:"name" jsonschema:"short key used in project files: lowercase letters, digits, - and _"`
	Keywords []string `json:"keywords,omitempty" jsonschema:"words advisories use for it, matched as whole words; empty means the name. For edit, the new list (empty removes it)"`
	Excludes []string `json:"excludes,omitempty" jsonschema:"an item containing any of these is not about this technology"`
	CPE      []string `json:"cpe,omitempty" jsonschema:"NVD CPE names vendor:product in lowercase; they make the technology match NVD product data and versions"`
	Category string   `json:"category,omitempty" jsonschema:"for example database, runtime, framework, web-server, cms, search, other"`
	Title    string   `json:"title,omitempty" jsonschema:"display name"`
	Vendor   string   `json:"vendor,omitempty"`
}

func (s *server) previewTech(_ context.Context, _ *mcp.CallToolRequest, in techIn) (*mcp.CallToolResult, ops.SettingsPreview, error) {
	var out ops.SettingsPreview
	err := s.withSettings(func(ss *ops.SettingsSession) (err error) {
		out, err = runTech(ss, in, false)
		return err
	})
	return nil, out, err
}

func (s *server) editTech(_ context.Context, _ *mcp.CallToolRequest, in techIn) (*mcp.CallToolResult, ops.SettingsPreview, error) {
	var out ops.SettingsPreview
	err := s.withSettings(func(ss *ops.SettingsSession) (err error) {
		out, err = runTech(ss, in, true)
		return err
	})
	return nil, out, err
}

func runTech(ss *ops.SettingsSession, in techIn, save bool) (ops.SettingsPreview, error) {
	t := model.Tech{Name: in.Name, Aliases: in.Keywords, Excludes: in.Excludes, CPE: in.CPE, Category: in.Category, Title: in.Title, Vendor: in.Vendor}
	c := ops.TechChange{Tech: t, Save: save}
	switch in.Action {
	case "add":
		return ss.AddTech(c)
	case "edit":
		return ss.EditTech(c)
	case "remove":
		return ss.RemoveTech(c)
	}
	return ops.SettingsPreview{}, fmt.Errorf("action %q is not add, edit or remove", in.Action)
}
