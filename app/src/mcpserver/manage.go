package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/ops"
)

type manageIn struct {
	Verb          string `json:"verb" jsonschema:"rename, duplicate, delete, disable or enable"`
	Project       string `json:"project" jsonschema:"the project to change"`
	NewName       string `json:"new_name,omitempty" jsonschema:"the new name, for rename and duplicate"`
	CloseFindings bool   `json:"close_findings,omitempty" jsonschema:"delete only: mark the project's open findings ignored; otherwise they stay as they are"`
	Confirm       bool   `json:"confirm,omitempty" jsonschema:"false (default) only returns the consequences; true carries the change out, after the user has seen them"`
}

func (s *server) manageProject(_ context.Context, _ *mcp.CallToolRequest, in manageIn) (*mcp.CallToolResult, ops.LifecyclePreview, error) {
	req := ops.LifecycleRequest{Verb: ops.LifecycleVerb(in.Verb), Project: in.Project, NewName: in.NewName, CloseFindings: in.CloseFindings}
	var out ops.LifecyclePreview
	if !in.Confirm {
		err := s.withRead(func(sess *ops.Session) (err error) {
			out, err = sess.ProjectLifecycle(req)
			return err
		})
		return nil, out, err
	}
	req.Apply, req.Confirm = true, true
	err := s.with(func(sess *ops.Session) (err error) {
		out, err = sess.ProjectLifecycle(req)
		return err
	})
	return nil, out, err
}

type settingEdit struct {
	Doc   string `json:"doc,omitempty" jsonschema:"document: config, techs or sources/NAME; empty lets the path decide (a new feed goes to sources/custom)"`
	Op    string `json:"op" jsonschema:"set (give a path a value, or add a map entry), unset (remove a value, a map entry or a list item) or append (add an item to a list)"`
	Path  string `json:"path" jsonschema:"setting path from the schema, such as http.timeout, policy.rules or sources.[id=nvd].url; a name holding a dot is written in brackets, a list item is picked with [key=value] or its position"`
	Value any    `json:"value,omitempty" jsonschema:"the new value: text such as 45s or true (converted to the setting's type), a number, a list, or an object for a record; not used by unset"`
}

type settingsChangeIn struct {
	Edits []settingEdit `json:"edits" jsonschema:"the edits, applied in order; none are applied if one fails"`
}

func (in settingsChangeIn) change(save bool) (ops.SettingsChange, error) {
	c := ops.SettingsChange{Save: save}
	for i, e := range in.Edits {
		switch op := confdoc.Op(e.Op); op {
		case confdoc.OpSet, confdoc.OpUnset, confdoc.OpAppend:
			c.Edits = append(c.Edits, confdoc.Edit{Doc: e.Doc, Op: op, Path: e.Path, Value: e.Value})
		default:
			// replace swaps whole documents, whose text hides secrets: it would write the placeholder over them
			return c, fmt.Errorf("edit %d: op %q is not available here (use set, unset or append)", i+1, e.Op)
		}
	}
	return c, nil
}

// withSettings opens the configuration documents without loading them, so a
// broken config.yaml can still be read and repaired field by field.
func (s *server) withSettings(fn func(*ops.SettingsSession) error) error {
	ss, err := ops.OpenSettings(s.root)
	if err != nil {
		return err
	}
	ss.Actor = "mcp:" + audit.Actor()
	return fn(ss)
}

func (s *server) previewSettings(_ context.Context, _ *mcp.CallToolRequest, in settingsChangeIn) (*mcp.CallToolResult, ops.SettingsPreview, error) {
	var out ops.SettingsPreview
	c, err := in.change(false)
	if err != nil {
		return nil, out, err
	}
	err = s.withSettings(func(ss *ops.SettingsSession) (err error) {
		out, err = ss.Edit(c)
		return err
	})
	return nil, out, err
}

func (s *server) editSettings(_ context.Context, _ *mcp.CallToolRequest, in settingsChangeIn) (*mcp.CallToolResult, ops.SettingsPreview, error) {
	var out ops.SettingsPreview
	c, err := in.change(true)
	if err != nil {
		return nil, out, err
	}
	err = s.withSettings(func(ss *ops.SettingsSession) (err error) {
		out, err = ss.Edit(c)
		return err
	})
	return nil, out, err
}

type settingsIn struct {
	IncludeSchema bool `json:"include_schema,omitempty" jsonschema:"also return every setting with its path, type, allowed values, default and help"`
}

type settingsDoc struct {
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Path    string          `json:"path,omitempty"`
	Exists  bool            `json:"exists"`
	Error   string          `json:"error,omitempty" jsonschema:"set when the file cannot be read as YAML; its values are then not listed"`
	Entries []confdoc.Entry `json:"entries,omitempty"`
}

type settingsOut struct {
	Docs   []settingsDoc   `json:"docs"`
	Issues []confdoc.Issue `json:"issues"`
	Schema []confdoc.Field `json:"schema,omitempty"`
}

func (s *server) getSettings(_ context.Context, _ *mcp.CallToolRequest, in settingsIn) (*mcp.CallToolResult, settingsOut, error) {
	out := settingsOut{Docs: []settingsDoc{}, Issues: []confdoc.Issue{}}
	err := s.withSettings(func(ss *ops.SettingsSession) error {
		v, err := ss.View()
		if err != nil {
			return err
		}
		for _, d := range v.Docs {
			if d.Layer == confdoc.LayerUser { // shipped documents are reference only
				out.Docs = append(out.Docs, settingsDoc{ID: d.ID, Kind: d.Kind, Path: d.Path, Exists: d.Exists, Error: d.Error, Entries: d.Entries})
			}
		}
		out.Issues = append(out.Issues, v.Issues...)
		if in.IncludeSchema {
			out.Schema = confdoc.Schema()
		}
		return nil
	})
	return nil, out, err
}
