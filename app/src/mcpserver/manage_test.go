package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func writeConf(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readConf(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func tool(t *testing.T, cs *mcp.ClientSession, name string) *mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name == name {
			return tl
		}
	}
	t.Fatalf("no tool %s in %s", name, toolNames(t, cs))
	return nil
}

// props returns the JSON schema properties at path, as the client sees them.
func props(t *testing.T, schema any, path ...string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(schema)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, p := range path {
		m, _ = m["properties"].(map[string]any)[p].(map[string]any)
		if p == "changes" {
			m, _ = m["items"].(map[string]any)
		}
	}
	out, ok := m["properties"].(map[string]any)
	if !ok {
		t.Fatalf("no properties at %v in %s", path, raw)
	}
	return out
}

func TestWriteToolsAreAbsentWithoutAllowWrite(t *testing.T) {
	ro := toolNames(t, connect(t, fixture(t), false))
	for _, want := range []string{"get_settings", "preview_settings_change", "preview_project_change", "check_projects"} {
		if !strings.Contains(ro, want) {
			t.Errorf("read-only mode must list %s: %s", want, ro)
		}
	}
	for _, bad := range []string{"edit_project", "edit_settings", "manage_project", "set_status", "refresh"} {
		if strings.Contains(ro, bad) {
			t.Errorf("read-only mode lists the write tool %s: %s", bad, ro)
		}
	}
	rw := toolNames(t, connect(t, fixture(t), true))
	for _, want := range []string{"edit_project", "edit_settings", "manage_project"} {
		if !strings.Contains(rw, want) {
			t.Errorf("-allow-write must list %s: %s", want, rw)
		}
	}
}

// The MCP schema is built from projectfile.OpTable; this is the other half of
// the parity test: every kind and every input of the table reaches the client.
func TestProjectSchemaCoversTheOpTable(t *testing.T) {
	cs := connect(t, fixture(t), true)
	for _, name := range []string{"preview_project_change", "edit_project"} {
		tl := tool(t, cs, name)
		change := props(t, tl.InputSchema, "changes")

		raw, _ := json.Marshal(change["kind"])
		var kind struct {
			Enum        []string
			Description string
		}
		json.Unmarshal(raw, &kind)
		want := projectfile.Kinds()
		sort.Strings(want)
		sort.Strings(kind.Enum)
		if !slices.Equal(kind.Enum, want) {
			t.Errorf("%s: kind enum %v, table %v", name, kind.Enum, want)
		}
		for _, k := range want {
			if !strings.Contains(kind.Description, k) || !strings.Contains(tl.Description, k) {
				t.Errorf("%s: kind %s is not described", name, k)
			}
		}

		for _, spec := range projectfile.OpTable {
			for _, p := range spec.Params {
				flat := strings.Replace(p.Name, ".", "_", 1)
				if _, ok := change[flat]; !ok {
					t.Errorf("%s: %s takes %s, which the schema lacks as %s", name, spec.Kind, p.Name, flat)
				}
				if strings.HasPrefix(p.Name, "lockfile.") {
					obj := props(t, tl.InputSchema, "changes", "lockfile")
					if _, ok := obj[strings.TrimPrefix(p.Name, "lockfile.")]; !ok {
						t.Errorf("%s: the lockfile object lacks %s", name, p.Name)
					}
				}
			}
		}

		// no input without a field in opIn and no field without an input
		var fields []string
		for i, rt := 0, reflect.TypeOf(opIn{}); i < rt.NumField(); i++ {
			fields = append(fields, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
		}
		var shown []string
		for k := range change {
			shown = append(shown, k)
		}
		sort.Strings(fields)
		sort.Strings(shown)
		if !slices.Equal(fields, shown) {
			t.Errorf("%s: schema properties %v differ from opIn fields %v", name, shown, fields)
		}
	}
}

func TestEveryExampleOfTheOpTableIsAcceptedByTheTool(t *testing.T) {
	root := fixture(t)
	writeConf(t, root, "config/projects/shop.yaml",
		"name: shop\nenvs: [dev, int, staging, prod]\ntechs: [{name: php, version: \"8.2\"}]\nlockfiles: [{type: composer, path: composer.lock, env: prod}]\nenvironments:\n  prod:\n    techs: {php: \"8.3\"}\n")
	cs := connect(t, root, false)
	for _, spec := range projectfile.OpTable {
		raw, _ := json.Marshal(spec.Example) // the JSON a check_projects fix carries
		var change map[string]any
		json.Unmarshal(raw, &change)
		res, out := call(t, cs, "preview_project_change", map[string]any{"project": "shop", "changes": []any{change}})
		if res.IsError {
			t.Errorf("%s: %s %s", spec.Kind, res.Content[0].(*mcp.TextContent).Text, raw)
		} else if !strings.Contains(out, `"saved":false`) {
			t.Errorf("%s: %s", spec.Kind, out)
		}
	}
}

func TestEditProjectTakesSinceAndLockfileDev(t *testing.T) {
	root := fixture(t)
	writeConf(t, root, "config/projects/shop.yaml", "name: shop\nenvs: [dev, prod]\ntechs: [{name: php}]\nlockfiles: [{type: composer, path: composer.lock, env: prod}]\n")
	cs := connect(t, root, true)
	changes := []any{
		map[string]any{"kind": "set_since", "since": "2026-01-31"},
		map[string]any{"kind": "set_lockfile_dev", "lockfile_path": "composer.lock", "lockfile_env": "prod", "lockfile_dev": true},
		map[string]any{"kind": "add_lockfile", "lockfile": map[string]any{"type": "npm", "path": "package-lock.json", "env": "dev", "dev": true}},
	}
	if res, out := call(t, cs, "edit_project", map[string]any{"project": "shop", "changes": changes}); res.IsError {
		t.Fatalf("%s %s", out, res.Content[0].(*mcp.TextContent).Text)
	}
	got := readConf(t, root, "config/projects/shop.yaml")
	for _, want := range []string{"since: 2026-01-31", "package-lock.json"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s:\n%s", want, got)
		}
	}
	if strings.Count(got, "dev: true") != 2 {
		t.Errorf("want dev on both lockfiles:\n%s", got)
	}
	_, out := call(t, cs, "list_projects", map[string]any{})
	if !strings.Contains(out, `"since":"2026-01-31"`) || !strings.Contains(out, `"dev":true`) {
		t.Errorf("list_projects: %s", out)
	}
}

func TestManageProjectPreviewsUntilConfirmed(t *testing.T) {
	root := fixture(t)
	cs := connect(t, root, true)
	if d := tool(t, cs, "manage_project").Description; !strings.Contains(d, "confirm") {
		t.Errorf("the description must explain confirm: %s", d)
	}
	raw, _ := json.Marshal(tool(t, cs, "manage_project").InputSchema)
	for _, v := range ops.LifecycleVerbs {
		if !strings.Contains(string(raw), string(v)) {
			t.Errorf("verb %s is not in the schema: %s", v, raw)
		}
	}

	req := map[string]any{"verb": "rename", "project": "shop", "new_name": "store"}
	res, out := call(t, cs, "manage_project", req)
	if res.IsError || !strings.Contains(out, `"applied":false`) || !strings.Contains(out, `"total":2`) || !strings.Contains(out, `"requires_confirm":true`) {
		t.Fatalf("preview: %v %s", res.IsError, out)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "projects", "shop.yaml")); err != nil {
		t.Fatal("the preview moved the project")
	}

	req["confirm"] = true
	res, out = call(t, cs, "manage_project", req)
	if res.IsError || !strings.Contains(out, `"applied":true`) {
		t.Fatalf("apply: %v %s", res.IsError, out)
	}
	if !strings.Contains(readConf(t, root, "config/projects/store.yaml"), "name: store") {
		t.Fatal("not renamed")
	}
	if _, out = call(t, cs, "list_findings", map[string]any{"project": "store"}); !strings.Contains(out, `"count":1`) {
		t.Errorf("the findings did not follow the rename: %s", out)
	}

	for _, bad := range []map[string]any{
		{"verb": "explode", "project": "store", "confirm": true},
		{"verb": "rename", "project": "store", "confirm": true},
		{"verb": "delete", "project": "nope", "confirm": true},
	} {
		if res, _ := call(t, cs, "manage_project", bad); !res.IsError {
			t.Errorf("%v must be a tool error", bad)
		}
	}
	if res, _ := call(t, cs, "manage_project", map[string]any{"verb": "delete", "project": "store", "confirm": true, "close_findings": true}); res.IsError {
		t.Error("delete with confirm must go through")
	}
	if _, err := os.Stat(filepath.Join(root, "config", "projects", "store.yaml")); err == nil {
		t.Error("not deleted")
	}
}

const settingsDocText = "# mine\ninterval: 4h   # period\nhttp:\n  timeout: 30s\n"

func TestSettingsToolsPreviewAndEdit(t *testing.T) {
	root := fixture(t)
	writeConf(t, root, "config/config.yaml", settingsDocText)
	edit := map[string]any{"edits": []any{map[string]any{"op": "set", "path": "http.timeout", "value": "45s"}}}

	ro := connect(t, root, false)
	res, out := call(t, ro, "preview_settings_change", edit)
	if res.IsError || !strings.Contains(out, `"saved":false`) || !strings.Contains(out, "45s") || !strings.Contains(out, "next daemon cycle") {
		t.Fatalf("preview: %v %s", res.IsError, out)
	}
	if readConf(t, root, "config/config.yaml") != settingsDocText {
		t.Fatal("a preview wrote config.yaml")
	}
	_, out = call(t, ro, "get_settings", map[string]any{})
	if !strings.Contains(out, `"path":"http.timeout"`) || !strings.Contains(out, `"value":"30s"`) || strings.Contains(out, `"schema"`) {
		t.Fatalf("get_settings: %s", out)
	}
	if _, out = call(t, ro, "get_settings", map[string]any{"include_schema": true}); !strings.Contains(out, `"schema"`) || !strings.Contains(out, `"path":"http.retries"`) {
		t.Fatalf("schema: %s", out)
	}

	rw := connect(t, root, true)
	if res, out = call(t, rw, "edit_settings", edit); res.IsError || !strings.Contains(out, `"saved":true`) {
		t.Fatalf("edit: %v %s", res.IsError, out)
	}
	got := readConf(t, root, "config/config.yaml")
	if !strings.Contains(got, "timeout: 45s") || !strings.Contains(got, "# mine") || !strings.Contains(got, "# period") {
		t.Fatalf("value or comments lost:\n%s", got)
	}
	for _, bad := range []map[string]any{
		{"edits": []any{map[string]any{"op": "set", "path": "http.timeout", "value": "soon"}}},
		{"edits": []any{map[string]any{"op": "set", "path": "no.such.setting", "value": "1"}}},
		{"edits": []any{map[string]any{"op": "replace", "doc": "config", "value": "interval: 1h\n"}}},
	} {
		if res, _ := call(t, rw, "edit_settings", bad); !res.IsError {
			t.Errorf("%v must be a tool error", bad)
		}
	}
	if readConf(t, root, "config/config.yaml") != got {
		t.Error("a refused edit changed the file")
	}
}

func TestSettingsSecretsAreNeverReturned(t *testing.T) {
	root := fixture(t)
	writeConf(t, root, "sources/s.yaml", "sources:\n  - id: priv\n    type: rss\n    url: https://feed.example.com/rss?token=SECRET-TOKEN\n    headers:\n      X-Key: SECRET-HEADER\n")
	cs := connect(t, root, true)
	for name, args := range map[string]map[string]any{
		"get_settings":            {"include_schema": true},
		"preview_settings_change": {"edits": []any{map[string]any{"op": "set", "path": "sources.[id=priv].url", "value": "https://feed.example.com/rss?token=SECRET-NEW"}}},
		"edit_settings":           {"edits": []any{map[string]any{"op": "set", "path": "sources.[id=priv].headers.X-Key", "value": "SECRET-OTHER"}}},
	} {
		res, out := call(t, cs, name, args)
		if res.IsError || strings.Contains(out, "SECRET") {
			t.Errorf("%s: %v %s", name, res.IsError, out)
		}
	}
	if _, out := call(t, cs, "get_settings", map[string]any{}); !strings.Contains(out, "(set)") {
		t.Errorf("a secret reads (set): %s", out)
	}
	if !strings.Contains(readConf(t, root, "sources/s.yaml"), "SECRET-OTHER") {
		t.Error("the edit was not saved")
	}
}

func TestSettingsReadableWhenConfigIsBroken(t *testing.T) {
	root := fixture(t)
	writeConf(t, root, "config/config.yaml", "interval: [oops\n")
	cs := connect(t, root, false)
	res, out := call(t, cs, "get_settings", map[string]any{})
	if res.IsError || !strings.Contains(out, `"id":"config"`) || !strings.Contains(out, `"error"`) {
		t.Fatalf("a broken config.yaml must be reported, not fail the tool: %v %s", res.IsError, out)
	}
	if res, _ = call(t, cs, "list_findings", map[string]any{}); !res.IsError {
		t.Error("the broken configuration should still stop the tools that need it")
	}
}
