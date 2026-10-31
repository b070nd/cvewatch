package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSuggestTechAndSearchSayWhenNothingIsClose(t *testing.T) {
	cs := connect(t, fixture(t), false)
	if _, out := call(t, cs, "suggest_tech", map[string]any{"term": "rabbitMW"}); !strings.Contains(out, `"found":false`) || !strings.Contains(out, `"name":"rabbitmq"`) {
		t.Fatalf("a typo: %s", out)
	}
	if _, out := call(t, cs, "suggest_tech", map[string]any{"term": "algolia"}); !strings.Contains(out, `"found":false`) || !strings.Contains(out, `"suggestions":[]`) {
		t.Fatalf("nothing close: %s", out)
	}
	if _, out := call(t, cs, "suggest_tech", map[string]any{"term": "php"}); !strings.Contains(out, `"found":true`) {
		t.Fatalf("an exact name: %s", out)
	}
	if _, out := call(t, cs, "search_catalog", map[string]any{"query": "algolia"}); !strings.Contains(out, `"not_found":true`) {
		t.Fatalf("search: %s", out)
	}
	if _, out := call(t, cs, "search_catalog", map[string]any{"query": "rabbitmw"}); !strings.Contains(out, `"not_found":true`) || !strings.Contains(out, `"name":"rabbitmq"`) {
		t.Fatalf("search with a typo: %s", out)
	}
}

func TestEditTechIsGatedAndWritesTechsYaml(t *testing.T) {
	root := fixture(t)
	add := map[string]any{"action": "add", "name": "algolia", "keywords": []any{"algolia", "algolia search"}, "category": "search"}

	ro := connect(t, root, false)
	if strings.Contains(toolNames(t, ro), "edit_tech") {
		t.Fatal("edit_tech must need allow-write")
	}
	before := techsFile(root)
	if _, out := call(t, ro, "preview_tech_change", add); !strings.Contains(out, `"saved":false`) || !strings.Contains(out, "algolia") || techsFile(root) != before {
		t.Fatalf("preview: %s", out)
	}

	rw := connect(t, root, true)
	if res, out := call(t, rw, "edit_tech", add); res.IsError || !strings.Contains(out, `"saved":true`) {
		t.Fatalf("add: %v %s", res.IsError, out)
	}
	if got := techsFile(root); !strings.Contains(got, "name: algolia") || !strings.Contains(got, "algolia search") {
		t.Fatalf("techs.yaml:\n%s", got)
	}
	if res, _ := call(t, rw, "edit_tech", add); !res.IsError {
		t.Fatal("a duplicate must be an error")
	}
	if res, _ := call(t, rw, "edit_tech", map[string]any{"action": "teleport", "name": "algolia"}); !res.IsError {
		t.Fatal("an unknown action must be an error")
	}
	if res, _ := call(t, rw, "edit_tech", map[string]any{"action": "remove", "name": "redis"}); !res.IsError {
		t.Fatal("a built-in name cannot be removed")
	}
	if _, out := call(t, rw, "edit_tech", map[string]any{"action": "remove", "name": "algolia"}); !strings.Contains(out, `"saved":true`) || strings.Contains(techsFile(root), "algolia") {
		t.Fatalf("remove: %s\n%s", out, techsFile(root))
	}
}

func TestCheckProjectsAddsHints(t *testing.T) {
	root := fixture(t)
	os.WriteFile(filepath.Join(root, "config", "projects", "shop.yaml"), []byte("name: shop\nenvs: [local]\ntechs: [{name: algolia}, {name: rabbitMW, version: \"3\"}]\n"), 0o644)
	cs := connect(t, root, false)
	_, out := call(t, cs, "check_projects", map[string]any{"project": "shop"})
	for _, want := range []string{`"hints":[`, `"keyword":"algolia"`, `"suggest":["rabbitmq"`, `"field":"techs[1]"`, `"level":"warn"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	_, out = call(t, cs, "preview_project_change", map[string]any{"project": "shop", "changes": []any{map[string]any{"kind": "set_tech", "tech": "algolia", "version": "1"}}})
	if !strings.Contains(out, `"hints":[`) {
		t.Errorf("a preview carries the hints: %s", out)
	}
}

func techsFile(root string) string {
	b, _ := os.ReadFile(filepath.Join(root, "config", "techs.yaml"))
	return string(b)
}
