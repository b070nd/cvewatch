package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/store"
)

// tenantFixture has one issue open in shop and crm (vendor acme) and in blog (no vendor).
func tenantFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	dir := filepath.Join(root, "config", "projects")
	for name, body := range map[string]string{
		"shop": "name: shop\nvendor: acme\nenvs: [dev, prod]\ntechs: [{name: php}]\n",
		"crm":  "name: crm\nvendor: acme\nenvs: [dev, prod]\ntechs: [{name: php}]\n",
		"blog": "name: blog\nenvs: [dev, prod]\ntechs: [{name: php}]\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.OpenFile(filepath.Join(root, "..", "data"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New(state)
	for _, p := range []string{"crm", "blog"} {
		l.AddFinding(model.Finding{VulnID: "CVE-2026-1", Project: p, Env: model.EnvProd, Status: model.StatusOpen})
	}
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	return root
}

func TestVendorFilterOnTheReadTools(t *testing.T) {
	cs := connect(t, tenantFixture(t), false)
	for _, tool := range []string{"list_findings", "search_findings"} {
		args := map[string]any{"vendor": "acme"}
		if tool == "search_findings" {
			args["query"] = "php"
		}
		_, out := call(t, cs, tool, args)
		if !strings.Contains(out, `"vendor":"acme"`) || strings.Contains(out, `"project":"blog"`) {
			t.Errorf("%s vendor acme: %s", tool, out)
		}
		args["vendor"] = "-"
		if _, out = call(t, cs, tool, args); strings.Contains(out, `"project":"shop"`) || !strings.Contains(out, `"project":"blog"`) {
			t.Errorf("%s vendor -: %s", tool, out)
		}
	}
	_, out := call(t, cs, "search_findings", map[string]any{"query": "project:crm env:dev"})
	if !strings.Contains(out, `"count":0`) {
		t.Errorf("crm has no dev row, whatever another project has: %s", out)
	}
	_, out = call(t, cs, "search_findings", map[string]any{"query": "vendor:acme env:prod"})
	if strings.Count(out, `"project":`) != 2 || strings.Contains(out, `"env":"dev"`) {
		t.Errorf("only the rows that hold every term: %s", out)
	}
	if res, _ := call(t, cs, "list_findings", map[string]any{"vendor": "Bad Name"}); !res.IsError {
		t.Error("a bad vendor must be a tool error")
	}
}

func TestIssueToolsCanBeNarrowedToAProjectOrVendor(t *testing.T) {
	cs := connect(t, tenantFixture(t), false)
	_, out := call(t, cs, "get_vulnerability", map[string]any{"id": "CVE-2026-1", "vendor": "acme"})
	if !strings.Contains(out, `"project":"shop"`) || strings.Contains(out, `"project":"blog"`) {
		t.Errorf("get_vulnerability: %s", out)
	}
	_, out = call(t, cs, "get_evidence", map[string]any{"id": "CVE-2026-1", "project": "blog"})
	if !strings.Contains(out, `"project":"blog"`) || strings.Contains(out, `"project":"shop"`) {
		t.Errorf("get_evidence: %s", out)
	}
	_, out = call(t, cs, "explain", map[string]any{"id": "CVE-2026-1", "project": "crm"})
	if strings.Contains(out, "blog") {
		t.Errorf("explain: %s", out)
	}
}

func TestEditProjectSetsAndClearsTheVendor(t *testing.T) {
	root := fixture(t)
	file := filepath.Join(root, "config", "projects", "shop.yaml")
	cs := connect(t, root, true)
	edit := func(vendor string) {
		t.Helper()
		res, out := call(t, cs, "edit_project", map[string]any{"project": "shop", "changes": []any{map[string]any{"kind": "set_vendor", "vendor": vendor}}})
		if res.IsError {
			t.Fatalf("edit_project: %s", out)
		}
	}
	edit("acme")
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), "name: shop\nvendor: acme\n") {
		t.Fatalf("file:\n%s", b)
	}
	if _, out := call(t, cs, "list_projects", map[string]any{}); !strings.Contains(out, `"vendor":"acme"`) {
		t.Errorf("list_projects: %s", out)
	}
	if res, _ := call(t, cs, "edit_project", map[string]any{"project": "shop", "changes": []any{map[string]any{"kind": "set_vendor", "vendor": "Acme Corp"}}}); !res.IsError {
		t.Error("a bad vendor must be refused")
	}
	edit("")
	if b, _ := os.ReadFile(file); strings.Contains(string(b), "vendor") {
		t.Fatalf("file:\n%s", b)
	}
}
