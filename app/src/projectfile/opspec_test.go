package projectfile

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// applyKinds reads the kinds apply switches on from the source, so a new case
// cannot be added without a row in OpTable.
func applyKinds(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "projectfile.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "apply" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if sel, ok := sw.Tag.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Kind" {
				return true
			}
			for _, c := range sw.Body.List {
				for _, e := range c.(*ast.CaseClause).List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, _ := strconv.Unquote(lit.Value)
						kinds = append(kinds, s)
					}
				}
			}
			return true
		})
	}
	if len(kinds) == 0 {
		t.Fatal("found no kinds in apply: has its shape changed?")
	}
	sort.Strings(kinds)
	return slices.Compact(kinds)
}

func TestOpTableCoversEveryKindApplyAccepts(t *testing.T) {
	want := applyKinds(t)
	got := Kinds()
	sort.Strings(got)
	if !slices.Equal(want, got) {
		t.Fatalf("apply accepts %v but OpTable lists %v: every kind needs a row, and every row a case", want, got)
	}
}

// sample has what every example needs to work on.
const opSample = `name: shop
envs: [dev, int, staging, prod]
techs:
  - {name: php, version: "8.2"}
lockfiles:
  - {type: composer, path: composer.lock, env: prod}
when@prod:
  techs: {php: "8.3"}
when@dev:
  exclude: [varnish]
`

func TestOpTableExamplesApplyAndMatchTheirParams(t *testing.T) {
	for _, s := range OpTable {
		t.Run(s.Kind, func(t *testing.T) {
			if s.Example.Kind != s.Kind {
				t.Fatalf("example has kind %q", s.Example.Kind)
			}
			if s.Summary == "" || s.Flag == "" || len(s.Args) == 0 {
				t.Fatalf("incomplete row: %+v", s)
			}
			if err := mustParse(t, opSample).Apply(s.Example); err != nil {
				t.Fatalf("example does not apply: %v", err)
			}

			// the example sets exactly the declared inputs, and every required one
			raw, _ := json.Marshal(s.Example)
			var m map[string]any
			json.Unmarshal(raw, &m)
			set := map[string]bool{}
			for k, v := range m {
				if k == "kind" {
					continue
				}
				if lock, ok := v.(map[string]any); ok && k == "lockfile" {
					for lk, lv := range lock {
						set["lockfile."+lk] = lv != "" // Lockfile has no omitempty on type and path
					}
					continue
				}
				set[k] = true
			}
			declared := map[string]bool{}
			for _, p := range s.Params {
				declared[p.Name] = true
				if p.Required && !set[p.Name] {
					t.Errorf("example leaves out required %s", p.Name)
				}
				if p.Help == "" || p.Type == "" {
					t.Errorf("param %s needs a type and help", p.Name)
				}
			}
			for k, on := range set {
				if on && !declared[k] {
					t.Errorf("example sets %s, which the row does not declare", k)
				}
			}
		})
	}
}

func TestOpTableUnknownKindIsRejected(t *testing.T) {
	if err := mustParse(t, opSample).Apply(Op{Kind: "teleport"}); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpTableHelpTexts(t *testing.T) {
	if h := KindHelp(); !strings.Contains(h, "set_tech(tech, version?)") || !strings.Contains(h, "set_since(since?)") {
		t.Errorf("KindHelp:\n%s", h)
	}
	if h := ParamHelp("lockfile_dev"); !strings.Contains(h, "add_lockfile") || !strings.Contains(h, "set_lockfile_dev") {
		t.Errorf("ParamHelp: %s", h)
	}
	if h := ParamHelp("version"); !strings.Contains(h, "set_env_tech (required)") {
		t.Errorf("ParamHelp: %s", h)
	}
	if u := FlagHelp("  "); !strings.Contains(u, "  -since DATE") || strings.Count(u, "\n") != len(OpTable) {
		t.Errorf("FlagHelp: %s", u)
	}
}
