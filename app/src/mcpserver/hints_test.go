package mcpserver

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryToolDeclaresAllFourHints(t *testing.T) {
	cs := connect(t, fixture(t), true)
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) == 0 {
		t.Fatal("no tools listed")
	}
	for _, tool := range res.Tools {
		raw, err := json.Marshal(tool.Annotations)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
			if _, ok := got[k].(bool); !ok {
				t.Errorf("%s: %s is not declared as a boolean (annotations %s)", tool.Name, k, raw)
			}
		}
	}
}

func TestManageProjectIsMarkedDestructiveAndRefreshOpenWorld(t *testing.T) {
	cs := connect(t, fixture(t), true)
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		a := tool.Annotations
		switch tool.Name {
		case "manage_project":
			if a == nil || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint {
				t.Errorf("manage_project must be destructive and not read-only: %+v", a)
			}
		case "refresh":
			if a == nil || a.OpenWorldHint == nil || !*a.OpenWorldHint {
				t.Errorf("refresh reaches feeds and Slack, so it is open-world: %+v", a)
			}
		default:
			if a != nil && a.OpenWorldHint != nil && *a.OpenWorldHint {
				t.Errorf("%s works on local files only: %+v", tool.Name, a)
			}
		}
	}
}

// Directories and graders cut long descriptions, so each says its point in
// at most 380 characters.
func TestToolDescriptionsStayShort(t *testing.T) {
	cs := connect(t, fixture(t), true)
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if n := len([]rune(tool.Description)); n > 380 || n == 0 {
			t.Errorf("%s: description is %d characters", tool.Name, n)
		}
	}
}

// Directories read the descriptions from the source and stop at an escape or
// a concatenation, so each is one plain string literal.
func TestToolDescriptionsArePlainLiterals(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	tools := 0
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if sel, ok := lit.Type.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Tool" {
				return true
			}
			tools++
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok || kv.Key.(*ast.Ident).Name != "Description" {
					continue
				}
				s, ok := kv.Value.(*ast.BasicLit)
				if !ok || s.Kind != token.STRING || !strings.HasPrefix(s.Value, `"`) || strings.Contains(s.Value, `\`) {
					t.Errorf("%s: a tool description is not one plain string literal", fset.Position(kv.Pos()))
				}
			}
			return true
		})
	}
	if tools == 0 {
		t.Fatal("no mcp.Tool literals found")
	}
}
