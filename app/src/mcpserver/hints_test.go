package mcpserver

import (
	"encoding/json"
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
// at most 380 characters; the list of change kinds after it is extra.
func TestToolDescriptionsStayShort(t *testing.T) {
	cs := connect(t, fixture(t), true)
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		lead, _, _ := strings.Cut(tool.Description, "The kinds of change:")
		if n := len([]rune(lead)); n > 380 || n == 0 {
			t.Errorf("%s: description is %d characters", tool.Name, n)
		}
	}
}
