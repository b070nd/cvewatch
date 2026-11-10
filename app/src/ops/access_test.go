package ops

import (
	"errors"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

// A refusal comes before anything else: it never says whether a project
// exists, and nobody without a view of everything writes a shared page.
func TestAccessIsDecidedFirst(t *testing.T) {
	acc := map[string]config.Grant{"bob": {Projects: []string{"shop"}, Write: true}, "carol": {Projects: []string{"*"}}}
	bob := editable(t, acc, "bob")

	denied := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: want a refusal, got %v", what, err)
		} else if strings.Contains(err.Error(), "unknown project") || strings.Contains(err.Error(), "is the file of") {
			t.Errorf("%s: the refusal tells what exists: %v", what, err)
		}
	}
	for _, project := range []string{"mw", "no-such-project"} { // one that exists, one that does not: the same answer
		_, err := bob.Resolve(Change{ID: "CVE-2026-1", Project: project, Env: model.EnvProd, Status: model.StatusFixed})
		denied("resolve "+project, err)
		_, err = bob.Assign(Assignment{ID: "CVE-2026-1", Project: project, Owner: "x"})
		denied("assign "+project, err)
		_, err = bob.Attach(Attachment{ID: "CVE-2026-1", Project: project, Note: "x"})
		denied("attach "+project, err)
		_, err = bob.EditProject(ProjectChange{Project: project, Ops: addPHP})
		denied("edit "+project, err)
		_, err = bob.ProjectFile(project)
		denied("file of "+project, err)
		_, err = bob.Inventory(project)
		denied("inventory of "+project, err)
		_, err = bob.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: project})
		denied("delete "+project, err)
	}
	if _, err := bob.Inventory("shop"); err != nil {
		t.Errorf("bob's own project: %v", err)
	}

	// A shared page shows everything or it misleads; writing it is a change.
	_, err := bob.WriteDashboard()
	denied("bob's dashboard", err)
	_, err = editable(t, acc, "carol").WriteDashboard()
	denied("a read-only actor's dashboard", err)
	if _, err := bob.DashboardHTML(); err != nil {
		t.Errorf("bob may still render his own view: %v", err)
	}
}

// A bulk status change is one operation: one audit record per change, and a
// refusal stops it without losing what landed before.
func TestResolveAllIsOneOperation(t *testing.T) {
	s := editable(t, nil, "alice")
	issues, err := s.List(query.Filter{})
	if err != nil || len(issues) != 1 {
		t.Fatalf("setup: %v %+v", err, issues)
	}
	cs := StatusChanges(issues, model.StatusFixed, "MR 9")
	if len(cs) != 2 {
		t.Fatalf("one change per open environment: %+v", cs)
	}
	if len(StatusChanges(issues, model.StatusOpen, "")) != 0 {
		t.Fatal("nothing is closed, so nothing reopens")
	}
	cs = append(cs, Change{ID: "CVE-2026-1", Project: "gone", Env: model.EnvProd, Status: model.StatusFixed})
	res, err := s.ResolveAll(cs)
	if err == nil || !strings.Contains(err.Error(), "2 of 3 changes written") || res.Applied != 2 || res.Findings != 2 {
		t.Fatalf("it stops at the refusal and keeps the rest: %+v %v", res, err)
	}
	events, _ := s.Audit.Events()
	n := 0
	for _, e := range events {
		if e.Action == "status" && e.Note == "MR 9" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("one audit record per change, got %d", n)
	}
	if left, _ := s.List(query.Filter{}); len(left) != 0 {
		t.Fatalf("both are fixed: %+v", left)
	}
}

// The workspace holds only what the actor may see.
func TestWorkspaceIsScoped(t *testing.T) {
	acc := map[string]config.Grant{"bob": {Projects: []string{"shop"}, Write: true}}
	w, err := editable(t, acc, "bob").Workspace()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Projects) != 1 || w.Projects[0].Name != "shop" || len(w.Issues["shop"]) != 1 || len(w.Issues["mw"]) != 0 {
		t.Fatalf("bob sees shop only: %+v", w)
	}
	if _, err := editable(t, acc, "nobody").Workspace(); !errors.Is(err, ErrDenied) {
		t.Fatalf("no grant, no workspace: %v", err)
	}
}
