package ops

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func TestRenameEnvMovesTheFindings(t *testing.T) {
	s, st := lcSession(t, "root", false)
	s.Cfg.Policy.Rules = []config.PolicyRule{{Name: "fast", Env: model.EnvProd, FixWithin: 1}}
	change := ProjectChange{Project: "shop", Ops: []projectfile.Op{{Kind: "rename_env", Env: "prod", To: "production"}}}

	p, err := s.EditProject(change)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Moved) != 1 || p.Moved[0] != (EnvMove{From: "prod", To: "production", Findings: 1}) {
		t.Fatalf("moved = %+v", p.Moved)
	}
	if !slices.Contains(p.Result.Envs, "production") {
		t.Errorf("result envs = %v", p.Result.Envs)
	}
	warned := false
	for _, i := range p.Issues {
		warned = warned || strings.Contains(i.Message, `policy rule "fast" still names environment prod`)
	}
	if !warned {
		t.Errorf("no warning about the policy rule: %+v", p.Issues)
	}
	if fs := findingsOf(stored(t, st), "shop"); len(fs) != 1 || fs[0].Env != model.EnvProd {
		t.Fatalf("a preview moved findings: %+v", fs)
	}

	change.Save = true
	if p, err = s.EditProject(change); err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	if fs := findingsOf(stored(t, st), "shop"); len(fs) != 1 || fs[0].Env != "production" || fs[0].Status != model.StatusOpen {
		t.Fatalf("findings = %+v", fs)
	}
	if fs := findingsOf(stored(t, st), "mw"); len(fs) != 1 || fs[0].Env != model.EnvProd {
		t.Fatalf("another project's findings changed: %+v", fs)
	}
	if got := readRoot(t, s, "config/projects/shop.yaml"); !strings.Contains(got, "envs: [dev, int, staging, production]") {
		t.Errorf("file:\n%s", got)
	}
	log, err := s.Audit.Events()
	if err != nil || !strings.Contains(log[len(log)-1].Note, "environment prod renamed to production, 1 finding(s) moved") {
		t.Errorf("audit = %+v %v", log, err)
	}
}

func TestRenameEnvRefusesToMerge(t *testing.T) {
	s, st := lcSession(t, "root", false)
	v := s.Ledger.Relevant()[0]
	s.Ledger.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvDev, Status: model.StatusOpen})
	before := readRoot(t, s, "config/projects/shop.yaml")
	_, err := s.EditProject(ProjectChange{Project: "shop", Save: true, Ops: []projectfile.Op{{Kind: "rename_env", Env: "dev", To: "prod"}}})
	if err == nil {
		t.Fatal("renaming onto an environment that has findings must fail")
	}
	if readRoot(t, s, "config/projects/shop.yaml") != before {
		t.Error("the file changed")
	}
	_, err = s.EditProject(ProjectChange{Project: "shop", Save: true, Ops: []projectfile.Op{{Kind: "rename_env", Env: "staging", To: "stage"}}})
	if err != nil {
		t.Fatalf("a finding-free target is fine: %v", err)
	}
	if fs := findingsOf(stored(t, st), "shop"); len(fs) != 2 || fs[0].Env != model.EnvDev || fs[1].Env != model.EnvProd {
		t.Errorf("findings keep their environments: %+v", fs)
	}
}

func TestRenameEnvNeedsWriteAccess(t *testing.T) {
	s, st := lcSession(t, "bob", true)
	_, err := s.EditProject(ProjectChange{Project: "shop", Save: true, Ops: []projectfile.Op{{Kind: "rename_env", Env: "prod", To: "production"}}})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	if fs := findingsOf(stored(t, st), "shop"); len(fs) != 1 || fs[0].Env != model.EnvProd {
		t.Fatalf("findings = %+v", fs)
	}
}
