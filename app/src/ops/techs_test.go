package ops

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/relevance"
)

func TestAddTechMakesAKeywordMatch(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/techs.yaml", "# my techs\ntechs: []\n")
	if s.Cfg.Catalog.Has("algolia") {
		t.Fatal("the test needs a catalog without algolia")
	}
	add := TechChange{Tech: model.Tech{Name: "Algolia", Aliases: []string{"algolia", "algolia search"}, Category: "search"}}

	p, err := s.AddTech(add)
	if err != nil || p.Saved || !strings.Contains(p.Diff, "algolia") || readRoot(t, s, "config/techs.yaml") != "# my techs\ntechs: []\n" {
		t.Fatalf("preview must not write: %+v %v", p, err)
	}
	add.Save = true
	if p, err = s.AddTech(add); err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	got := readRoot(t, s, "config/techs.yaml")
	if !strings.Contains(got, "# my techs") || !strings.Contains(got, "name: algolia") || !strings.Contains(got, "category: search") {
		t.Fatalf("file:\n%s", got)
	}
	if evs, _ := s.Audit.Events(); len(evs) != 1 || evs[0].Action != "settings" {
		t.Fatalf("audit: %+v", evs)
	}
	if !s.Cfg.Catalog.Has("algolia") {
		t.Fatal("the session catalog does not hold the new technology")
	}

	// the daemon loads the same file and the keyword decides the match
	cfg, err := config.Load(s.Cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	judge := relevance.New(cfg.Techs)
	target := relevance.Target{Project: "shop", Env: "prod", Techs: []model.ProjectTech{{Name: "algolia"}}}
	hit := judge.Judge(model.Item{Title: "Algolia Search API key exposure in the dashboard"}, []relevance.Target{target})
	if len(hit.Matches) != 1 {
		t.Fatalf("keyword tech did not match: %+v", hit)
	}
	miss := judge.Judge(model.Item{Title: "Unrelated router flaw"}, []relevance.Target{target})
	if len(miss.Matches) != 0 {
		t.Fatalf("matched without the keyword: %+v", miss)
	}
}

func TestAddTechRefusals(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/techs.yaml", "techs: []\n")
	for name, c := range map[string]TechChange{
		"bad name":     {Tech: model.Tech{Name: "Acme Gateway"}},
		"empty":        {Tech: model.Tech{}},
		"comma":        {Tech: model.Tech{Name: "acme", Aliases: []string{"a,b"}}},
		"bad category": {Tech: model.Tech{Name: "acme", Category: "weird"}},
		"bad cpe":      {Tech: model.Tech{Name: "acme", CPE: []string{"Acme"}}},
	} {
		c.Save = true
		if p, err := s.AddTech(c); err == nil && !p.Blocked() {
			t.Errorf("%s: accepted: %+v", name, p)
		}
	}
	if readRoot(t, s, "config/techs.yaml") != "techs: []\n" {
		t.Fatal("a refused change wrote the file")
	}
}

var errNotSaved = errors.New("not saved")

func TestAddEditRemoveTech(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/techs.yaml", "techs: []\n")
	save := func(do func(TechChange) (SettingsPreview, error), t0 model.Tech) error {
		p, err := do(TechChange{Tech: t0, Save: true})
		if err == nil && !p.Saved {
			err = errNotSaved
		}
		return err
	}
	if err := save(s.AddTech, model.Tech{Name: "acme-gateway", Aliases: []string{"acme gateway"}, CPE: []string{"acme:gateway"}}); err != nil {
		t.Fatal(err)
	}
	if err := save(s.AddTech, model.Tech{Name: "acme-gateway"}); err == nil || !strings.Contains(err.Error(), "already one of your") {
		t.Fatalf("duplicate: %v", err)
	}
	if err := save(s.AddTech, model.Tech{Name: "php"}); err == nil || !strings.Contains(err.Error(), "already in the catalog") {
		t.Fatalf("shipped: %v", err)
	}

	if err := save(s.EditTech, model.Tech{Name: "ACME-GATEWAY", Aliases: []string{"acme gateway", "acmegw"}, Vendor: "ACME"}); err != nil {
		t.Fatal(err)
	}
	got := readRoot(t, s, "config/techs.yaml")
	if !strings.Contains(got, "acmegw") || !strings.Contains(got, "vendor: ACME") || strings.Contains(got, "cpe") {
		t.Fatalf("edit (empty cpe must be removed):\n%s", got)
	}
	mine, err := s.UserTechs()
	if err != nil || len(mine) != 1 || len(mine[0].Aliases) != 2 || mine[0].Vendor != "ACME" {
		t.Fatalf("%+v %v", mine, err)
	}
	if err := save(s.EditTech, model.Tech{Name: "php"}); err == nil || !strings.Contains(err.Error(), "not one of your") {
		t.Fatalf("editing a built-in one: %v", err)
	}

	if err := save(s.RemoveTech, model.Tech{Name: "php"}); err == nil || !strings.Contains(err.Error(), "built in") {
		t.Fatalf("removing a built-in one: %v", err)
	}
	if err := save(s.RemoveTech, model.Tech{Name: "acme-gateway"}); err != nil {
		t.Fatal(err)
	}
	if s.Cfg.Catalog.Has("acme-gateway") {
		t.Fatal("removed technology is still in the session catalog")
	}
	if mine, _ := s.UserTechs(); len(mine) != 0 {
		t.Fatalf("%+v", mine)
	}
}

func TestTechWritesAreGated(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/techs.yaml", "techs: []\n")
	s.readOnly = true
	if _, err := s.AddTech(TechChange{Tech: model.Tech{Name: "acme"}, Save: true}); err == nil {
		t.Fatal("a read-only session wrote")
	}
	if p, err := s.AddTech(TechChange{Tech: model.Tech{Name: "acme"}}); err != nil || p.Saved {
		t.Fatalf("a read-only session may still preview: %+v %v", p, err)
	}
	s.readOnly = false
	s.Cfg.Access = map[string]config.Grant{"bob": {Projects: []string{"*"}, Write: true}}
	if _, err := s.AddTech(TechChange{Tech: model.Tech{Name: "acme"}, Save: true}); err == nil {
		t.Fatal("alice has no rule, so the access rules refuse her")
	}
}

func TestEditProjectWithNewTechs(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/techs.yaml", "techs: []\n")
	edits := []projectfile.Op{{Kind: "set_tech", Tech: "algolia", Version: "1"}}

	p, err := s.EditProject(ProjectChange{Project: "shop", Ops: edits})
	if err != nil || len(p.Hints) == 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if h := p.Hints[0]; h.Keyword != "algolia" || h.Level != "warn" || h.Field != "techs[0]" {
		t.Fatalf("an unknown technology is the first hint, with the keyword to add: %+v", p.Hints)
	}

	p, err = s.EditProject(ProjectChange{Project: "shop", Ops: edits, NewTechs: []model.Tech{{Name: "algolia", Category: "weird"}}, Save: true})
	if err == nil || p.Saved {
		t.Fatalf("a bad new technology refuses the save: %+v %v", p, err)
	}
	if readRoot(t, s, "config/techs.yaml") != "techs: []\n" {
		t.Fatal("techs.yaml was written for a blocked change")
	}
	if _, err := os.Stat(p.Path); err == nil {
		t.Fatal("the project was written for a blocked change")
	}

	p, err = s.EditProject(ProjectChange{Project: "shop", Ops: edits, NewTechs: []model.Tech{{Name: "algolia", Aliases: []string{"algolia"}}}, Save: true})
	if err != nil || !p.Saved || len(p.NewTechs) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if !strings.Contains(readRoot(t, s, "config/techs.yaml"), "name: algolia") {
		t.Fatal("techs.yaml not written")
	}
	if !s.Cfg.Catalog.Has("algolia") {
		t.Fatal("session catalog not refreshed")
	}
}
