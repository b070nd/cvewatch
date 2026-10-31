package ops

import (
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

const legacyShop = `name: shop
envs: [local, prod]
techs:
  - {name: php, version: "8.2"}
environments:   # what runs where
  prod:
    techs: {php: "8.3"}
    image: shop:1
`

func TestMigrateEnvsIsPreviewedThenSaved(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/projects/shop.yaml", legacyShop)
	change := ProjectChange{Project: "shop", Ops: []projectfile.Op{{Kind: "migrate_envs"}}}

	p, err := s.EditProject(change)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Diff, "- environments:") || !strings.Contains(p.Diff, "+ when@prod:") || p.Blocked() || p.Saved {
		t.Fatalf("preview wrong:\n%s", p.Diff)
	}
	if got := readRoot(t, s, "config/projects/shop.yaml"); got != legacyShop {
		t.Fatalf("a preview wrote the file:\n%s", got)
	}
	for _, h := range p.Hints {
		if h.Field == "environments" {
			t.Errorf("the migrated result still hints: %+v", h)
		}
	}
	if len(p.Result.Differences) != 1 || p.Result.Differences[0].Env != "prod" || p.Result.Differences[0].Old || p.Result.Differences[0].Techs["php"] != "8.3" {
		t.Errorf("result differences = %+v", p.Result.Differences)
	}

	// the hint of the file as it is carries the fix that was just previewed
	hints, err := s.ProjectHints("shop")
	if err != nil {
		t.Fatal(err)
	}
	var hint *projectfile.Hint
	for _, h := range hints {
		if h.Field == "environments" {
			hint = &h.Hint
		}
	}
	if hint == nil || len(hint.Fix) != 1 || hint.Fix[0].Kind != "migrate_envs" {
		t.Fatalf("hints = %+v", hints)
	}

	change.Save = true
	if p, err = s.EditProject(change); err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	if got := readRoot(t, s, "config/projects/shop.yaml"); strings.Contains(got, "environments:") || !strings.Contains(got, "when@prod:") || !strings.Contains(got, "# what runs where") {
		t.Errorf("file:\n%s", got)
	}
}

func TestEditingADifferenceOfAnOldFileWritesTheNewSpelling(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/projects/shop.yaml", legacyShop)
	p, err := s.EditProject(ProjectChange{Project: "shop", Ops: []projectfile.Op{{Kind: "exclude_env_tech", Env: "local", Tech: "php"}}, Save: true})
	if err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	got := readRoot(t, s, "config/projects/shop.yaml")
	if strings.Contains(got, "environments:") || !strings.Contains(got, "when@prod:") || !strings.Contains(got, "when@local:\n  exclude: [php]") {
		t.Errorf("file:\n%s", got)
	}
}

func TestViewListsTheScopeOfATechAndTheDifferences(t *testing.T) {
	p := model.Project{Name: "x", Techs: []model.ProjectTech{{Name: "php", Version: "8"}, {Name: "xdebug", Envs: []model.Env{"local", "dev"}}},
		Environments: map[model.Env]model.EnvConfig{"prod": {Exclude: []string{"xdebug"}}, "local": {Image: "i", Old: true}}}
	v := ViewOf(p)
	if !slices.Equal(v.Techs[1].Envs, []string{"local", "dev"}) || v.Techs[0].Envs != nil {
		t.Errorf("techs = %+v", v.Techs)
	}
	if len(v.Differences) != 2 || v.Differences[0].Env != "local" || !v.Differences[0].Old || v.Differences[1].Env != "prod" || v.Differences[1].Exclude[0] != "xdebug" {
		t.Errorf("differences = %+v", v.Differences)
	}
}
