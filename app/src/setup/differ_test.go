package setup

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func TestCreateAsksOnceWhetherAnEnvironmentDiffers(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")
	answer(t, f, "add-techs", "php, nginx")
	answer(t, f, "add-techs", "")
	answer(t, f, "version:php", "8.2")
	answer(t, f, "version:nginx", "1.25")
	for _, st := range []string{"version:php", "version:nginx"} {
		if f.Current().ID == st {
			t.Fatal("versions are asked once per technology, not per environment")
		}
	}
	answer(t, f, "envs", "local,prod")
	if st := f.Current(); st.ID != "differ" || st.Kind != KindConfirm || st.Default != "no" || !strings.Contains(st.Title, "default: no") {
		t.Fatalf("differ = %+v", st)
	}
	answer(t, f, "differ", "yes")
	if st := f.Current(); st.ID != "differ-envs" || st.Kind != KindMulti || len(st.Options) != 2 {
		t.Fatalf("differ-envs = %+v", st)
	}
	answer(t, f, "differ-envs", "prod")
	if err := f.Answer("php=8.3, varnish 7.4"); err == nil {
		t.Fatal("a technology the catalog lacks is refused")
	}
	if st := f.Current(); st.ID != "diff-techs:prod" || !strings.Contains(st.Problem, "varnish") {
		t.Fatalf("a technology the catalog lacks is refused: %+v", st)
	}
	answer(t, f, "diff-techs:prod", "php=8.3, redis=7")
	if st := f.Current(); st.ID != "diff-exclude:prod" || len(st.Options) != 2 {
		t.Fatalf("diff-exclude = %+v", st)
	}
	answer(t, f, "diff-exclude:prod", "nginx")
	answer(t, f, "diff-image:prod", "shop:1.4")
	if st := f.Current(); st.ID != "review" || !strings.Contains(st.Help, "Differences per environment: prod: php 8.3, +redis 7, -nginx, image shop:1.4") {
		t.Fatalf("review = %+v", st)
	}

	want := []projectfile.Op{
		{Kind: "set_envs", Envs: []model.Env{"local", "prod"}},
		{Kind: "set_tech", Tech: "php", Version: "8.2"},
		{Kind: "set_tech", Tech: "nginx", Version: "1.25"},
		{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.3"},
		{Kind: "set_env_tech", Env: "prod", Tech: "redis", Version: "7"},
		{Kind: "exclude_env_tech", Env: "prod", Tech: "nginx"},
		{Kind: "set_image", Env: "prod", Image: "shop:1.4"},
	}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
	diff, issues, err := f.Review(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "when@prod:") || strings.Contains(diff, "environments:") {
		t.Errorf("differences are written as a when@ block:\n%s", diff)
	}
	for _, is := range issues {
		if is.Level == "error" {
			t.Errorf("issue %+v", is)
		}
	}
}

func TestOneEnvironmentAsksNothingAboutDifferences(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")
	answer(t, f, "add-techs", "")
	answer(t, f, "envs", "local")
	if f.Current().ID != "review" {
		t.Fatalf("current = %q", f.Current().ID)
	}
	for _, s := range f.Sections() {
		if s.ID == "differ" {
			t.Error("one environment has nothing to differ from")
		}
	}
}

func TestAnsweringNoToDifferencesKeepsNoneAndYesKeepsTheExisting(t *testing.T) {
	ex := &model.Project{Name: "shop", Envs: []model.Env{"local", "prod"},
		Techs:        []model.ProjectTech{{Name: "php", Version: "8.2"}, {Name: "nginx"}},
		Environments: map[model.Env]model.EnvConfig{"prod": {Techs: map[string]string{"php": "8.3"}, Exclude: []string{"nginx"}, Image: "shop:1"}}}

	f := NewFlow(testCatalog(), ex)
	if !slices.ContainsFunc(f.Current().Options, func(o Option) bool { return o.Value == "differ" }) {
		t.Fatalf("the menu offers the differences: %+v", f.Current().Options)
	}
	answer(t, f, "menu", "differ")
	if st := f.Current(); st.Default != "yes" || !strings.Contains(st.Title, "default: yes") {
		t.Fatalf("a project with differences defaults to yes: %+v", st)
	}
	answer(t, f, "differ", "yes")
	if st := f.Current(); !st.Options[1].Selected || st.Options[0].Selected || st.Options[1].Detail != "php 8.3, -nginx, image shop:1" {
		t.Fatalf("differ-envs = %+v", st)
	}
	answer(t, f, "differ-envs", "prod")
	if st := f.Current(); st.Default != "php=8.3" {
		t.Fatalf("diff-techs default = %q", st.Default)
	}
	answer(t, f, "diff-techs:prod", "php=8.3")
	if st := f.Current(); !st.Options[1].Selected || st.Options[0].Selected {
		t.Fatalf("diff-exclude = %+v", st)
	}
	answer(t, f, "diff-exclude:prod", "nginx")
	answer(t, f, "diff-image:prod", "shop:1")
	if f.Current().ID != "menu" || len(f.Ops()) != 0 {
		t.Fatalf("nothing changed: %q, %+v", f.Current().ID, f.Ops())
	}

	answer(t, f, "menu", "differ")
	answer(t, f, "differ", "no")
	want := []projectfile.Op{
		{Kind: "remove_env_tech", Env: "prod", Tech: "php"},
		{Kind: "include_env_tech", Env: "prod", Tech: "nginx"},
		{Kind: "set_image", Env: "prod"},
	}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
	if len(ex.Environments) != 1 {
		t.Error("the existing project was modified")
	}
}

func TestDifferStepsFromTheReviewReturnToTheReview(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")
	answer(t, f, "add-techs", "php")
	answer(t, f, "add-techs", "")
	answer(t, f, "version:php", "8.2")
	answer(t, f, "envs", "local,dev,prod")
	answer(t, f, "differ", "no")
	if err := f.Revisit("differ"); err != nil {
		t.Fatal(err)
	}
	answer(t, f, "differ", "yes")
	answer(t, f, "differ-envs", "dev,prod")
	answer(t, f, "diff-techs:dev", "php=8.1")
	answer(t, f, "diff-exclude:dev", "")
	answer(t, f, "diff-image:dev", "")
	if f.Current().ID != "diff-techs:prod" {
		t.Fatalf("the next chosen environment follows: %q", f.Current().ID)
	}
	answer(t, f, "diff-techs:prod", "")
	answer(t, f, "diff-exclude:prod", "php")
	answer(t, f, "diff-image:prod", "")
	if f.Current().ID != "review" {
		t.Fatalf("current = %q", f.Current().ID)
	}
	if got := DifferenceLines(f.Draft().Project); !reflect.DeepEqual(got, []string{"dev: php 8.1", "prod: -php"}) {
		t.Errorf("lines = %v", got)
	}
}

func TestDifferencesTextAndOrder(t *testing.T) {
	generic := []model.ProjectTech{{Name: "php", Version: "8.2"}, {Name: "nginx"}}
	c := model.EnvConfig{Techs: map[string]string{"varnish": "7.4", "PHP": "8.3"}, Exclude: []string{"nginx", "apache"}, Image: "shop:1"}
	var got []string
	for _, d := range Differences(generic, c) {
		got = append(got, d.String())
	}
	want := []string{"PHP 8.3", "+varnish 7.4", "-apache", "-nginx", "image shop:1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("differences = %v", got)
	}
	if d := Differences(generic, c)[0]; d.Kind != "version" || d.Generic != "8.2" {
		t.Errorf("first = %+v", d)
	}
}

func TestReplacingATypoRenamesATechnologyOnlyAnEnvironmentNames(t *testing.T) {
	ex := &model.Project{Name: "shop", Envs: []model.Env{"local", "prod"}, Techs: []model.ProjectTech{{Name: "php", Version: "8.2"}},
		Environments: map[model.Env]model.EnvConfig{"prod": {Techs: map[string]string{"rediss": "7"}}, "local": {Exclude: []string{"rediss"}}}}
	f := NewFlow(testCatalog(), ex)
	if err := f.ReplaceTech("nothing", "redis"); err == nil {
		t.Fatal("a name the project does not use is refused")
	}
	if err := f.ReplaceTech("rediss", "redis"); err != nil {
		t.Fatal(err)
	}
	d := f.Draft().Project
	if d.Environments["prod"].Techs["redis"] != "7" || len(d.Environments["prod"].Techs) != 1 || d.Environments["local"].Exclude[0] != "redis" || len(d.Techs) != 1 {
		t.Errorf("draft = %+v", d)
	}
}
