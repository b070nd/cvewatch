package tui

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/setup"
)

const diffSvc = "name: svc\nenvs: [local, dev, prod]\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: nginx, version: \"1.25\"}\n  - {name: mysql, version: \"8.0\", envs: [dev, prod]}\n" +
	"when@prod:\n  techs: {php: \"8.3\", redis: \"7\"}\n  exclude: [nginx]\n  image: reg/svc:1\n"

// selectProject moves the cursor of the Projects screen onto a project.
func selectProject(d *driver, name string) {
	d.press("3")
	for i := 0; i < 6 && !strings.Contains(d.view(), "> "+name); i++ {
		d.press("down")
	}
}

func TestDifferencesAreListedOnceAndOnlyWhenTheyExist(t *testing.T) {
	b, _ := diskFake(t, map[string]string{"config/projects/svc.yaml": diffSvc})
	d := start(t, b, Options{})
	selectProject(d, "svc")
	d.press("c")
	d.want("Differences per environment", "prod: php 8.3, +redis 7, -nginx, image reg/svc:1")
	d.wantNot("Versions per environment", "Image per environment")

	d.toField(1)
	d.press("enter")
	d.want("TECHNOLOGY", "WHERE", "php", "everywhere", "mysql", "only in dev, prod")
	d.press("esc")

	d.toField(3)
	d.press("enter")
	d.want("ENV", "DIFFERENCE", "prod", "php 8.3", "generic: 8.2", "+redis 7", "runs only in prod", "-nginx", "does not run in prod", "image reg/svc:1", "+ add a difference")
	d.wantNot("local", "DEPLOYED", "old environments: block")
}

func TestADifferenceIsAddedByPickingTheEnvironmentTheTechnologyAndHow(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/svc.yaml": diffSvc})
	d := start(t, b, Options{})
	selectProject(d, "svc")
	d.press("c")
	d.toField(3)
	d.press("enter", "+")
	d.want("Which environment differs?", "local", "dev", "prod", "php 8.3, +redis 7")
	d.press("down", "enter") // dev
	d.want("What differs in dev?", "generic 8.2", "generic 1.25", "another technology", "the image")
	d.press("enter") // php
	d.want("php in dev", "another version", "it does not run there")
	d.press("enter")
	d.want("Version of php in dev", "generic one")
	d.typ("8.1")
	d.press("enter")
	d.want("Save this change?", "set php in dev to 8.1", "when@dev:")
	d.press("y")
	d.want("ok: saved svc")
	got := fileAt(t, root, "config/projects/svc.yaml")
	if !strings.Contains(got, "when@dev:") || !strings.Contains(got, `php: "8.1"`) {
		t.Fatalf("file:\n%s", got)
	}
	d.want("dev", "php 8.1", "generic: 8.2")

	// leaving a technology out of an environment: the project already says what it has in prod
	d.press("+", "down", "down", "enter", "down", "enter", "down", "enter")
	d.want("Save this change?", "nginx does not run in prod")
}

func TestOldSpellingIsSaidInThePreviewAndCanBeMigratedByKeyOrHint(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	selectProject(d, "shop")
	d.press("H")
	d.want("Hints", "environments: is the old spelling of the when@<env> blocks")
	d.pickTo("environments")
	d.press("enter")
	d.want("Save this change?", "- environments:", "+ when@prod:", "the whole old environments: block becomes when@<env> blocks")
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); strings.Contains(got, "environments:") || !strings.Contains(got, "when@prod:") {
		t.Fatalf("file:\n%s", got)
	}
	d.press("H")
	d.wantNot("old spelling")

	// any change to the differences says the same before it migrates
	b, _ = diskFake(t, nil)
	d = start(t, b, Options{})
	selectProject(d, "shop")
	d.press("c")
	d.toField(3)
	d.press("enter")
	d.want("old environments: block", "m rewrites it")
	d.press("home", "enter")
	d.press("ctrl+u")
	d.typ("8.4")
	d.press("enter")
	d.want("Save this change?", "the whole old environments: block becomes when@<env> blocks", "when@prod:")
}

func TestUnknownTechnologyInAnEnvironmentBlockIsReplacedThere(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/svc.yaml": "name: svc\nenvs: [local, prod]\ntechs:\n  - {name: php, version: \"8.2\"}\nwhen@prod:\n  techs: {rediss: \"7\"}\n"})
	d := start(t, b, Options{})
	selectProject(d, "svc")
	d.press("H")
	d.want("Hints", `when@prod.techs.rediss: "rediss" is not in the catalog`)
	d.pickTo("when@prod.techs.rediss")
	d.press("enter")
	d.want("Instead of rediss", "use redis")
	d.press("enter")
	d.want("Save this change?", `instead of "rediss" in prod`, "redis")
	d.press("y")
	d.want("ok: saved svc")
	got := fileAt(t, root, "config/projects/svc.yaml")
	if strings.Contains(got, "rediss") || !strings.Contains(got, `redis: "7"`) {
		t.Fatalf("file:\n%s", got)
	}
}

func TestNewProjectFormAsksOnceAboutDifferencesAndShowsThemCompactly(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "n", "ctrl+u")
	d.typ("blog")
	d.press("enter", "enter") // techs (none), then add-techs
	d.typ("php")
	d.press("enter", "enter")
	d.typ("8.2")
	d.press("enter")
	d.want("Environments")
	d.press("down", "down", "down", "down", " ", "enter") // prod
	d.want("Does an environment differ from the rest? (default: no)", "y yes, n no")
	d.press("y")
	d.want("Which environments differ?", "[ ] local", "[ ] prod")
	d.press("down", " ", "enter")
	d.want("Versions that differ in prod", "tech=version")
	d.typ("php=8.3")
	d.press("enter")
	d.want("Technologies that do not run in prod", "[ ] php")
	d.press("enter")
	d.want("Image of prod")
	d.typ("reg/blog:1")
	d.press("enter")
	d.want("Save this project?", "when@prod:", "Differences per environment", "prod: php 8.3, image reg/blog:1")
	d.wantNot("environments:")
	d.press("y")
	d.want("ok: created project blog")
	got := projectFile(t, b, "blog")
	if !strings.Contains(got, "when@prod:") || !strings.Contains(got, `php: "8.3"`) || !strings.Contains(got, "image: reg/blog:1") {
		t.Fatalf("file:\n%s", got)
	}
}

func TestADifferenceHintInTheReviewGoesToTheStepThatSettlesIt(t *testing.T) {
	b, _ := diskFake(t, map[string]string{"config/projects/svc.yaml": "name: svc\nenvs: [local, prod]\ntechs:\n  - {name: php, version: \"8.2\"}\nwhen@prod:\n  techs: {rediss: \"7\"}\n"})
	d := start(t, b, Options{})
	selectProject(d, "svc")
	d.press("e", "end", "enter")
	d.want("Save this project?", "Differences per environment", "prod: +rediss 7", "when@prod.techs.rediss")
	d.press("H")
	d.pickTo("when@prod.techs.rediss")
	d.press("enter")
	d.want("Instead of rediss")
	d.press("enter")
	d.want("Save this project?", "using redis instead of rediss", "prod: +redis 7")
}

func TestEnvTechFieldNamesTheEnvironmentAndTechnology(t *testing.T) {
	for _, c := range []struct {
		field string
		env   model.Env
		tech  string
		ok    bool
	}{
		{"when@prod.techs.rediss", "prod", "rediss", true},
		{"environments.staging.techs.my-tech", "staging", "my-tech", true},
		{"techs[0]", "", "", false},
		{"when@prod.exclude", "", "", false},
		{"when@.techs.x", "", "", false},
		{"environments", "", "", false},
	} {
		env, tech, ok := envTechField(c.field)
		if env != c.env || tech != c.tech || ok != c.ok {
			t.Errorf("%s: got %q %q %v", c.field, env, tech, ok)
		}
	}
}

func TestMigratesRecognisesTheRewriteOfTheOldBlock(t *testing.T) {
	old := "  lockfiles:\n- environments:\n-   prod:\n+ when@prod:\n+   image: x\n"
	if !migrates(old) || migrates("+ when@prod:\n+   image: x\n") || migrates("- environments:\n-   prod:\n") || migrates("") {
		t.Error("only a diff that removes environments: and adds when@ is a migration")
	}
}

func TestDifferenceLinesFollowTheGenericTechnologies(t *testing.T) {
	techs := []ops.TechPin{{Name: "php", Version: "8.2"}, {Name: "nginx"}}
	diffs := []ops.EnvDiff{
		{Env: "dev"},
		{Env: "prod", Techs: map[string]string{"php": "8.3", "varnish": "7.4"}, Exclude: []string{"nginx"}, Image: "shop:1"},
	}
	want := []string{"prod: php 8.3, +varnish 7.4, -nginx, image shop:1"}
	if got := diffLinesOf(techs, diffs); !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %v", got)
	}
}

func TestDifferenceOpKindsAreDeclaredByEditorAndSetup(t *testing.T) {
	for _, k := range []string{"set_tech_envs", "exclude_env_tech", "include_env_tech", "migrate_envs"} {
		if !slices.Contains(OpKinds, k) {
			t.Errorf("tui.OpKinds lacks %s", k)
		}
		if !slices.Contains(setup.OpKinds, k) {
			t.Errorf("setup.OpKinds lacks %s", k)
		}
		if slices.Contains(setup.NotYet, k) {
			t.Errorf("%s is still listed as not yet handled", k)
		}
	}
}
