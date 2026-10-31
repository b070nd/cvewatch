package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
)

const composerLock = `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.0.0"}]}`

func names(pkgs []model.Package) map[string]bool {
	out := map[string]bool{}
	for _, p := range pkgs {
		out[p.Name] = true
	}
	return out
}

func TestDevOnlyPackagesCountInDevLikeEnvironmentsOfAnyName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "composer.lock")
	if err := os.WriteFile(path, []byte(composerLock), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Bundle{Projects: []model.Project{{
		Name:      "shop",
		Envs:      []model.Env{"local", "dev", "test", "qa", "production"},
		Lockfiles: []model.Lockfile{{Type: "composer", Path: path}},
	}}}
	inv := Load(cfg)
	for env, wantDev := range map[model.Env]bool{"local": true, "dev": true, "test": true, "qa": false, "production": false} {
		tg, ok := inv.Target("shop", env)
		if !ok {
			t.Fatalf("no target for %s", env)
		}
		got := names(tg.Packages)
		if !got["monolog/monolog"] || got["phpunit/phpunit"] != wantDev {
			t.Errorf("%s: packages = %v, dev-only packages expected: %v", env, got, wantDev)
		}
	}
	if len(inv.Targets()) != 5 {
		t.Errorf("targets = %d", len(inv.Targets()))
	}
}

func TestProjectWithoutEnvsKeepsTheOldFour(t *testing.T) {
	inv := Load(&config.Bundle{Projects: []model.Project{{Name: "shop"}}})
	var got []model.Env
	for _, tg := range inv.Targets() {
		got = append(got, tg.Env)
	}
	want := []model.Env{"dev", "int", "staging", "prod"}
	if len(got) != 4 {
		t.Fatalf("envs = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("envs = %v", got)
		}
	}
	if inv2 := Load(&config.Bundle{Projects: []model.Project{{Name: "shop", Envs: []model.Env{"local"}}}}); len(inv2.Targets()) != 1 {
		t.Errorf("explicit envs = %d targets", len(inv2.Targets()))
	}
}

func TestUnreadableNamesTheLockfilesOfAnEnvironmentThatCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "composer.lock")
	if err := os.WriteFile(good, []byte(composerLock), 0o600); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "missing.lock")
	cfg := &config.Bundle{Projects: []model.Project{{
		Name: "shop",
		Envs: []model.Env{"dev", "prod"},
		Lockfiles: []model.Lockfile{{Type: "composer", Path: good},
			{Type: "composer", Path: gone, Env: "prod"}},
	}}}
	inv := Load(cfg)
	if got := inv.Unreadable("shop", "prod"); len(got) != 1 || got[0] != gone {
		t.Errorf("prod = %v", got)
	}
	if got := inv.Unreadable("shop", "dev"); len(got) != 0 {
		t.Errorf("dev does not use that file: %v", got)
	}
	if got := inv.Unreadable("other", "prod"); len(got) != 0 {
		t.Errorf("other project: %v", got)
	}
}
