package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
)

var today = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func writeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func judging(t *testing.T, files map[string]string) model.Judging {
	t.Helper()
	cfg, err := config.Load(writeRoot(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return Load(cfg).Judging(cfg, today)
}

const shopYAML = "name: shop\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: '8.2'}\n"
const techsYAML = "techs:\n  - name: php\n    aliases: [php]\n  - name: redis\n"

func TestJudgingChangesOnlyWithJudgingInputs(t *testing.T) {
	files := func(project, techs, cfg string) map[string]string {
		return map[string]string{"config/projects/shop.yaml": project, "config/techs.yaml": techs, "config/config.yaml": cfg}
	}
	base := judging(t, files(shopYAML, techsYAML, "interval: 4h\n"))
	if base.Hash == "" || len(base.Projects["shop"].Techs) != 1 || base.Projects["shop"].Techs[0] != "php" {
		t.Fatalf("fingerprint = %+v", base)
	}

	same := map[string]string{
		"comment":        "# watching the shop\n" + shopYAML,
		"key order":      "techs:\n  - {version: '8.2', name: php}\nenvs: [dev, prod]\nname: shop\n",
		"env order":      "name: shop\nenvs: [prod, dev]\ntechs:\n  - {name: php, version: '8.2'}\n",
		"other settings": shopYAML,
	}
	for name, project := range same {
		cfgYAML := "interval: 4h\n"
		if name == "other settings" {
			cfgYAML = "interval: 1h\nlookback: 72h\n"
		}
		if got := judging(t, files(project, techsYAML, cfgYAML)); got.Hash != base.Hash {
			t.Errorf("%s must not change the fingerprint", name)
		}
	}

	differ := map[string]map[string]string{
		"version":    files("name: shop\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: '8.3'}\n", techsYAML, ""),
		"new tech":   files("name: shop\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: '8.2'}\n  - {name: redis}\n", techsYAML, ""),
		"since":      files("name: shop\nsince: 2024-01-01\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: '8.2'}\n", techsYAML, ""),
		"envs":       files("name: shop\nenvs: [dev, prod, qa]\ntechs:\n  - {name: php, version: '8.2'}\n", techsYAML, ""),
		"when block": files("name: shop\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: '8.2'}\nwhen@prod:\n  techs: {php: '8.1'}\n", techsYAML, ""),
		"alias":      files(shopYAML, "techs:\n  - name: php\n    aliases: [php, hhvm]\n  - name: redis\n", ""),
		"horizon":    files(shopYAML, techsYAML, "horizon:\n  window: year\n"),
	}
	for name, f := range differ {
		if got := judging(t, f); got.Hash == base.Hash {
			t.Errorf("%s must change the fingerprint", name)
		}
	}
	// A tech no project uses is not an input.
	if got := judging(t, files(shopYAML, techsYAML+"  - name: pasta\n", "")); got.Hash != base.Hash {
		t.Error("an unused catalog entry must not change the fingerprint")
	}
}

func TestJudgingCountsLockfilePackages(t *testing.T) {
	lock := func(v string) string { return `{"packages":[{"name":"monolog/monolog","version":"` + v + `"}]}` }
	project := "name: shop\nenvs: [prod]\ntechs:\n  - {name: php}\nlockfiles:\n  - {type: composer, path: composer.lock}\n"
	build := func(version string) model.Judging {
		root := writeRoot(t, map[string]string{"config/projects/shop.yaml": project, "config/techs.yaml": techsYAML})
		if err := os.WriteFile(filepath.Join(root, "composer.lock"), []byte(lock(version)), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(root)
		if err != nil {
			t.Fatal(err)
		}
		return Load(cfg).Judging(cfg, today)
	}
	if build("3.0.0").Hash == build("3.1.0").Hash {
		t.Error("an upgraded lockfile package must change the fingerprint")
	}
}

func TestCompare(t *testing.T) {
	prev := judging(t, map[string]string{"config/projects/shop.yaml": shopYAML, "config/projects/api.yaml": "name: api\ntechs:\n  - {name: php}\n", "config/techs.yaml": techsYAML})
	prev.At = today
	h := config.Horizon{}

	if d := Compare(nil, prev, h, today); !d.Never || !d.Stale() || !slices.Equal(d.Changed, []string{"api", "shop"}) {
		t.Errorf("nothing recorded: %+v", d)
	}
	if d := Compare(&prev, prev, h, today); d.Stale() || d.Backfill != (time.Time{}) {
		t.Errorf("same inputs: %+v", d)
	}

	cur := judging(t, map[string]string{
		"config/projects/shop.yaml": "name: shop\nsince: 2024-01-01\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: '8.2'}\n",
		"config/projects/new.yaml":  "name: new\nsince: 2023-06-01\ntechs:\n  - {name: redis}\n",
		"config/techs.yaml":         techsYAML})
	d := Compare(&prev, cur, h, today)
	if !slices.Equal(d.Changed, []string{"api", "new", "shop"}) { // api was removed
		t.Errorf("changed = %v", d.Changed)
	}
	if want := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC); !d.Backfill.Equal(want) {
		t.Errorf("backfill = %v, want the earliest start among changed projects %v", d.Backfill, want)
	}

	curH := prev
	curH.Horizon = "year"
	if d := Compare(&prev, curH, config.Horizon{Window: config.WindowYear}, today); !d.Horizon || !d.Stale() || !d.Backfill.Equal(today.Add(-365*24*time.Hour)) {
		t.Errorf("horizon change: %+v", d)
	}
}

func TestStart(t *testing.T) {
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	year := config.Horizon{Window: config.WindowYear}
	cases := []struct {
		name  string
		since time.Time
		h     config.Horizon
		want  time.Time
	}{
		{"nothing", time.Time{}, config.Horizon{}, time.Time{}},
		{"since only", since, config.Horizon{}, since},
		{"horizon only", time.Time{}, year, today.Add(-365 * 24 * time.Hour)},
		{"since is later than the horizon", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), year, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
		{"horizon is later than since", since, year, today.Add(-365 * 24 * time.Hour)},
	}
	for _, c := range cases {
		if got := Start(c.since, c.h, today); !got.Equal(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
