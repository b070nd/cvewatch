package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/store"
)

func openIssue(targets ...string) query.Issue {
	var is query.Issue
	for _, t := range targets {
		project, env, _ := strings.Cut(t, "/")
		st := model.StatusOpen
		if strings.HasSuffix(env, "!") {
			env, st = strings.TrimSuffix(env, "!"), model.StatusFixed
		}
		is.Targets = append(is.Targets, query.Target{Project: project, Env: model.Env(env), Status: st})
	}
	return is
}

func envs(names ...string) []model.Env {
	var out []model.Env
	for _, n := range names {
		out = append(out, model.Env(n))
	}
	return out
}

func TestWhereOpenNamesOnlyWhatDiffers(t *testing.T) {
	mon := map[string][]model.Env{
		"shop":  envs("dev", "int", "staging", "prod"),
		"mw":    envs("prod"),
		"many":  envs("local", "dev", "int", "staging", "qa", "prod"),
		"solo":  envs("local"),
		"other": envs("dev", "prod"),
	}
	for _, c := range []struct {
		name string
		is   query.Issue
		w    int
		want string
	}{
		{"all environments", openIssue("shop/dev", "shop/int", "shop/staging", "shop/prod"), 22, "shop"},
		{"all, in any order", openIssue("shop/prod", "shop/dev", "shop/staging", "shop/int"), 22, "shop"},
		{"a subset", openIssue("shop/dev", "shop/staging"), 22, "shop:dev,staging"},
		{"prod first", openIssue("shop/dev", "shop/prod"), 22, "shop:prod,dev"},
		{"one environment", openIssue("shop/int"), 22, "shop:int"},
		{"a resolved target is not open", openIssue("shop/dev", "shop/int", "shop/staging", "shop/prod!"), 22, "shop:dev,int,staging"},
		{"a project with one environment", openIssue("mw/prod"), 22, "mw"},
		{"a default-only project", openIssue("solo/local"), 22, "solo"},
		{"many environments", openIssue("many/local", "many/dev", "many/int", "many/prod"), 40, "many:prod,local,dev+1"},
		{"all of six", openIssue("many/local", "many/dev", "many/int", "many/staging", "many/qa", "many/prod"), 22, "many"},
		{"an unknown project lists its environments", openIssue("gone/dev", "gone/prod"), 22, "gone:prod,dev"},
		{"an environment the project does not monitor", openIssue("other/dev", "other/prod", "other/qa"), 40, "other:prod,dev,qa"},
		{"two projects", openIssue("shop/dev", "mw/prod"), 40, "shop:dev mw"},
		{"two projects, both everywhere", openIssue("shop/dev", "shop/int", "shop/staging", "shop/prod", "mw/prod"), 22, "shop mw"},
		{"more projects than fit", openIssue("shop/dev", "mw/prod", "solo/local", "other/dev"), 18, "shop:dev +3 more"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := whereOpen(c.is, mon, c.w); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
			if strings.Contains(whereOpen(c.is, mon, c.w), "…") {
				t.Errorf("no ellipsis expected in %q", whereOpen(c.is, mon, c.w))
			}
		})
	}
}

func TestOpenInForOneProject(t *testing.T) {
	all := []string{"dev", "int", "staging", "prod"}
	for _, c := range []struct {
		is   query.Issue
		envs []string
		want string
	}{
		{openIssue("shop/dev", "shop/int", "shop/staging", "shop/prod"), all, "all"},
		{openIssue("shop/dev", "shop/prod"), all, "prod,dev"},
		{openIssue("shop/staging"), all, "staging"},
		{openIssue("shop/dev", "shop/int", "shop/staging", "shop/prod!"), all, "dev,int,staging"},
		{openIssue("shop/local"), []string{"local"}, "all"},
		{openIssue("shop/dev", "shop/int", "shop/staging", "shop/prod", "shop/qa"), all, "prod,dev,int+2"},
	} {
		if got := openIn(c.is, "shop", c.envs); got != c.want {
			t.Errorf("%v: got %q, want %q", c.is.Targets, got, c.want)
		}
	}
}

func TestEnvSummaryOneLineWhenAlike(t *testing.T) {
	four := envs("dev", "int", "staging", "prod")
	for _, c := range []struct {
		name  string
		by    map[model.Env]int
		scope []model.Env
		want  []string
		not   []string
	}{
		{"alike", map[model.Env]int{"dev": 18, "int": 18, "staging": 18, "prod": 18}, four, []string{"all 4 environments alike (18 open each)"}, []string{"█", "dev 18"}},
		{"alike, one with no findings named only by the project", map[model.Env]int{"dev": 5, "int": 5}, envs("dev", "int"), []string{"all 2 environments alike (5 open each)"}, nil},
		{"nothing open", nil, four, []string{"all 4 environments alike (none open)"}, []string{"█"}},
		{"one environment", map[model.Env]int{"local": 3}, envs("local"), []string{"local 3"}, []string{"alike", "█"}},
		{"differ: equal counts share a bar", map[model.Env]int{"dev": 18, "int": 18, "staging": 18, "prod": 4}, four, []string{"dev,int,staging 18 ██", "prod 4 █"}, []string{"alike"}},
		{"differ: environments with nothing open are left out", map[model.Env]int{"prod": 2}, four, []string{"prod 2 █"}, []string{"dev", "staging", "alike"}},
		{"a finding names an environment the project does not list", map[model.Env]int{"dev": 1, "qa": 2}, envs("dev"), []string{"dev 1", "qa 2"}, []string{"alike"}},
		{"no environments", nil, nil, []string{"none"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := envSummary(c.by, c.scope, 2)
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("%q lacks %q", got, w)
				}
			}
			for _, w := range c.not {
				if strings.Contains(got, w) {
					t.Errorf("%q has %q", got, w)
				}
			}
		})
	}
}

// alikeFake is the user's screen: one project, four environments, every issue open in all of them.
func alikeFake(t *testing.T, issues int) *fake {
	t.Helper()
	l := ledger.New(ledger.State{})
	for i := 0; i < issues; i++ {
		id := fmt.Sprintf("CVE-2026-%d", 100+i)
		v := l.Create(model.Item{Title: "Bug " + id, Summary: "S", URL: "https://a.test/" + id, IDs: []string{id}, Severity: model.SevHigh,
			Published: t0, SourceID: "hn", SourceType: "hn"}, t0, []string{"php"})
		for _, e := range []model.Env{model.EnvDev, model.EnvInt, model.EnvStaging, model.EnvProd} {
			l.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: e, Status: model.StatusOpen, Applies: model.AppUnknown})
		}
	}
	st := store.NewMemory()
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	b := newFake(t, st)
	b.cfg.Projects = b.cfg.Projects[:1]
	b.cfg.Projects[0].Envs = envs("dev", "int", "staging", "prod")
	return b
}

func TestIssueListsDoNotRepeatTheEnvironmentsOfAProject(t *testing.T) {
	d := start(t, alikeFake(t, 18), Options{})
	d.send(tea_window(110, 30))
	d.want("by environment", "all 4 environments alike (18 open each)", "PROJECTS (ONLY IN)", "18 of 18 open issues")
	d.wantNot("dev 18", "int 18", "shop:", "…")
	for _, l := range strings.Split(d.view(), "\n") {
		if strings.Contains(l, "CVE-2026-100") && !strings.Contains(l, " shop ") {
			t.Errorf("the row names the project alone: %q", l)
		}
	}
	d.screen("findings")
	d.want("PROJECTS (ONLY IN)", "CVE-2026-100")
	d.wantNot("shop:", "…")
}

func TestIssueListsNameOnlyWhereAnIssueIsOpenWhenItDiffers(t *testing.T) {
	d := start(t, newFake(t, nil), Options{}) // shop has the old default four environments, mw only prod
	d.send(tea_window(110, 30))
	d.want("shop:dev", "shop:staging", "mw shop:prod")
	d.wantNot("dev,int,staging", "all 4 environments alike")
	d.want("dev,staging 1", "prod 2")
}
