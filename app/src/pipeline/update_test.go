package pipeline_test

import (
	"slices"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

func twoProjects(t *testing.T) *testkit.Rig {
	t.Helper()
	g := rig(t, phpTech, map[string]string{
		"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n",
		"blog": "name: blog\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n",
	}, phpFlaw("CVE-2026-8001"))
	return g
}

func projectsOf(fs []model.Finding) []string {
	var out []string
	for _, f := range fs {
		if !slices.Contains(out, f.Project) {
			out = append(out, f.Project)
		}
	}
	slices.Sort(out)
	return out
}

func alertedProjects(g *testkit.Rig) []string {
	var out []string
	for _, b := range g.Channel.Batches {
		for _, a := range b {
			out = append(out, projectsOf(a.Findings)...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestAScheduledRunJudgesAndAlertsOnlyTheDueProjects(t *testing.T) {
	g := twoProjects(t)
	g.Runner.Only = map[string]bool{"shop": true}
	res := g.Run()
	if got := projectsOf(g.Findings("CVE-2026-8001")); !slices.Equal(got, []string{"shop"}) {
		t.Fatalf("only shop is due, findings for %v", got)
	}
	if got := alertedProjects(g); !slices.Equal(got, []string{"shop"}) || res.Alerted != 1 {
		t.Fatalf("only shop is alerted: %v, %+v", got, res)
	}
	if !slices.Equal(res.Updated, []string{"shop"}) {
		t.Errorf("updated = %v", res.Updated)
	}
	if !g.Ledger.LastUpdate("shop").Equal(g.Now.Add(-time.Hour)) || !g.Ledger.LastUpdate("blog").IsZero() {
		t.Errorf("only shop counts as updated: shop %v, blog %v", g.Ledger.LastUpdate("shop"), g.Ledger.LastUpdate("blog"))
	}
}

func TestAProjectThatBecomesDueCatchesUpOnWhatWasFetchedBefore(t *testing.T) {
	g := twoProjects(t)
	g.Runner.Only = map[string]bool{"shop": true}
	g.Run()
	g.Runner.Only = map[string]bool{"blog": true}
	res := g.Run()
	if got := projectsOf(g.Findings("CVE-2026-8001")); !slices.Equal(got, []string{"blog", "shop"}) {
		t.Fatalf("blog is judged on what an earlier run fetched: %v", got)
	}
	if got := alertedProjects(g); !slices.Equal(got, []string{"blog", "shop"}) || res.Findings != 1 {
		t.Fatalf("blog is alerted when it is due: %v, %+v", got, res)
	}
	if g.Ledger.LastUpdate("blog").IsZero() {
		t.Error("blog is updated now")
	}
}

func TestARunWithoutARestrictionCoversEveryProject(t *testing.T) {
	g := twoProjects(t)
	res := g.Run()
	if got := projectsOf(g.Findings("CVE-2026-8001")); !slices.Equal(got, []string{"blog", "shop"}) || !slices.Equal(res.Updated, []string{"blog", "shop"}) {
		t.Fatalf("a manual run does everything: %v, %+v", got, res)
	}
	if g.Ledger.LastUpdate("shop").IsZero() || g.Ledger.LastUpdate("blog").IsZero() {
		t.Error("every project counts as updated")
	}
}

func TestABackfillRunIsNoUpdate(t *testing.T) {
	g := twoProjects(t)
	g.Runner.BackfillOnly = true
	g.Run()
	if !g.Ledger.LastUpdate("shop").IsZero() || !g.Ledger.LastUpdate("blog").IsZero() {
		t.Error("a back-fill only fills history and is no update")
	}
}

func TestRevalidateStillSeesEveryProjectAfterAScheduledRun(t *testing.T) {
	g := twoProjects(t)
	g.Runner.Only = map[string]bool{"shop": true}
	g.Run()
	g.Runner.Only = nil
	rv := revalidate(t, g, false)
	if rv.NewFindings != 1 {
		t.Fatalf("the full revalidation finds what blog is missing: %+v", rv)
	}
}
