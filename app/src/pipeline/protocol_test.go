package pipeline_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

const (
	monologLock   = `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}]}`
	otherLock     = `{"packages":[{"name":"other/thing","version":"1.0.0"}]}`
	lockedProject = "name: shop\nenvs: [prod]\nlockfiles: [{type: composer, path: composer.lock}]\n"
)

// lockRig is a project whose composer.lock has monolog 3.0.0 and an advisory for it.
func lockRig(t *testing.T) *testkit.Rig {
	t.Helper()
	g := rig(t, phpTech, map[string]string{"shop": lockedProject}, nil)
	g.Write("composer.lock", monologLock)
	g.Reload()
	v := g.Ledger.Create(model.Item{Title: "monolog flaw", URL: "https://ex.test/m", IDs: []string{"CVE-2026-3001"}, Published: newDay,
		SourceID: "feed", SourceType: "rss",
		Affected: []model.Affected{{Ecosystem: model.EcoComposer, Name: "monolog/monolog", Ranges: []model.Range{{Max: "3.5.0", MaxExcl: true}}}}}, g.Now, nil)
	g.Run()
	f := g.Findings(v.ID)
	if len(f) != 1 || f[0].Applies != model.AppAffected || len(f[0].Installed) != 1 {
		t.Fatalf("setup: %+v", f)
	}
	return g
}

func auditEvents(t *testing.T, g *testkit.Rig) []audit.Event {
	t.Helper()
	ev, err := g.Runner.Audit.Events()
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestAnUnavailableInventoryNeverProvesAbsence(t *testing.T) {
	for name, damage := range map[string]func(g *testkit.Rig){
		"missing":    func(g *testkit.Rig) { os.Remove(filepath.Join(g.Root, "composer.lock")) },
		"unreadable": func(g *testkit.Rig) { g.Write("composer.lock", "{ not json") },
	} {
		t.Run(name, func(t *testing.T) {
			g := lockRig(t)
			before := g.Findings("CVE-2026-3001")[0]

			damage(g)
			g.Reload()
			res := g.Run()
			after := g.Findings("CVE-2026-3001")[0]
			if res.Reconciled != 0 || after.Applies != model.AppAffected || len(after.Installed) != 1 || len(after.History) != len(before.History) ||
				strings.Contains(strings.Join(after.Reasons, " "), "no longer installed") {
				t.Fatalf("a lockfile that cannot be read says nothing about what is installed: res=%+v %+v", res, after)
			}

			g.Write("composer.lock", monologLock)
			g.Reload()
			g.Run()
			if f := g.Findings("CVE-2026-3001")[0]; f.Applies != model.AppAffected || len(f.Installed) != 1 {
				t.Fatalf("after the file is back: %+v", f)
			}
		})
	}
}

func TestAPackageThatIsLegitimatelyGoneIsJudgedAgainWhenItComesBack(t *testing.T) {
	g := lockRig(t)
	g.Write("composer.lock", otherLock)
	g.Reload()
	if res := g.Run(); res.Reconciled != 1 {
		t.Fatalf("the file is there and lacks monolog: %+v", res)
	}
	f := g.Findings("CVE-2026-3001")[0]
	if f.Applies != model.AppNotAffected || len(f.Installed) != 0 || !strings.HasPrefix(f.Reasons[0], "no longer installed") || f.Status != model.StatusOpen {
		t.Fatalf("removal: %+v", f)
	}

	g.Ledger.SetStatus("CVE-2026-3001", "shop", model.EnvProd, model.StatusOpen, "", g.Now)
	g.Ledger.Update("CVE-2026-3001", "shop", model.EnvProd, updateOwner("ann"), g.Now)
	g.Write("composer.lock", monologLock)
	g.Reload()
	if res := g.Run(); res.Reconciled != 1 {
		t.Fatalf("the package is back: %+v", res)
	}
	f = g.Findings("CVE-2026-3001")[0]
	if f.Applies != model.AppAffected || len(f.Installed) != 1 || f.Installed[0].Version != "3.0.0" || f.Status != model.StatusOpen || f.Owner != "ann" {
		t.Fatalf("recovered, status and owner kept: %+v", f)
	}
	if last := f.History[len(f.History)-1]; last.Action != "inventory" || !strings.Contains(last.Note, "installed again") {
		t.Errorf("history = %+v", last)
	}
	if res := g.Run(); res.Reconciled != 0 {
		t.Fatalf("nothing left to do: %+v", res)
	}
}

func TestAFindingDamagedByAnEarlierMissingLockfileRecovers(t *testing.T) {
	g := lockRig(t)
	g.Ledger.Mutate(g.Findings("CVE-2026-3001")[0].Key(), func(f *model.Finding) { // what the old behaviour left behind
		f.Installed, f.Matched, f.Applies, f.Reasons = nil, []string{}, model.AppNotAffected, []string{"no longer installed: monolog/monolog@3.0.0"}
	})
	g.Run()
	f := g.Findings("CVE-2026-3001")[0]
	if f.Applies != model.AppAffected || len(f.Installed) != 1 || len(f.Matched) != 1 || f.Matched[0] != "monolog/monolog@3.0.0" {
		t.Fatalf("the package is installed, the verdict follows the ranges: %+v", f)
	}

	g.Ledger.Mutate(f.Key(), func(f *model.Finding) {
		f.Installed, f.Matched, f.Applies, f.Reasons = nil, []string{}, model.AppNotAffected, []string{"no longer installed: monolog/monolog@3.0.0"}
	})
	g.Write("composer.lock", otherLock)
	g.Reload()
	g.Run()
	if f := g.Findings("CVE-2026-3001")[0]; f.Applies != model.AppNotAffected || len(f.Installed) != 0 {
		t.Fatalf("still not installed: %+v", f)
	}
}

func TestEveryFindingCreationAndAutomaticChangeIsAudited(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"}, phpFlaw("CVE-2026-3101"))
	g.Run()
	g.Write("config/projects/mw.yaml", "name: mw\nenvs: [prod, dr]\ntechs: [{name: php, version: '8.2.10'}]\n") // enrolled after the advisory is stored
	g.Reload()
	g.Run()

	var detected []audit.Event
	for _, e := range auditEvents(t, g) {
		if e.Action == "detected" {
			detected = append(detected, e)
		}
	}
	if len(detected) != 3 || detected[0].Project != "shop" || detected[0].Env != "prod" || detected[0].Note != "" {
		t.Fatalf("the fetch detected shop/prod: %+v", detected)
	}
	for i, env := range []string{"prod", "dr"} {
		if e := detected[1+i]; e.Project != "mw" || e.Env != env || e.Actor != "cvewatch" || e.Vuln != "CVE-2026-3101" || e.Note != "matched an advisory already stored" {
			t.Errorf("revalidation detected mw/%s: %+v", env, e)
		}
	}

	g.Write("config/projects/mw.yaml", "name: mw\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\nsince: 2030-01-01\n") // dr is gone, the advisory predates since
	g.Reload()
	g.Run()
	g.Write("config/projects/mw.yaml", "name: mw\nenvs: [prod, dr]\ntechs: [{name: php, version: '8.2.10'}]\n")
	g.Reload()
	g.Run()

	var changes []string
	for _, e := range auditEvents(t, g) {
		if e.Action == "status" {
			if e.Actor != "cvewatch" || e.Vuln != "CVE-2026-3101" || e.Project != "mw" {
				t.Errorf("automatic change: %+v", e)
			}
			changes = append(changes, e.Env+" "+e.Status)
		}
	}
	if got := strings.Join(changes, "; "); got != "dr ignored; prod not_affected; dr open; prod open" {
		t.Fatalf("automatic changes = %q", got)
	}
	if n, err := g.Runner.Audit.Verify(); err != nil || n < 8 {
		t.Fatalf("chain n=%d err=%v", n, err)
	}
}

func TestRemovingAnEnvironmentClosesItsOpenFindingsAndAddingItBackReopensThem(t *testing.T) {
	const both = "name: shop\nenvs: [stage-eu, prod]\ntechs: [{name: php, version: '8.2.10'}]\n"
	g := rig(t, phpTech, map[string]string{"shop": both}, phpFlaw("CVE-2026-3201"))
	g.Run()
	g.Serve(nvdURL, nvdBody("CVE-2026-3202", "PHP flaw.", "php:php", "8.2.30"))
	g.Run()
	if len(g.Findings("CVE-2026-3201")) != 2 || len(g.Findings("CVE-2026-3202")) != 2 {
		t.Fatalf("setup: %v %v", g.Findings("CVE-2026-3201"), g.Findings("CVE-2026-3202"))
	}
	g.Ledger.SetStatus("CVE-2026-3202", "shop", "stage-eu", model.StatusIgnored, "accepted by ann", g.Now) // a person closed this one

	g.Write("config/projects/shop.yaml", strings.Replace(both, "stage-eu, ", "", 1))
	g.Reload()
	g.Run()
	status := func(id string, env model.Env) model.Finding {
		for _, f := range g.Findings(id) {
			if f.Env == env {
				return f
			}
		}
		t.Fatalf("no finding for %s in %s", id, env)
		return model.Finding{}
	}
	f := status("CVE-2026-3201", "stage-eu")
	h := f.History[len(f.History)-1]
	if f.Status != model.StatusIgnored || !f.Auto || f.Note != "environment removed from project" || h.Actor != "cvewatch" || h.Status != model.StatusIgnored || len(f.History) == 0 {
		t.Fatalf("retired environment: %+v", f)
	}
	if p := status("CVE-2026-3201", "prod"); p.Status != model.StatusOpen || p.Auto {
		t.Fatalf("prod is untouched: %+v", p)
	}
	if p := status("CVE-2026-3202", "stage-eu"); p.Auto || p.Note != "accepted by ann" {
		t.Fatalf("a person's status is left alone: %+v", p)
	}
	var closed []audit.Event
	for _, e := range auditEvents(t, g) {
		if e.Action == "status" {
			closed = append(closed, e)
		}
	}
	if len(closed) != 1 || closed[0].Env != "stage-eu" || closed[0].Project != "shop" || closed[0].Vuln != "CVE-2026-3201" || closed[0].Actor != "cvewatch" ||
		closed[0].Status != "ignored" || closed[0].Note != "environment removed from project" {
		t.Fatalf("closing is audited: %+v", closed)
	}
	n := len(closed)
	g.Run()
	again := 0
	for _, e := range auditEvents(t, g) {
		if e.Action == "status" {
			again++
		}
	}
	if again != n || status("CVE-2026-3201", "stage-eu").Status != model.StatusIgnored {
		t.Fatal("closing is idempotent")
	}

	g.Write("config/projects/shop.yaml", both)
	g.Reload()
	g.Run()
	if f := status("CVE-2026-3201", "stage-eu"); f.Status != model.StatusOpen || f.Auto || f.Note != "" {
		t.Fatalf("declared again: %+v", f)
	}
	if f := status("CVE-2026-3202", "stage-eu"); f.Status != model.StatusIgnored || f.Note != "accepted by ann" {
		t.Fatalf("a person's close stays: %+v", f)
	}
}

func TestAProjectWithoutEnvsClosesNothingForItsLegacyEnvironments(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\ntechs: [{name: php, version: '8.2.10'}]\n"}, phpFlaw("CVE-2026-3301"))
	g.Run()
	g.Run()
	fs := g.Findings("CVE-2026-3301")
	if len(fs) != 4 {
		t.Fatalf("dev, int, staging and prod: %+v", fs)
	}
	for _, f := range fs {
		if f.Status != model.StatusOpen || f.Auto {
			t.Errorf("%s: %+v", f.Env, f)
		}
	}
}

func updateOwner(owner string) ledger.Update { return ledger.Update{Actor: "test", Owner: &owner} }
