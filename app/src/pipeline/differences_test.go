package pipeline_test

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

func phpFlaw(id string) map[string]string {
	return map[string]string{nvdURL: nvdBody(id, "PHP flaw.", "php:php", "8.2.30")}
}

func applies(g interface {
	Findings(string) []model.Finding
}, id string) map[model.Env]model.Applicability {
	out := map[model.Env]model.Applicability{}
	for _, f := range g.Findings(id) {
		out[f.Env] = f.Applies
	}
	return out
}

func TestGenericTechWithAWhenBlockOverridesItsVersionThere(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [local, prod]\ntechs: [{name: php, version: '8.3'}]\nwhen@prod:\n  techs: {php: '8.2.10'}\n"},
		phpFlaw("CVE-2026-7001"))
	g.Run()
	got := applies(g, "CVE-2026-7001")
	if got[model.EnvProd] != model.AppAffected || got[model.EnvLocal] != model.AppNotAffected {
		t.Fatalf("prod runs 8.2.10 (affected), local the generic 8.3 (not): %v", got)
	}
}

func TestATechOfOneEnvironmentOnlyIsJudgedThere(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [local, prod]\nlockfiles: []\nwhen@prod:\n  techs: {php: '8.2.10'}\n"},
		phpFlaw("CVE-2026-7002"))
	g.Run()
	got := applies(g, "CVE-2026-7002")
	if len(got) != 1 || got[model.EnvProd] != model.AppAffected {
		t.Fatalf("only prod runs php: %v", got)
	}
}

func TestATechScopedToEnvironmentsIsOnlyJudgedThere(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [local, dev, prod]\ntechs: [{name: php, version: '8.2.10', envs: [local, dev]}]\n"},
		phpFlaw("CVE-2026-7003"))
	g.Run()
	got := applies(g, "CVE-2026-7003")
	if len(got) != 2 || got[model.EnvLocal] != model.AppAffected || got[model.EnvDev] != model.AppAffected {
		t.Fatalf("php runs in local and dev only: %v", got)
	}
}

func TestExcludingATechRemovesItsMatchesOnTheNextCycle(t *testing.T) {
	const generic = "name: shop\nenvs: [local, prod]\ntechs: [{name: php, version: '8.2.10'}]\n"
	g := rig(t, phpTech, map[string]string{"shop": generic}, phpFlaw("CVE-2026-7004"))
	g.Run()
	if got := applies(g, "CVE-2026-7004"); got[model.EnvProd] != model.AppAffected || got[model.EnvLocal] != model.AppAffected {
		t.Fatalf("both start affected: %v", got)
	}

	g.Write("config/projects/shop.yaml", generic+"when@prod:\n  exclude: [php]\n")
	g.Reload()
	res := g.Run()
	got := applies(g, "CVE-2026-7004")
	if res.Reconciled != 1 || got[model.EnvProd] != model.AppNotAffected || got[model.EnvLocal] != model.AppAffected {
		t.Fatalf("prod no longer runs php, local still does: res=%+v %v", res, got)
	}
	for _, f := range g.Findings("CVE-2026-7004") {
		if f.Env == model.EnvProd && (len(f.Reasons) == 0 || !strings.Contains(f.Reasons[0], "no longer installed")) {
			t.Errorf("the finding should say why: %+v", f.Reasons)
		}
	}

	g.Write("config/projects/shop.yaml", "name: shop\nenvs: [local, prod]\ntechs: [{name: php, version: '8.2.10', envs: [local]}]\n") // scoping does the same
	g.Reload()
	if res := g.Run(); res.Reconciled != 0 {
		t.Fatalf("prod was already settled: %+v", res)
	}
}

func TestScopingATechAwayReconcilesItToo(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [local, prod]\ntechs: [{name: php, version: '8.2.10'}]\n"}, phpFlaw("CVE-2026-7005"))
	g.Run()
	g.Write("config/projects/shop.yaml", "name: shop\nenvs: [local, prod]\ntechs: [{name: php, version: '8.2.10', envs: [local]}]\n")
	g.Reload()
	res := g.Run()
	got := applies(g, "CVE-2026-7005")
	if res.Reconciled != 1 || got[model.EnvProd] != model.AppNotAffected || got[model.EnvLocal] != model.AppAffected {
		t.Fatalf("res=%+v %v", res, got)
	}
}

func TestTheOldEnvironmentsKeyStillWorks(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [local, prod]\ntechs: [{name: php, version: '8.3'}]\nenvironments:\n  prod:\n    techs: {php: '8.2.10'}\n"},
		phpFlaw("CVE-2026-7006"))
	g.Run()
	got := applies(g, "CVE-2026-7006")
	if got[model.EnvProd] != model.AppAffected || got[model.EnvLocal] != model.AppNotAffected {
		t.Fatalf("%v", got)
	}
}
