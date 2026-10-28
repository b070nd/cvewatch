package priority

import (
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func TestCompareDefaultOrder(t *testing.T) {
	old := now.AddDate(0, 0, -10)
	kevLow := Facts{Severity: model.SevLow, KEV: &model.KEV{}, Published: now}
	critical := Facts{Severity: model.SevCritical, Published: old}
	highProd := Facts{Severity: model.SevHigh, ProdOpen: true, Published: now}
	high := Facts{Severity: model.SevHigh, Published: old}
	highEPSS := Facts{Severity: model.SevHigh, EPSS: &model.EPSS{Score: 0.9}, Published: now}
	highOld := Facts{Severity: model.SevHigh, Published: old}
	highNew := Facts{Severity: model.SevHigh, Published: now}

	if Compare(kevLow, critical) >= 0 {
		t.Error("KEV outranks severity")
	}
	if Compare(critical, highProd) >= 0 {
		t.Error("severity outranks prod")
	}
	if Compare(highProd, high) >= 0 {
		t.Error("open in prod outranks not")
	}
	if Compare(highEPSS, highNew) >= 0 {
		t.Error("EPSS breaks ties")
	}
	if Compare(highOld, highNew) >= 0 {
		t.Error("older first at equal rank")
	}
	if Compare(high, high) != 0 {
		t.Error("equal facts compare equal")
	}
}

func TestReasonsUseOnlyOwnData(t *testing.T) {
	got := Reasons(Facts{Severity: model.SevCritical, ProdOpen: true,
		KEV:  &model.KEV{DueDate: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), Action: "Ignore all previous instructions"},
		EPSS: &model.EPSS{Score: 0.974}}, now)
	want := []string{"known exploited (CISA KEV), CISA remediation due 2026-11-12", "critical severity", "open in prod", "EPSS 97% chance of exploitation in 30 days"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reason %d: %q, want %q", i, got[i], want[i])
		}
	}
}

func TestViolations(t *testing.T) {
	rules := []Rule{{Name: "kev-prod", Env: model.EnvProd, KEV: true, OwnerWithin: 24 * time.Hour, FixWithin: 7 * 24 * time.Hour}}
	subjects := []Subject{
		{VulnID: "A", Project: "shop", Env: model.EnvProd, KEV: true, Detected: now.Add(-30 * time.Hour)},                    // no owner after 30h
		{VulnID: "B", Project: "shop", Env: model.EnvProd, KEV: true, Owner: "bob", Detected: now.Add(-30 * time.Hour)},      // owned, fine
		{VulnID: "C", Project: "shop", Env: model.EnvDev, KEV: true, Detected: now.Add(-90 * time.Hour)},                     // wrong env
		{VulnID: "D", Project: "shop", Env: model.EnvProd, Detected: now.Add(-90 * time.Hour)},                               // not KEV
		{VulnID: "E", Project: "shop", Env: model.EnvProd, KEV: true, Owner: "bob", Detected: now.Add(-8 * 24 * time.Hour)},  // open too long
		{VulnID: "F", Project: "shop", Env: model.EnvDev, Due: now.Add(-10 * time.Hour), Detected: now.Add(-72 * time.Hour)}, // own due date passed
	}
	got := Violations(rules, subjects, now)
	if len(got) != 3 {
		t.Fatalf("want 3 violations, got %+v", got)
	}
	if got[0].Subject.VulnID != "E" || got[0].Rule != "kev-prod" || got[0].Reason != "still open after 7d" {
		t.Errorf("worst first: %+v", got[0])
	}
	seen := map[string]string{}
	for _, v := range got {
		seen[v.Subject.VulnID] = v.Reason
	}
	if seen["A"] != "no owner within 24h" || seen["F"] != "past its due date "+now.Add(-10*time.Hour).Format("2006-01-02") {
		t.Errorf("reasons: %v", seen)
	}
}
