package query

import (
	"testing"
	"time"

	"cvewatch/src/model"
	"cvewatch/src/store"
)

func seed(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	day := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, v := range []*model.Vulnerability{
		{ID: "LOW", Severity: model.SevLow, Title: "low", FirstSeen: day},
		{ID: "CRIT", Severity: model.SevCritical, Title: "crit", FirstSeen: day, Aliases: []string{"GHSA-AAAA-BBBB-CCCC"}},
		{ID: "OLD", Severity: model.SevHigh, Title: "old", FirstSeen: day},
		{ID: "NEW", Severity: model.SevHigh, Title: "new", FirstSeen: day.AddDate(0, 0, 1)},
	} {
		s.AddVuln(v)
	}
	for _, f := range []model.Finding{
		{VulnID: "LOW", Project: "shop", Env: model.EnvProd},
		{VulnID: "NEW", Project: "shop", Env: model.EnvProd},
		{VulnID: "OLD", Project: "shop", Env: model.EnvDev, Status: model.StatusFixed},
		{VulnID: "OLD", Project: "shop", Env: model.EnvProd},
		{VulnID: "CRIT", Project: "mw", Env: model.EnvProd},
	} {
		if f.Status == "" {
			f.Status = model.StatusOpen
		}
		s.AddFinding(f)
	}
	return s
}

func ids(is []Issue) []string {
	var out []string
	for _, i := range is {
		out = append(out, i.ID)
	}
	return out
}

func TestOpenOrdersAndFilters(t *testing.T) {
	s := seed(t)
	got := ids(Open(s, Filter{}))
	want := []string{"CRIT", "OLD", "NEW", "LOW"} // severity desc, older first inside a severity
	if len(got) != 4 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
		t.Fatalf("got %v want %v", got, want)
	}
	if old := Open(s, Filter{})[1]; len(old.Targets) != 1 || old.Targets[0].Env != model.EnvProd {
		t.Fatalf("fixed targets must be hidden: %+v", old.Targets)
	}
	if got := ids(Open(s, Filter{Min: model.SevHigh})); len(got) != 3 {
		t.Fatalf("min filter: %v", got)
	}
	if got := ids(Open(s, Filter{Project: "mw"})); len(got) != 1 || got[0] != "CRIT" {
		t.Fatalf("project filter: %v", got)
	}
}

func TestOneIncludesAllStatusesAndResolvesAliases(t *testing.T) {
	s := seed(t)
	is, err := One(s, "ghsa-aaaa-bbbb-cccc")
	if err != nil || is.ID != "CRIT" {
		t.Fatalf("alias lookup: %v %+v", err, is)
	}
	old, _ := One(s, "OLD")
	if len(old.Targets) != 2 {
		t.Fatalf("want fixed and open targets: %+v", old.Targets)
	}
	if _, err := One(s, "nope"); err == nil {
		t.Fatal("unknown id must error")
	}
}

func TestClipKeepsRunesIntact(t *testing.T) {
	if got := Clip("ééééé ééééé", 7); got != "ééééé…" {
		t.Fatal(got)
	}
}
