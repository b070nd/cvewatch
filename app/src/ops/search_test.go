package ops

import (
	"errors"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

func TestSearchFindsPartialCodesExactFirst(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New(state)
	v := l.Create(model.Item{Title: "Newer PHP bug", IDs: []string{"CVE-2026-10"}, Severity: model.SevCritical, Published: day,
		SourceID: "hn", SourceType: "hn"}, day, []string{"php"})
	l.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown})
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	s := open(t, cfg, st, "alice")

	found, err := s.Search("2026-1", query.Filter{}, false)
	if err != nil || len(found) != 2 {
		t.Fatalf("a partial code matches every id containing it: %+v %v", found, err)
	}
	found, err = s.Search("cve-2026-1", query.Filter{}, false)
	if err != nil || len(found) != 2 || found[0].ID != "CVE-2026-1" {
		t.Fatalf("the exact id must come first even though CVE-2026-10 is more severe: %+v %v", found, err)
	}
	found, err = s.Search("cve-2026-10", query.Filter{}, false)
	if err != nil || len(found) != 1 || found[0].ID != "CVE-2026-10" {
		t.Fatalf("exact match: %+v %v", found, err)
	}
}

func TestSearchRespectsProjectAccess(t *testing.T) {
	cfg := bundle(t, map[string]config.Grant{"alice": {Projects: []string{"shop"}}})
	st := seeded(t)
	s := open(t, cfg, st, "alice")

	found, err := s.Search("tracked", query.Filter{}, false)
	if err != nil || len(found) != 1 || len(found[0].Targets) != 1 || found[0].Targets[0].Project != "shop" {
		t.Fatalf("alice must find the issue only in shop: %+v %v", found, err)
	}
	found, err = s.Search("project:mw", query.Filter{}, false)
	if err != nil || len(found) != 0 {
		t.Fatalf("a field search must not reveal other projects: %+v %v", found, err)
	}
	if _, err := open(t, cfg, st, "mallory").Search("tracked", query.Filter{}, false); !errors.Is(err, ErrDenied) {
		t.Fatalf("unlisted actors get nothing: %v", err)
	}
}

func TestSearchOpenOnlyAndFixedFindings(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	if _, err := s.Resolve(Change{ID: "CVE-2026-1", Project: "shop", Status: model.StatusFixed}); err != nil {
		t.Fatal(err)
	}
	found, err := s.Search("tracked", query.Filter{}, true)
	if err != nil || len(found) != 1 || len(found[0].Targets) != 1 || found[0].Targets[0].Project != "mw" {
		t.Fatalf("open only lists the open environments: %+v %v", found, err)
	}
	if _, err := s.Resolve(Change{ID: "CVE-2026-1", Project: "mw", Status: model.StatusFixed}); err != nil {
		t.Fatal(err)
	}
	if found, _ := s.Search("tracked", query.Filter{}, true); len(found) != 0 {
		t.Fatalf("open only must hide an issue with no open finding: %+v", found)
	}
	found, err = s.Search("tracked", query.Filter{}, false)
	if err != nil || len(found) != 1 || len(found[0].Targets) != 2 || found[0].Targets[0].Status != model.StatusFixed {
		t.Fatalf("a fixed finding is found by default, with its status: %+v %v", found, err)
	}
}

func TestSearchParseErrorIsReturned(t *testing.T) {
	s := open(t, bundle(t, nil), seeded(t), "alice")
	if _, err := s.Search("severity:urgent", query.Filter{}, false); err == nil || !strings.Contains(err.Error(), "unknown severity") {
		t.Fatalf("a bad query must be an error: %v", err)
	}
}

func TestPublishedFilterAndHorizonApplyToSearchListAndDigest(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice") // now is two days after the issue was published

	week, _ := query.ParseTimeRange("week")
	day1, _ := query.ParseTimeRange("day")
	for name, c := range map[string]struct {
		f    query.Filter
		text string
		want int
	}{
		"search flag, inside":  {query.Filter{Published: week}, "tracked", 1},
		"search flag, outside": {query.Filter{Published: day1}, "tracked", 0},
		"field, inside":        {query.Filter{}, "tracked published:week", 1},
		"field, outside":       {query.Filter{}, "tracked published:24h", 0},
		"field, range":         {query.Filter{}, "tracked published:2026-10-01", 1},
	} {
		found, err := s.Search(c.text, c.f, false)
		if err != nil || len(found) != c.want {
			t.Errorf("%s: %d issues, %v", name, len(found), err)
		}
	}
	if list, err := s.List(query.Filter{Published: day1}); err != nil || len(list) != 0 {
		t.Errorf("list outside: %+v %v", list, err)
	}
	if d, err := s.Digest(); err != nil || d.Open != 1 {
		t.Fatalf("digest without a horizon: %+v %v", d, err)
	}
	s.Cfg.Horizon = config.Horizon{Window: config.WindowDay}
	if d, err := s.Digest(); err != nil || d.Open != 0 {
		t.Fatalf("the digest preview must follow the horizon: %+v %v", d, err)
	}
}
