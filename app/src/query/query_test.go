package query

import (
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

var (
	day = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now = day.AddDate(0, 0, 3).Add(5 * time.Hour)
)

func seed() *ledger.Ledger {
	l := ledger.New(ledger.State{})
	add := func(id string, sev model.Severity, first time.Time, aliases ...string) *model.Vulnerability {
		v := l.Create(model.Item{Title: id + " title", URL: "https://a.test/" + id, IDs: append([]string{id}, aliases...),
			Severity: sev, Published: first, SourceID: "feed", SourceType: "rss"}, first, []string{"php"})
		return v
	}
	add("LOW", model.SevLow, day)
	crit := add("CRIT", model.SevCritical, day, "GHSA-AAAA-BBBB-CCCC")
	add("OLD", model.SevHigh, day)
	add("NEW", model.SevHigh, day.AddDate(0, 0, 1))

	// Articles arrive out of order; the collection must come back oldest first.
	crit.Refs = []model.Ref{
		{Source: "hn", Kind: model.RefArticle, URL: "https://late.test", Title: "late", Published: day.Add(48 * time.Hour)},
		{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test"},
		{Source: "rss", Kind: model.RefArticle, URL: "https://early.test", Title: "early", Published: day.Add(time.Hour)},
		{Source: "rss", Kind: model.RefArticle, URL: "https://undated.test", Title: "undated"},
	}
	crit.Fixes = []model.Fix{{Kind: model.FixVersion, Detail: "8.2.30", Source: "ghsa", Official: true}}

	for _, f := range []model.Finding{
		{VulnID: "LOW", Project: "shop", Env: model.EnvProd},
		{VulnID: "NEW", Project: "shop", Env: model.EnvProd},
		{VulnID: "OLD", Project: "shop", Env: model.EnvDev, Status: model.StatusFixed},
		{VulnID: "OLD", Project: "shop", Env: model.EnvProd},
		{VulnID: "CRIT", Project: "mw", Env: model.EnvProd, Applies: model.AppAffected},
		{VulnID: "CRIT", Project: "mw", Env: model.EnvDev, Applies: model.AppNotAffected},
	} {
		if f.Status == "" {
			f.Status = model.StatusOpen
		}
		l.AddFinding(f)
	}
	return l
}

func ids(is []Issue) string {
	var out []string
	for _, i := range is {
		out = append(out, i.ID)
	}
	return strings.Join(out, ",")
}

func TestOpenOrdersFiltersAndHidesUnaffected(t *testing.T) {
	l := seed()
	if got := ids(Open(l, Filter{}, now)); got != "CRIT,OLD,NEW,LOW" { // severity desc, older first inside one
		t.Fatalf("order: %s", got)
	}
	crit := Open(l, Filter{}, now)[0]
	if len(crit.Targets) != 1 || crit.Targets[0].Env != model.EnvProd || crit.Applies != model.AppAffected {
		t.Fatalf("unaffected target must be hidden: %+v", crit.Targets)
	}
	if all := Open(l, Filter{All: true}, now)[0]; len(all.Targets) != 2 {
		t.Fatalf("All must include unaffected targets: %+v", all.Targets)
	}
	if got := ids(Open(l, Filter{Min: model.SevHigh}, now)); got != "CRIT,OLD,NEW" {
		t.Fatalf("min: %s", got)
	}
	if got := ids(Open(l, Filter{Projects: []string{"mw"}}, now)); got != "CRIT" {
		t.Fatalf("access filter: %s", got)
	}
}

func TestArticlesChronologicalWithCountAgeAndFix(t *testing.T) {
	is, err := One(seed(), "ghsa-aaaa-bbbb-cccc", Filter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, a := range is.Untrusted.Articles {
		order = append(order, a.Title)
	}
	if strings.Join(order, ",") != "early,late,undated" || is.ArticleCount != 3 {
		t.Fatalf("articles must be oldest first, advisories excluded: %v count=%d", order, is.ArticleCount)
	}
	if is.Age != "3d 5h" || is.AgeHours != 77 {
		t.Fatalf("age: %q %d", is.Age, is.AgeHours)
	}
	if !is.Fix.Available || !is.Fix.Official || len(is.Untrusted.Fixes) != 1 {
		t.Fatalf("fix: %+v", is.Fix)
	}
	if _, err := One(seed(), "CRIT", Filter{Projects: []string{"shop"}}, now); err == nil {
		t.Fatal("a project outside the caller's access must look unknown")
	}
}

func TestAgeFormats(t *testing.T) {
	cases := map[time.Duration]string{
		12 * time.Minute: "12m", 5 * time.Hour: "5h", 52 * time.Hour: "2d 4h",
		21 * 24 * time.Hour: "3w", 200 * 24 * time.Hour: "6mo",
	}
	for d, want := range cases {
		if got := Age(now.Add(-d), now); got != want {
			t.Errorf("%v: got %q want %q", d, got, want)
		}
	}
	if Age(time.Time{}, now) != "" || Age(now.Add(time.Hour), now) != "" {
		t.Error("zero and future times must give an empty age")
	}
}

func TestClipKeepsRunesAndDropsEscapes(t *testing.T) {
	if got := Clip("ééééé ééééé", 7); got != "ééééé…" {
		t.Fatal(got)
	}
	if got := Clip("a\x1b[31mb‮c", 20); got != "a[31mbc" {
		t.Fatalf("got %q", got)
	}
}
