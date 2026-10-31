package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

var now = time.Date(2026, 10, 3, 5, 0, 0, 0, time.UTC)

func TestPathIsStable(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-2026-1111", Techs: []string{"php"}, FirstSeen: time.Date(2026, 10, 27, 23, 0, 0, 0, time.UTC)}
	if got := Path("alerts", v); got != filepath.Join("alerts", "2026", "2026-10-27-php-cve-2026-1111.md") {
		t.Fatal(got)
	}
	v.Techs = nil
	if got := Path("alerts", v); !strings.Contains(got, "-deps-") {
		t.Fatal(got)
	}
}

func TestDigestGroupsAndSummarizes(t *testing.T) {
	issues := []query.Issue{
		{ID: "CRIT", Severity: model.SevCritical, Age: "2d 4h", ArticleCount: 3, Applies: model.AppAffected,
			Aliases: []string{"GHSA-X"}, Fix: query.FixInfo{Available: true, Official: true},
			Untrusted: query.Untrusted{Title: "crit one", Articles: []query.Article{{URL: "https://x.test/first"}},
				Fixes: []model.Fix{{Kind: model.FixVersion, Detail: "8.2.30"}}},
			Targets: []query.Target{{Project: "mw", Env: model.EnvProd}}},
		{ID: "OLD", Severity: model.SevHigh, ArticleCount: 1, Targets: []query.Target{{Project: "shop", Env: model.EnvProd}, {Project: "shop", Env: model.EnvDev}}},
		{ID: "NEW", Severity: model.SevHigh, Targets: []query.Target{{Project: "shop", Env: model.EnvProd}}},
		{ID: "ODD", Severity: model.SevUnknown, Targets: []query.Target{{Project: "shop", Env: model.EnvProd}}},
	}
	out := Digest(issues, map[string]bool{"NEW": true})
	for _, want := range []string{"Open findings: 4", "CRITICAL (1)", "HIGH (2)", "UNRATED (1)", "NEW NEW",
		"mw: prod  [affected]  (+1 ids)", "shop: prod,dev  [unchecked]", "published 2d 4h ago · 3 articles · official fix: 8.2.30",
		"1 article · no fix known", "https://x.test/first"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "NEW OLD") {
		t.Errorf("OLD must not be marked new:\n%s", out)
	}
	if Digest(nil, nil) != "No open findings.\n" {
		t.Fatal("empty digest")
	}
}

func TestRenderShowsArticlesChronologicallyFixAndAge(t *testing.T) {
	v := &model.Vulnerability{
		ID: "CVE-1", Title: "Bug", Summary: "Plain words.", Severity: model.SevHigh, Aliases: []string{"CVE-2"},
		Published: now.Add(-77 * time.Hour),
		Refs: []model.Ref{
			{Source: "hn", Kind: model.RefArticle, URL: "https://late.test", Title: "Late", Published: now.Add(-time.Hour)},
			{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test/1"},
			{Source: "rss", Kind: model.RefArticle, URL: "https://early.test", Title: "Early", Published: now.Add(-70 * time.Hour)},
		},
		Fixes: []model.Fix{{Kind: model.FixVersion, Detail: "8.2.30", Source: "ghsa", Official: true, URL: "https://fix.test"}},
	}
	out := Render(v, []model.Finding{{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen,
		Applies: model.AppAffected, Reasons: []string{"php@8.2.10: in range"}}}, now)
	for _, want := range []string{"(3d 5h ago)", "**Articles found:** 2", "**Also reported as:** CVE-2",
		"**version** 8.2.30 (ghsa, official) https://fix.test", "https://nvd.test/1 (nvd)",
		"inside the affected range", "php@8.2.10: in range"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "Early") > strings.Index(out, "Late") || strings.Index(out, "Early") < 0 {
		t.Errorf("articles must be oldest first:\n%s", out)
	}
	v.Summary, v.Fixes = "", nil
	out = Render(v, nil, now)
	if !strings.Contains(out, "gave no description") || !strings.Contains(out, "No official fix") {
		t.Error("missing empty-state notes")
	}
}

func TestRenderNeutralizesHostileText(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "<script>alert(1)</script> bug", Summary: "<img src=x onerror=1>",
		Severity: model.SevHigh, Refs: []model.Ref{{Source: "s", Kind: model.RefArticle, URL: "https://a.test/<b>", Title: "<i>t</i>"}}}
	out := Render(v, []model.Finding{{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen,
		Note: "line1\nline2 | pipe"}}, now)
	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") || strings.Contains(out, "<b>") || strings.Contains(out, "<i>") {
		t.Fatalf("raw markup survived:\n%s", out)
	}
	if !strings.Contains(out, "line1 line2 \\| pipe") {
		t.Fatalf("table cell not sanitized:\n%s", out)
	}
}

func TestRenderShowsKEVEPSSOwnerDueAndEvidence(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "Bug", Severity: model.SevCritical, Published: now.Add(-48 * time.Hour),
		KEV:  &model.KEV{DateAdded: now.Add(-24 * time.Hour), DueDate: now.Add(72 * time.Hour), Ransomware: true, Action: "Apply <b>updates</b>."},
		EPSS: &model.EPSS{Score: 0.912, Percentile: 0.99}}
	due := now.Add(-time.Hour)
	out := Render(v, []model.Finding{{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen,
		Owner: "bob", Due: due, Ticket: "JIRA-1", Evidence: []model.Evidence{{Time: now, Actor: "bob", Note: "merged", URL: "https://mr.test/1"}}}}, now)
	for _, want := range []string{"**KEV:** on CISA's Known Exploited Vulnerabilities list since 2026-10-02, CISA remediation due 2026-10-06, known ransomware use",
		"Required action: Apply &lt;b&gt;updates&lt;/b&gt;.", "**EPSS:** 91% chance", "known exploited (CISA KEV)", "open in prod",
		"| shop | prod | open | unchecked | bob |", "(overdue)", "JIRA-1", "**Evidence:**", "bob: merged https://mr.test/1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<b>") {
		t.Error("feed text must stay escaped")
	}
}

func TestDigestFlagsKEVEPSSAndOverdue(t *testing.T) {
	out := Digest([]query.Issue{{ID: "CVE-9", Severity: model.SevHigh, ArticleCount: 1,
		KEV: &query.KEVInfo{DueDate: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)}, EPSS: &model.EPSS{Score: 0.5},
		Targets: []query.Target{{Project: "shop", Env: model.EnvProd, Overdue: true}}}}, nil)
	for _, want := range []string{"KEV, CISA due 2026-11-17", "EPSS 50%", "OVERDUE"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderDetailNamesTheScoreVersionAndVector(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "Bug", Severity: model.SevCritical, Published: now.Add(-time.Hour),
		CVSS: 9.3, CVSSVersion: model.CVSS40, CVSSVector: "CVSS:4.0/AV:N/AC:L", CVSSSource: model.ScoreCNA}
	out := RenderDetail(query.DetailOf(v, nil, now))
	for _, want := range []string{"**CVSS:** 9.3 (v4.0)", "**CVSS detail:** CVSS:4.0/AV:N/AC:L from cna"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	v.CVSSVersion, v.CVSSVector, v.CVSSSource = "", "", ""
	out = RenderDetail(query.DetailOf(v, nil, now))
	if !strings.Contains(out, "**CVSS:** 9.3\n") || strings.Contains(out, "CVSS detail") {
		t.Errorf("an old score prints as before:\n%s", out)
	}
}
