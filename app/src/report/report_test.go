package report

import (
	"strings"
	"testing"
	"time"

	"cvewatch/src/model"
	"cvewatch/src/query"
)

func TestPathIsStable(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-2026-1111", Techs: []string{"php"}, FirstSeen: time.Date(2026, 10, 27, 23, 0, 0, 0, time.UTC)}
	if got := Path("alerts", v); got != "alerts/2026/2026-10-27-php-cve-2026-1111.md" {
		t.Fatal(got)
	}
	v.Techs = nil
	if got := Path("alerts", v); !strings.Contains(got, "-deps-") {
		t.Fatal(got)
	}
}

func TestDigestGroupsMarksAndLinks(t *testing.T) {
	issues := []query.Issue{
		{ID: "CRIT", Severity: model.SevCritical, Untrusted: query.Untrusted{Title: "crit one"},
			Refs:    []model.Ref{{URL: "https://x.test/crit"}, {URL: "https://y.test"}},
			Targets: []query.Target{{Project: "mw", Env: model.EnvProd}}},
		{ID: "OLD", Severity: model.SevHigh, Targets: []query.Target{{Project: "shop", Env: model.EnvProd}, {Project: "shop", Env: model.EnvDev}}},
		{ID: "NEW", Severity: model.SevHigh, Targets: []query.Target{{Project: "shop", Env: model.EnvProd}}},
		{ID: "ODD", Severity: model.SevUnknown, Targets: []query.Target{{Project: "shop", Env: model.EnvProd}}},
	}
	out := Digest(issues, map[string]bool{"NEW": true})
	for _, want := range []string{"Open findings: 4", "CRITICAL (1)", "HIGH (2)", "UNRATED (1)", "NEW NEW",
		"mw: prod  (+1 related)", "shop: prod,dev", "https://x.test/crit"} {
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

func TestRenderShowsDescriptionAndOriginal(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "Bug", Summary: "Plain words.", Severity: model.SevHigh,
		Aliases: []string{"CVE-2"}, Refs: []model.Ref{{Source: "nvd", URL: "https://a.test/1"}, {Source: "hn", URL: "https://b.test/2"}}}
	out := Render(v, []model.Finding{{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen}})
	for _, want := range []string{"## Description", "Plain words.", "**Original:** https://a.test/1", "https://b.test/2 (hn)", "**Also reported as:** CVE-2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	v.Summary = ""
	if !strings.Contains(Render(v, nil), "gave no description") {
		t.Error("missing no-description note")
	}
}

func TestRenderNeutralizesHostileText(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "<script>alert(1)</script> bug", Summary: "<img src=x onerror=1>",
		Severity: model.SevHigh, Refs: []model.Ref{{Source: "s", URL: "https://a.test/<b>"}}}
	out := Render(v, []model.Finding{{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen,
		Note: "line1\nline2 | pipe"}})
	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") || strings.Contains(out, "<b>") {
		t.Fatalf("raw markup survived:\n%s", out)
	}
	if !strings.Contains(out, "line1 line2 \\| pipe") {
		t.Fatalf("table cell not sanitized:\n%s", out)
	}
}
