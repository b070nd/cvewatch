package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got with testdata/name; -update rewrites the file.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got { // a checkout may have turned the line ends into CRLF
		t.Errorf("%s differs from the golden file (run with -update to accept):\n%s", name, got)
	}
}

// rich is a vulnerability with every kind of fact, and its findings.
func rich() (*model.Vulnerability, []model.Finding) {
	v := &model.Vulnerability{
		ID: "CVE-2026-0100", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "Remote code execution in Example <b>Framework</b>",
		Summary: "An attacker can run code.", Severity: model.SevCritical, CVSS: 9.8,
		Published: now.Add(-77 * time.Hour), FirstSeen: now.Add(-70 * time.Hour), Techs: []string{"php"},
		KEV:  &model.KEV{DateAdded: now.Add(-24 * time.Hour), DueDate: now.Add(72 * time.Hour), Ransomware: true, Action: "Apply updates per vendor instructions."},
		EPSS: &model.EPSS{Score: 0.912, Percentile: 0.99},
		Refs: []model.Ref{
			{Source: "hn", Kind: model.RefArticle, URL: "https://news.test/late", Title: "Late news", Published: now.Add(-time.Hour)},
			{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test/CVE-2026-0100"},
			{Source: "rss", Kind: model.RefArticle, URL: "https://news.test/early", Title: "Early news", Published: now.Add(-70 * time.Hour)},
		},
		Fixes: []model.Fix{{Kind: model.FixVersion, Detail: "8.2.30", Source: "ghsa", Official: true, URL: "https://fix.test/8.2.30"}},
		Affected: []model.Affected{
			{Ecosystem: "composer", Name: "example/framework", Ranges: []model.Range{{Min: "8.0", Max: "8.2.30", MaxExcl: true}}, Fixed: "8.2.30"},
			{Ecosystem: "cpe", Name: "example:framework", Ranges: []model.Range{{}}},
		},
	}
	fs := []model.Finding{
		{VulnID: v.ID, Project: "mw", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown, Matched: []string{"php@8.2.10"}},
		{VulnID: v.ID, Project: "shop", Env: model.EnvDev, Status: model.StatusFixed, Applies: model.AppAffected, Matched: []string{"php@8.2.10"},
			Installed: []model.Installed{{Name: "php", Version: "8.2.10", Via: "tech"}, {Name: "example/framework", Version: "8.2.1", Ecosystem: "composer", Via: "package"}},
			Reasons:   []string{"php@8.2.10: in range"}, Owner: "bob", Ticket: "https://jira.test/SHOP-1",
			Evidence: []model.Evidence{{Time: now.Add(-2 * time.Hour), Actor: "bob", Note: "merged", URL: "https://mr.test/1"}},
			History: []model.Disposition{
				{Time: now.Add(-3 * time.Hour), Actor: "tui:bob", Action: "status", Status: model.StatusFixed, Note: "MR 1"},
				{Time: now.Add(-2 * time.Hour), Actor: "tui:bob", Action: "evidence", Note: "merged", URL: "https://mr.test/1"},
			}},
		{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppAffected, Matched: []string{"php@8.2.10"},
			Due: now.Add(-time.Hour), Installed: []model.Installed{{Name: "php", Version: "8.2.10", Via: "tech"}}},
	}
	return v, fs
}

func TestRenderGolden(t *testing.T) {
	v, fs := rich()
	golden(t, "render.md", Render(v, fs, now))
}

func TestRenderGoldenMinimal(t *testing.T) {
	golden(t, "render-minimal.md", Render(&model.Vulnerability{ID: "CVE-2026-0200", Title: "Bare", Severity: model.SevUnknown, Published: now.Add(-time.Hour)}, nil, now))
}
