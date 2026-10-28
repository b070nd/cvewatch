package dashboard

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/status"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func tgt(project string, env model.Env, st model.Status) query.Target {
	return query.Target{Project: project, Env: env, Status: st, Applies: model.AppAffected}
}

func issue(id string, sev model.Severity, ts ...query.Target) query.Issue {
	return query.Issue{ID: id, Severity: sev, Targets: ts, Untrusted: query.Untrusted{Title: "title of " + id}}
}

// cell returns the html of one matrix cell.
func cell(t *testing.T, page, project string, env model.Env) string {
	t.Helper()
	start := strings.Index(page, fmt.Sprintf("<tr><th scope=\"row\">%s</th>", project))
	if start < 0 {
		t.Fatalf("no row for project %q", project)
	}
	row := page[start : start+strings.Index(page[start:], "</tr>")]
	parts := strings.Split(row, "<td")[1:]
	for i, e := range model.AllEnvs {
		if e == env {
			return parts[i]
		}
	}
	t.Fatalf("unknown env %q", env)
	return ""
}

func fullEnvs() []model.Env { return model.AllEnvs }

func TestMatrixCountsAndWorstSeverity(t *testing.T) {
	d := Data{
		Projects: []Project{{Name: "shop", Envs: fullEnvs()}},
		Issues: []query.Issue{
			issue("CVE-1", model.SevMedium, tgt("shop", model.EnvProd, model.StatusOpen)),
			issue("CVE-2", model.SevCritical, tgt("shop", model.EnvProd, model.StatusOpen), tgt("shop", model.EnvDev, model.StatusOpen)),
			issue("CVE-3", model.SevHigh, tgt("shop", model.EnvProd, model.StatusOpen)),
		},
	}
	page := HTML(d, now)
	prod := cell(t, page, "shop", model.EnvProd)
	if !strings.Contains(prod, `class="badge s0"`) || !strings.Contains(prod, "<strong>3</strong> open") {
		t.Errorf("prod cell should show worst critical with 3 open: %s", prod)
	}
	dev := cell(t, page, "shop", model.EnvDev)
	if !strings.Contains(dev, `class="badge s0"`) || !strings.Contains(dev, "<strong>1</strong> open") {
		t.Errorf("dev cell: %s", dev)
	}
	if !strings.Contains(prod, `title="CVE-1, CVE-2, CVE-3"`) {
		t.Errorf("prod cell should list issue ids in its title: %s", prod)
	}
	if !strings.Contains(cell(t, page, "shop", model.EnvInt), "clear") {
		t.Error("an environment with no findings should read clear")
	}
}

func TestMatrixWorstIgnoresClosedTargets(t *testing.T) {
	d := Data{
		Projects: []Project{{Name: "shop", Envs: fullEnvs()}},
		Issues: []query.Issue{
			issue("CVE-1", model.SevLow, tgt("shop", model.EnvProd, model.StatusOpen)),
			issue("CVE-2", model.SevCritical, tgt("shop", model.EnvProd, model.StatusFixed)),
		},
	}
	prod := cell(t, HTML(d, now), "shop", model.EnvProd)
	if !strings.Contains(prod, `class="badge s3"`) || strings.Contains(prod, "s0") {
		t.Errorf("worst open should be low: %s", prod)
	}
}

func TestMatrixTitleCapsIDs(t *testing.T) {
	var is []query.Issue
	for i := 1; i <= 7; i++ {
		is = append(is, issue(fmt.Sprintf("CVE-%d", i), model.SevLow, tgt("shop", model.EnvDev, model.StatusOpen)))
	}
	dev := cell(t, HTML(Data{Projects: []Project{{Name: "shop", Envs: fullEnvs()}}, Issues: is}, now), "shop", model.EnvDev)
	if !strings.Contains(dev, `title="CVE-1, CVE-2, CVE-3, CVE-4, CVE-5 (+2 more)"`) {
		t.Errorf("title should list 5 ids: %s", dev)
	}
}

func TestMatrixFixedOnlyCell(t *testing.T) {
	d := Data{
		Projects: []Project{{Name: "shop", Envs: fullEnvs()}},
		Issues: []query.Issue{
			issue("CVE-1", model.SevHigh, tgt("shop", model.EnvStaging, model.StatusFixed), tgt("shop", model.EnvInt, model.StatusIgnored)),
			issue("CVE-2", model.SevHigh, tgt("shop", model.EnvStaging, model.StatusFixed), tgt("shop", model.EnvInt, model.StatusNotAffected), tgt("shop", model.EnvProd, model.StatusOpen)),
		},
	}
	page := HTML(d, now)
	st := cell(t, page, "shop", model.EnvStaging)
	if !strings.Contains(st, `<span class="muted">2 fixed</span>`) || strings.Contains(st, "badge") {
		t.Errorf("staging should be muted fixed count only: %s", st)
	}
	in := cell(t, page, "shop", model.EnvInt)
	if !strings.Contains(in, "1 ignored, 1 not affected") {
		t.Errorf("int cell: %s", in)
	}
}

func TestMatrixAbsentEnvAndOverdue(t *testing.T) {
	over := tgt("api", model.EnvProd, model.StatusOpen)
	over.Overdue = true
	d := Data{
		Projects: []Project{{Name: "zeta", Envs: []model.Env{model.EnvProd}}, {Name: "api", Envs: []model.Env{model.EnvDev, model.EnvProd}}},
		Issues:   []query.Issue{issue("CVE-1", model.SevHigh, over)},
	}
	page := HTML(d, now)
	if c := cell(t, page, "api", model.EnvStaging); !strings.Contains(c, ">-<") {
		t.Errorf("absent env should show a dash: %s", c)
	}
	if c := cell(t, page, "zeta", model.EnvDev); !strings.Contains(c, ">-<") {
		t.Errorf("absent env should show a dash: %s", c)
	}
	if c := cell(t, page, "api", model.EnvProd); !strings.Contains(c, "overdue") {
		t.Errorf("overdue marker missing: %s", c)
	}
	if strings.Contains(cell(t, page, "api", model.EnvDev), "overdue") {
		t.Error("overdue marker on the wrong cell")
	}
	if strings.Index(page, ">api</th>") > strings.Index(page, ">zeta</th>") {
		t.Error("rows should be ordered by project name")
	}
}

func TestKPIs(t *testing.T) {
	over := tgt("shop", model.EnvProd, model.StatusOpen)
	over.Overdue = true
	over2 := tgt("shop", model.EnvDev, model.StatusOpen)
	over2.Overdue = true
	kev := issue("CVE-2", model.SevCritical, over, over2)
	kev.KEV = &query.KEVInfo{}
	kev.ProdOpen = true
	d := Data{
		Issues: []query.Issue{
			issue("CVE-1", model.SevLow, tgt("shop", model.EnvDev, model.StatusOpen)),
			kev,
			issue("CVE-3", model.SevHigh, tgt("shop", model.EnvDev, model.StatusOpen)),
			issue("CVE-4", model.SevMedium),
		},
		Violations: []priority.Violation{{Rule: "r"}, {Rule: "r"}},
	}
	page := HTML(d, now)
	for label, n := range map[string]int{
		"open issues": 4, "critical + high open": 2, "known exploited (KEV) open": 1,
		"open in prod": 1, "overdue findings": 2, "policy violations": 2,
	} {
		want := fmt.Sprintf(`<div class="n">%d</div><div class="l">%s</div>`, n, label)
		if !strings.Contains(page, want) {
			t.Errorf("missing KPI %q = %d", label, n)
		}
	}
}

func TestPolicyTable(t *testing.T) {
	d := Data{Violations: []priority.Violation{{
		Rule:    "kev-prod",
		Subject: priority.Subject{VulnID: "CVE-9", Project: "shop", Env: model.EnvProd},
		Reason:  "still open after 24h",
		Late:    52 * time.Hour,
	}}}
	page := HTML(d, now)
	for _, want := range []string{"<td>kev-prod</td>", "CVE-9", "shop / prod", "still open after 24h", "2d 4h"} {
		if !strings.Contains(page, want) {
			t.Errorf("policy table missing %q", want)
		}
	}
	if !strings.Contains(HTML(Data{}, now), "No policy violations.") {
		t.Error("empty policy table should say so")
	}
}

func TestHealthSection(t *testing.T) {
	d := Data{Status: status.Report{
		Level:  status.Fail,
		Daemon: status.Daemon{Level: status.Warn, Mode: "daemon", LastCycle: now.Add(-time.Hour), NextRun: now.Add(time.Hour), Message: "slow cycle"},
		Sources: []status.SourceRow{
			{ID: "ghsa", Type: "rss", Level: status.OK, LastSuccess: now},
			{ID: "bad", Type: "rss", Level: status.Fail, Failures: 7, LastError: "boom: connection refused"},
		},
		Channels: []status.ChannelRow{{Name: "slack", Level: status.OK}},
		Cycles:   []status.CycleRow{{Started: now, Items: 10, New: 2, Findings: 3, Alerted: 1, Failed: 1, Err: "cycle err"}},
		Warnings: []string{"config is old"},
	}}
	page := HTML(d, now)
	for _, want := range []string{
		"✖ FAIL", "! WARN", "✔ OK", "slow cycle", "2026-10-28 11:00 UTC", "2026-10-28 13:00 UTC",
		"boom: connection refused", "<td>7</td>", "cycle err", "config is old", "slack", "never",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("health section missing %q", want)
		}
	}
	if strings.Index(page, "<td>bad</td>") > strings.Index(page, "<td>ghsa</td>") {
		t.Error("sources should be sorted by id")
	}
	if !strings.Contains(HTML(Data{}, now), "? UNKNOWN") {
		t.Error("empty level should read unknown")
	}
}

func TestLastFiveCycles(t *testing.T) {
	var cs []status.CycleRow
	for i := 0; i < 8; i++ {
		cs = append(cs, status.CycleRow{Started: now.Add(-time.Duration(i) * time.Hour), Err: fmt.Sprintf("err-%d", i)})
	}
	page := HTML(Data{Status: status.Report{Cycles: cs}}, now)
	if !strings.Contains(page, "err-4") || strings.Contains(page, "err-5") {
		t.Error("only the 5 most recent cycles should show")
	}
}

func TestEmptyData(t *testing.T) {
	page := HTML(Data{}, time.Time{})
	for _, want := range []string{"Nothing open", "cvewatch dashboard", footerLine, `<div class="n">0</div><div class="l">open issues</div>`} {
		if !strings.Contains(page, want) {
			t.Errorf("empty page missing %q", want)
		}
	}
}

func TestEscaping(t *testing.T) {
	xss := `<script>alert(1)</script>`
	attr := `" onmouseover="x`
	over := tgt(xss+attr, model.EnvProd, model.StatusOpen)
	is := issue(xss+attr, model.SevHigh, over)
	is.Untrusted.Title = xss + attr
	is.Untrusted.Articles = []query.Article{{URL: xss + attr}}
	d := Data{
		Projects: []Project{{Name: xss + attr, Envs: fullEnvs()}},
		Issues:   []query.Issue{is},
		Violations: []priority.Violation{{
			Rule: xss, Reason: attr, Subject: priority.Subject{VulnID: xss + attr, Project: xss, Env: model.Env(attr)},
		}},
		Status: status.Report{
			Daemon:   status.Daemon{Message: xss + attr},
			Sources:  []status.SourceRow{{ID: xss, Type: attr, LastError: xss + attr}},
			Channels: []status.ChannelRow{{Name: xss, LastError: attr}},
			Cycles:   []status.CycleRow{{Err: xss + attr}},
			Warnings: []string{xss + attr},
		},
	}
	page := HTML(d, now)
	for _, bad := range []string{xss, attr, "<script"} {
		if strings.Contains(page, bad) {
			t.Errorf("unescaped payload %q in output", bad)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("payload should appear escaped")
	}
}

func TestNoActiveOrExternalContent(t *testing.T) {
	is := issue("CVE-1", model.SevHigh, tgt("shop", model.EnvProd, model.StatusOpen))
	is.KEV = &query.KEVInfo{}
	is.EPSS = &model.EPSS{Score: 0.5}
	d := Data{
		Projects:   []Project{{Name: "shop", Envs: fullEnvs()}},
		Issues:     []query.Issue{is},
		Violations: []priority.Violation{{Rule: "r"}},
		Status:     status.Report{Level: status.OK, Sources: []status.SourceRow{{ID: "s"}}},
	}
	for _, page := range []string{HTML(d, now), HTML(Data{}, now)} {
		if !strings.Contains(page, `content="default-src 'none'; style-src 'unsafe-inline'"`) {
			t.Error("CSP meta missing")
		}
		for _, bad := range []string{"<script", "<link", "<img", "src=", "href=", "http:", "https:", "//", "@import", "url("} {
			if strings.Contains(page, bad) {
				t.Errorf("page contains %q", bad)
			}
		}
	}
}

func TestArticleURLIsPlainText(t *testing.T) {
	is := issue("CVE-1", model.SevHigh)
	is.Untrusted.Articles = []query.Article{
		{URL: "https://evil.example/a?x=1&y=2"},
		{URL: "https://other.example/b"},
	}
	page := HTML(Data{Issues: []query.Issue{is}}, now)
	if !strings.Contains(page, "<code>https://evil.example/a?x=1&amp;y=2</code>") {
		t.Error("first article URL should be plain text in code")
	}
	if strings.Contains(page, "other.example") {
		t.Error("only the first article should show")
	}
	for _, bad := range []string{"href=", "src=", "<a "} {
		if strings.Contains(page, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

func TestTopListRowsAndFlags(t *testing.T) {
	is := issue("CVE-1", model.SevCritical, tgt("shop", model.EnvProd, model.StatusOpen), tgt("shop", model.EnvDev, model.StatusOpen), tgt("api", model.EnvInt, model.StatusFixed))
	is.KEV = &query.KEVInfo{}
	is.EPSS = &model.EPSS{Score: 0.43}
	is.Age = "2d 4h"
	is.Fix = query.FixInfo{Available: true, Official: true}
	is.Untrusted.Title = strings.Repeat("x", 150)
	page := HTML(Data{Issues: []query.Issue{is}}, now)
	for _, want := range []string{"KEV", "EPSS 43%", "shop: dev, prod", "2d 4h", "official fix", strings.Repeat("x", 99) + "…"} {
		if !strings.Contains(page, want) {
			t.Errorf("top list missing %q", want)
		}
	}
	if strings.Contains(page, "api: int") || strings.Contains(page, strings.Repeat("x", 100)) {
		t.Error("closed targets must not be listed as open, titles are clipped to 100 runes")
	}
}

func TestTopListCap(t *testing.T) {
	var is []query.Issue
	for i := 1; i <= 20; i++ {
		is = append(is, issue(fmt.Sprintf("CVE-2026-%04d", i), model.SevHigh))
	}
	page := HTML(Data{Issues: is}, now)
	if n := strings.Count(page, `<tr class="issue">`); n != 15 {
		t.Errorf("rows = %d, want 15", n)
	}
	if !strings.Contains(page, "CVE-2026-0015") || strings.Contains(page, "CVE-2026-0016") {
		t.Error("cap should keep the first 15 in the given order")
	}
	if !strings.Contains(page, `<div class="n">20</div><div class="l">open issues</div>`) {
		t.Error("KPI should count all issues, not just the shown ones")
	}
}

func TestDeterministic(t *testing.T) {
	d := Data{
		Projects: []Project{{Name: "b", Envs: fullEnvs()}, {Name: "a", Envs: fullEnvs()}},
		Issues: []query.Issue{
			issue("CVE-1", model.SevHigh, tgt("a", model.EnvProd, model.StatusOpen), tgt("b", model.EnvDev, model.StatusOpen), tgt("b", model.EnvProd, model.StatusFixed)),
			issue("CVE-2", model.SevLow, tgt("b", model.EnvProd, model.StatusOpen)),
		},
		Status: status.Report{Sources: []status.SourceRow{{ID: "z"}, {ID: "a"}}, Channels: []status.ChannelRow{{Name: "y"}, {Name: "x"}}},
	}
	first := HTML(d, now)
	for range 20 {
		if HTML(d, now) != first {
			t.Fatal("output differs between calls")
		}
	}
	// the input must not be reordered
	if d.Status.Sources[0].ID != "z" || d.Projects[0].Name != "b" {
		t.Error("HTML mutated its input")
	}
}

func TestTimesAreUTC(t *testing.T) {
	zone := time.FixedZone("X", 5*3600)
	page := HTML(Data{}, time.Date(2026, 10, 28, 12, 0, 0, 0, zone))
	if !regexp.MustCompile(`Generated 2026-10-28 07:00 UTC`).MatchString(page) {
		t.Error("generated time should be in UTC")
	}
}
