package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func sample() []query.Issue {
	return []query.Issue{{
		ID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa", "OSV-1"}, Severity: model.SevCritical, CVSS: 9.8,
		Published: now.Add(-50 * time.Hour), Age: "2d 2h", AgeHours: 50, FirstSeen: now.Add(-48 * time.Hour),
		Techs: []string{"php"}, Applies: model.AppAffected, ArticleCount: 2,
		Fix:      query.FixInfo{Available: true, Official: true},
		KEV:      &query.KEVInfo{DateAdded: now.Add(-24 * time.Hour), DueDate: now.Add(72 * time.Hour), Ransomware: true},
		EPSS:     &model.EPSS{Score: 0.97312, Percentile: 0.99, Date: now.Add(-24 * time.Hour)},
		Priority: []string{"known exploited", "open in prod"}, ProdOpen: true, Report: "reports/CVE-2026-0001.md",
		Targets: []query.Target{
			{Project: "shop", Env: model.EnvStaging, Status: model.StatusOpen, Applies: model.AppAffected, Matched: []string{"php 8.2.1", "ext-x"},
				Reasons: []string{"version in range", "tech match"}, Owner: "ann", Due: now.Add(-24 * time.Hour), Overdue: true, Ticket: "OPS-1",
				Updated: now.Add(-time.Hour), Note: "waiting for window", Evidence: 2},
			{Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppAffected, Matched: []string{"php 8.2.1"},
				Owner: "bob", Due: now.Add(24 * time.Hour), Updated: now},
			{Project: "blog", Env: model.EnvProd, Status: model.StatusFixed, Applies: model.AppUnknown, Matched: []string{}, Updated: now},
		},
		Untrusted: query.Untrusted{
			Title: "PHP remote code execution", Description: "A flaw.",
			Articles: []query.Article{
				{Title: "News", URL: "https://example.com/a", Source: "feed1", Published: now.Add(-40 * time.Hour)},
				{Title: "More", URL: "https://example.com/b", Source: "feed2", Published: now.Add(-30 * time.Hour)},
			},
			Fixes:     []model.Fix{{Kind: model.FixVersion, Detail: "8.2.2", URL: "https://example.com/fix", Source: "feed1", Official: true}},
			KEVAction: "Apply updates.",
		},
	}}
}

func titled(titles ...string) []query.Issue {
	var out []query.Issue
	for _, t := range titles {
		out = append(out, query.Issue{
			ID: "CVE-1", Severity: model.SevLow, Published: now, Applies: model.AppUnknown,
			Targets:   []query.Target{{Project: "p", Env: model.EnvDev, Status: model.StatusOpen, Applies: model.AppAffected, Matched: []string{}, Updated: now, Note: t}},
			Untrusted: query.Untrusted{Title: t, Articles: []query.Article{}},
		})
	}
	return out
}

func csvRows(t *testing.T, d Document) [][]string {
	t.Helper()
	var buf bytes.Buffer
	if err := d.WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func col(t *testing.T, name string) int {
	t.Helper()
	for i, h := range csvHeader {
		if h == name {
			return i
		}
	}
	t.Fatalf("no column %s", name)
	return -1
}

func TestNew(t *testing.T) {
	d := New(nil, now.In(time.FixedZone("x", 3600)))
	if d.Issues == nil || len(d.Issues) != 0 || d.Count != 0 || d.SchemaVersion != 1 || !d.GeneratedAt.Equal(now) || d.GeneratedAt.Location() != time.UTC {
		t.Fatalf("%+v", d)
	}
	d = New([]query.Issue{{ID: "x"}}, now)
	if d.Count != 1 || d.Issues[0].Targets == nil || d.Issues[0].Untrusted.Articles == nil {
		t.Fatalf("%+v", d)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	d := New(sample(), now)
	var buf bytes.Buffer
	if err := d.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "{\n  \"schema_version\": 1,\n  \"generated_at\"") {
		t.Fatalf("not indented in field order:\n%s", buf.String()[:80])
	}
	var back Document
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, back) {
		t.Fatalf("round trip differs:\n%+v\n%+v", d, back)
	}
}

func TestCSVHeaderAndRows(t *testing.T) {
	rows := csvRows(t, New(sample(), now))
	if got := strings.Join(rows[0], ","); got != "id,aliases,severity,cvss,kev,kev_due,epss,published,age_hours,priority,project,env,status,applies,owner,due,overdue,ticket,matched,reasons,fix_available,official_fix,articles,note,updated,title,url" {
		t.Fatalf("header %s", got)
	}
	if len(rows) != 4 {
		t.Fatalf("want header + 3 target rows, got %d", len(rows))
	}
	want := map[string]string{
		"id": "CVE-2026-0001", "aliases": "GHSA-aaaa; OSV-1", "severity": "critical", "cvss": "9.8", "kev": "true", "kev_due": "2026-10-31",
		"epss": "0.973", "published": "2026-10-26", "age_hours": "50", "priority": "known exploited; open in prod",
		"project": "shop", "env": "staging", "status": "open", "applies": "affected", "owner": "ann", "due": "2026-10-27", "overdue": "true",
		"ticket": "OPS-1", "matched": "php 8.2.1; ext-x", "reasons": "version in range; tech match", "fix_available": "true",
		"official_fix": "true", "articles": "2", "note": "waiting for window", "updated": "2026-10-28T11:00:00Z",
		"title": "PHP remote code execution", "url": "https://example.com/a",
	}
	for k, v := range want {
		if got := rows[1][col(t, k)]; got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if rows[2][col(t, "overdue")] != "false" || rows[3][col(t, "project")] != "blog" || rows[3][col(t, "due")] != "" {
		t.Errorf("rows 2/3: %v %v", rows[2], rows[3])
	}
}

func TestCSVIssueWithoutTargets(t *testing.T) {
	is := sample()[:1]
	is[0].Targets = nil
	is[0].KEV, is[0].EPSS, is[0].CVSS = nil, nil, 0
	rows := csvRows(t, New(is, now))
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	for _, k := range []string{"project", "env", "status", "applies", "owner", "due", "overdue", "ticket", "matched", "reasons", "note", "updated", "kev_due", "epss", "cvss"} {
		if v := rows[1][col(t, k)]; v != "" {
			t.Errorf("%s = %q, want empty", k, v)
		}
	}
	if rows[1][col(t, "kev")] != "false" || rows[1][col(t, "id")] != "CVE-2026-0001" {
		t.Errorf("%v", rows[1])
	}
}

func TestCSVFormulaInjection(t *testing.T) {
	titles := []string{`=HYPERLINK("http://evil","x")`, "+1", "-2", "@x", "\tcmd", "\rcmd"}
	rows := csvRows(t, New(titled(titles...), now))
	for i, in := range titles {
		for _, k := range []string{"title", "note"} {
			got := rows[i+1][col(t, k)]
			if want := "'" + strings.NewReplacer("\r", " ").Replace(in); got != want {
				t.Errorf("%s: %q -> %q, want %q", k, in, got, want)
			}
		}
	}
	rows = csvRows(t, New(titled("safe = text", "a+b"), now))
	if rows[1][col(t, "title")] != "safe = text" || rows[2][col(t, "title")] != "a+b" {
		t.Errorf("harmless text was changed: %v", rows)
	}
}

func TestCSVNewlineInTitle(t *testing.T) {
	var buf bytes.Buffer
	if err := New(titled("line one\nline two\r\nthree, \"quoted\""), now).WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Fatalf("want 2 lines, got %d:\n%q", n, buf.String())
	}
	rows := csvRows(t, New(titled("line one\nline two\r\nthree, \"quoted\""), now))
	if got := rows[1][col(t, "title")]; got != `line one line two three, "quoted"` {
		t.Fatalf("%q", got)
	}
}

func TestMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := New(sample(), now).WriteMarkdown(&buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{
		"# Vulnerability export", "Generated: 2026-10-28T12:00:00Z", "Count: 1",
		"## shop", "## blog", "| ID | Sev | Env | Status | Version | Owner | Due | Age | Fix | KEV | Title |",
		"| CVE-2026-0001 | critical | staging | open | php 8.2.1; ext-x | ann | 2026-10-27 (overdue) | 2d 2h | official | yes | PHP remote code execution |",
		"Schema version 1\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Index(s, "## shop") > strings.Index(s, "## blog") {
		t.Error("projects not in document order")
	}
}

func TestMarkdownEscaping(t *testing.T) {
	var buf bytes.Buffer
	if err := New(titled("<script>alert(1)</script> | a\\|b\nnext"), now).WriteMarkdown(&buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if strings.Contains(s, "<script>") || !strings.Contains(s, "&lt;script&gt;alert(1)&lt;/script&gt; \\| a\\\\\\|b next") {
		t.Fatalf("not escaped:\n%s", s)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "| CVE-1") && strings.Count(strings.ReplaceAll(strings.ReplaceAll(line, `\\`, ""), `\|`, ""), "|") != 12 {
			t.Fatalf("pipes break the row: %s", line)
		}
	}
}

func TestMarkdownClipsTitle(t *testing.T) {
	var buf bytes.Buffer
	if err := New(titled(strings.Repeat("ä", 300)), now).WriteMarkdown(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), strings.Repeat("ä", 99)+"…") || strings.Contains(buf.String(), strings.Repeat("ä", 100)) {
		t.Fatalf("title not clipped to 100 runes:\n%s", buf.String())
	}
}

func TestEmptyDocument(t *testing.T) {
	d := New(nil, now)
	var j, c, m bytes.Buffer
	if err := d.WriteJSON(&j); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.String(), `"issues": []`) || !strings.Contains(j.String(), `"count": 0`) {
		t.Errorf("json: %s", j.String())
	}
	if err := d.WriteCSV(&c); err != nil {
		t.Fatal(err)
	}
	if strings.Count(c.String(), "\n") != 1 || !strings.HasPrefix(c.String(), "id,aliases,") {
		t.Errorf("csv: %q", c.String())
	}
	if err := d.WriteMarkdown(&m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.String(), "Count: 0") || !strings.Contains(m.String(), "Schema version 1") || strings.Contains(m.String(), "| ID |") {
		t.Errorf("md: %s", m.String())
	}
	if err := (Document{}).WriteJSON(&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFormats(t *testing.T) {
	d := New(sample(), now)
	for _, f := range append(Formats(), "markdown", "JSON", " csv ") {
		if err := Write(&bytes.Buffer{}, f, d); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	err := Write(&bytes.Buffer{}, "xml", d)
	if err == nil || !strings.Contains(err.Error(), `"xml"`) || !strings.Contains(err.Error(), "json, csv, md") {
		t.Fatalf("err = %v", err)
	}
}

func TestStableOutput(t *testing.T) {
	for _, f := range Formats() {
		var a, b bytes.Buffer
		if err := Write(&a, f, New(sample(), now)); err != nil {
			t.Fatal(err)
		}
		if err := Write(&b, f, New(sample(), now)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.Bytes(), b.Bytes()) || a.Len() == 0 {
			t.Errorf("%s output differs between runs", f)
		}
	}
}

// ---- schema drift ----

func TestSchemaMatchesEmittedJSON(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/schema/export-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if v := schema["properties"].(map[string]any)["schema_version"].(map[string]any)["const"]; v != float64(SchemaVersion) {
		t.Errorf("schema const = %v, SchemaVersion = %d", v, SchemaVersion)
	}
	out, err := json.Marshal(New(sample(), now))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	checkObject(t, "$", doc, schema)
}

// checkObject walks an emitted value next to its schema: every emitted key
// must be declared, every required key emitted, and (the sample fills every
// field) every declared property emitted, so a field removed in code or left
// behind in the schema fails.
func checkObject(t *testing.T, path string, val map[string]any, schema map[string]any) {
	t.Helper()
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		t.Errorf("%s: schema has no properties", path)
		return
	}
	for k := range val {
		if _, ok := props[k]; !ok {
			t.Errorf("%s.%s is emitted but not in the schema", path, k)
		}
	}
	req, _ := schema["required"].([]any)
	for _, r := range req {
		if _, ok := val[r.(string)]; !ok {
			t.Errorf("%s.%s is required by the schema but not emitted", path, r)
		}
	}
	for k, ps := range props {
		v, ok := val[k]
		if !ok {
			t.Errorf("%s.%s is in the schema but not emitted (sample is fully populated)", path, k)
			continue
		}
		ps, _ := ps.(map[string]any)
		switch x := v.(type) {
		case map[string]any:
			checkObject(t, path+"."+k, x, ps)
		case []any:
			items, _ := ps["items"].(map[string]any)
			for _, e := range x {
				if m, ok := e.(map[string]any); ok && items != nil {
					checkObject(t, path+"."+k+"[]", m, items)
					break // elements share a schema; the first one is enough
				}
			}
		}
	}
}

func TestSARIFHasARulePerIssueAndAResultPerTarget(t *testing.T) {
	d := New([]query.Issue{{
		ID: "CVE-2026-1", Severity: model.SevCritical, Untrusted: query.Untrusted{Title: "Bad bug"},
		Targets: []query.Target{{Project: "shop", Env: model.EnvProd, Status: model.StatusOpen}, {Project: "shop", Env: model.EnvDev, Status: model.StatusOpen}},
	}, {ID: "CVE-2026-2", Severity: model.SevLow}}, time.Now())
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", d); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string }
				}
			}
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	r := got.Runs[0]
	if got.Version != "2.1.0" || len(r.Tool.Driver.Rules) != 2 || len(r.Results) != 2 || r.Results[0].Level != "error" || r.Results[0].RuleID != "CVE-2026-1" {
		t.Fatalf("sarif = %s", buf.String())
	}
}
