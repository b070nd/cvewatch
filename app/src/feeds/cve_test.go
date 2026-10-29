package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

const cveLogURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"

// cveGetter serves a delta log (honouring Range) and records by URL.
type cveGetter struct {
	log     string
	records map[string]string // by record URL
	fail    map[string]error  // by record URL
	asked   []string
	ranges  []string
}

func (g *cveGetter) Get(_ context.Context, u string, _ model.Validators, h map[string]string) (*httpx.Response, error) {
	g.asked = append(g.asked, u)
	if u == cveLogURL {
		body := g.log
		if r := h["Range"]; r != "" {
			g.ranges = append(g.ranges, r)
			n, _ := strconv.Atoi(strings.TrimPrefix(r, "bytes=0-"))
			if n+1 < len(body) {
				body = body[:n+1]
			}
		}
		return &httpx.Response{Body: []byte(body)}, nil
	}
	if err := g.fail[u]; err != nil {
		return nil, err
	}
	if b, ok := g.records[u]; ok {
		return &httpx.Response{Body: []byte(b)}, nil
	}
	return nil, &httpx.StatusError{Code: 404, URL: u}
}

func recURL(id string) string {
	return "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/" + cveRecordPath(id)
}

// cveRecordPath mirrors the repository layout for the ids used in tests.
func cveRecordPath(id string) string {
	p := strings.Split(id, "-")
	n, _ := strconv.Atoi(p[2])
	return fmt.Sprintf("%s/%dxxx/%s.json", p[1], n/1000, id)
}

func deltaJSON(at string, ids ...string) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, `{"cveId":"`+id+`"}`)
	}
	return `{"fetchTime":"` + at + `","numberOfChanges":` + strconv.Itoa(len(ids)) + `,"new":[` + strings.Join(parts, ",") + `],"updated":[{"cveId":"CVE-2020-0001"}]}`
}

func logOf(deltas ...string) string { return "[" + strings.Join(deltas, ",") + "]" }

const adobeRecord = `{"cveMetadata":{"cveId":"CVE-2026-48356","state":"PUBLISHED","datePublished":"2026-07-14T19:44:17.036Z"},
"containers":{"cna":{"title":"Adobe Commerce | Unrestricted Upload of File with Dangerous Type (CWE-434)",
"descriptions":[{"lang":"en","value":"Adobe Commerce is affected by an upload flaw."}],
"affected":[{"vendor":"Adobe","product":"Adobe Commerce","versions":[
 {"version":"0","status":"affected","lessThanOrEqual":"2.4.9, 2.4.8-p5, 2.4.7-p10","versionType":"custom"},
 {"version":"2.4.9-2026-jul","status":"unaffected","versionType":"custom"}]},
 {"vendor":"Adobe","product":"Magento Open Source","versions":[{"version":"0","status":"affected","lessThanOrEqual":"2.4.9, 2.4.8-p5","versionType":"custom"}]}],
"metrics":[{"cvssV3_1":{"baseScore":9.3,"baseSeverity":"CRITICAL"}}],
"references":[{"url":"https://helpx.adobe.com/security/products/magento/apsb26-73.html","tags":["vendor-advisory"]},{"url":"javascript:alert(1)","tags":["patch"]}]}}}`

func TestCVERecordFromAVendorWithFreeTextVersions(t *testing.T) {
	var r cveRecord
	if err := jsonUnmarshal(adobeRecord, &r); err != nil {
		t.Fatal(err)
	}
	it, ok := r.item("cve-records")
	if !ok {
		t.Fatal("record dropped")
	}
	if it.IDs[0] != "CVE-2026-48356" || it.Severity != model.SevCritical || it.CVSS != 9.3 || it.Published.IsZero() {
		t.Errorf("item = %+v", it)
	}
	if !strings.Contains(it.Title, "Magento Open Source") || !strings.Contains(it.Title, "Unrestricted Upload") {
		t.Errorf("the title must name the products so tech matching finds them: %q", it.Title)
	}
	if len(it.Affected) != 0 {
		t.Errorf("free-text versions must not become ranges: %+v", it.Affected)
	}
	if len(it.Fixes) != 1 || it.Fixes[0].Kind != model.FixAdvisory || !it.Fixes[0].Official || !strings.Contains(it.Fixes[0].URL, "apsb26-73") {
		t.Errorf("fixes = %+v (a javascript: link must be dropped)", it.Fixes)
	}
	if it.URL != "https://www.cve.org/CVERecord?id=CVE-2026-48356" {
		t.Errorf("url = %q", it.URL)
	}
}

func TestCVERecordWithCPEsAndPlainVersions(t *testing.T) {
	rec := func(versions string) cveRecord {
		var r cveRecord
		doc := `{"cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{"title":"Bug",
"descriptions":[{"lang":"en","value":"A bug."}],"affected":[{"vendor":"Acme","product":"Widget","cpes":["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],"versions":` + versions + `}]}}}`
		if err := jsonUnmarshal(doc, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	got := rec(`[{"version":"1.0","status":"affected","lessThan":"1.4.2","versionType":"semver"},{"version":"2.0","status":"affected","lessThanOrEqual":"2.1.0"}]`).affected()
	want := []model.Range{{Min: "1.0", Max: "1.4.2", MaxExcl: true}, {Min: "2.0", Max: "2.1.0"}}
	if len(got) != 1 || got[0].Name != "acme:widget" || len(got[0].Ranges) != 2 || got[0].Ranges[0] != want[0] || got[0].Ranges[1] != want[1] {
		t.Fatalf("affected = %+v", got)
	}
	// One entry the parser cannot read: no ranges at all, never a partial list.
	got = rec(`[{"version":"1.0","status":"affected","lessThan":"1.4.2"},{"version":"main branch","status":"affected"}]`).affected()
	if len(got) != 1 || len(got[0].Ranges) != 0 {
		t.Fatalf("a partly understood list must stay unchecked: %+v", got)
	}
	// git hashes are not versions.
	got = rec(`[{"version":"3f2a9c1","status":"affected","versionType":"git"}]`).affected()
	if len(got[0].Ranges) != 0 {
		t.Fatalf("git versions: %+v", got)
	}
}

func TestCVERejectedRecordsAreSkipped(t *testing.T) {
	var r cveRecord
	jsonUnmarshal(`{"cveMetadata":{"cveId":"CVE-2026-1","state":"REJECTED"},"containers":{"cna":{"title":"x"}}}`, &r)
	if _, ok := r.item("s"); ok {
		t.Error("a rejected record must not become an item")
	}
}

func TestCVERecordURLFollowsTheRepositoryLayout(t *testing.T) {
	dir := mustURL(t, "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/")
	for id, want := range map[string]string{
		"CVE-2026-48356":  "2026/48xxx/CVE-2026-48356.json",
		"CVE-2021-0001":   "2021/0xxx/CVE-2021-0001.json",
		"CVE-2024-1234":   "2024/1xxx/CVE-2024-1234.json",
		"CVE-2019-100000": "2019/100xxx/CVE-2019-100000.json",
	} {
		if got := cveRecordURL(dir, id); got != dir.String()+want {
			t.Errorf("%s -> %s, want %s", id, got, want)
		}
	}
}

func cveSource() model.Source { return model.Source{ID: "cve-records", Type: "cve", URL: cveLogURL} }

func TestCVEFirstRunTakesTheNewestAndKeepsACursor(t *testing.T) {
	g := &cveGetter{
		log: logOf(deltaJSON("2026-10-29T08:00:00.000Z", "CVE-2026-48356"), deltaJSON("2026-10-29T07:55:00.000Z", "CVE-2026-1002")),
		records: map[string]string{recURL("CVE-2026-48356"): adobeRecord,
			recURL("CVE-2026-1002"): `{"cveMetadata":{"cveId":"CVE-2026-1002","state":"PUBLISHED","datePublished":"2026-10-29T07:00:00Z"},"containers":{"cna":{"title":"Other bug","descriptions":[{"lang":"en","value":"d"}]}}}`},
	}
	items, v, err := Fetch(context.Background(), g, cveSource(), model.FeedState{}, now, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].SourceType != "cve" || items[0].IDs[0] != "CVE-2026-1002" {
		t.Fatalf("items = %+v", items)
	}
	if !strings.HasPrefix(v.ETag, "cve:2026-10-29T08:00:00") {
		t.Fatalf("cursor = %q", v.ETag)
	}
	// The record published in July is kept although the window starts later: the cursor decides.
	if items[1].Published.Year() != 2026 || items[1].Published.Month() != time.July {
		t.Fatalf("published = %v", items[1].Published)
	}

	// Next run: nothing newer than the cursor, so no record is requested and the cursor stays.
	g.asked = nil
	items, v2, err := Fetch(context.Background(), g, cveSource(), model.FeedState{Validators: v, LastRun: now}, now, time.Hour)
	if err != nil || len(items) != 0 || v2.ETag != v.ETag {
		t.Fatalf("idle run: %v %v %q", err, items, v2.ETag)
	}
	for _, u := range g.asked {
		if u != cveLogURL {
			t.Errorf("record requested without a new delta: %s", u)
		}
	}
}

func TestCVEContinuesFromTheCursorOldestFirst(t *testing.T) {
	g := &cveGetter{log: logOf(
		deltaJSON("2026-10-29T08:10:00.000Z", "CVE-2026-1013"),
		deltaJSON("2026-10-29T08:05:00.000Z", "CVE-2026-1012"),
		deltaJSON("2026-10-29T08:00:00.000Z", "CVE-2026-1011")), records: map[string]string{}}
	for _, n := range []string{"1011", "1012", "1013"} {
		g.records[recURL("CVE-2026-"+n)] = `{"cveMetadata":{"cveId":"CVE-2026-` + n + `","state":"PUBLISHED"},"containers":{"cna":{"title":"Bug ` + n + `","descriptions":[{"lang":"en","value":"d"}]}}}`
	}
	st := model.FeedState{Validators: model.Validators{ETag: "cve:2026-10-29T08:00:00Z"}, LastRun: now}
	items, v, err := Fetch(context.Background(), g, cveSource(), st, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].IDs[0] != "CVE-2026-1012" || items[1].IDs[0] != "CVE-2026-1013" {
		t.Fatalf("items = %+v", items)
	}
	if !strings.HasPrefix(v.ETag, "cve:2026-10-29T08:10:00") {
		t.Errorf("cursor = %q", v.ETag)
	}
}

func TestCVEGrowsTheRangeUntilItReachesTheCursor(t *testing.T) {
	// Newest first; enough padding deltas that the first megabyte does not reach the cursor.
	var deltas []string
	deltas = append(deltas, deltaJSON("2030-01-01T00:00:00.000Z", "CVE-2026-1090"))
	start := time.Date(2029, 12, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 22000; i++ {
		deltas = append(deltas, deltaJSON(start.Add(-time.Duration(i)*time.Minute).Format("2006-01-02T15:04:05.000Z")))
	}
	g := &cveGetter{log: logOf(deltas...), records: map[string]string{recURL("CVE-2026-1090"): `{"cveMetadata":{"cveId":"CVE-2026-1090","state":"PUBLISHED"},"containers":{"cna":{"title":"Late","descriptions":[{"lang":"en","value":"d"}]}}}`}}
	if len(g.log) < 2<<20 {
		t.Fatalf("log too small for the test: %d", len(g.log))
	}
	cursor := start.Add(-21000 * time.Minute) // deep in the log
	st := model.FeedState{Validators: model.Validators{ETag: cveCursorPrefix + cursor.Format(time.RFC3339Nano)}, LastRun: now}
	items, _, err := Fetch(context.Background(), g, cveSource(), st, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.ranges) < 2 || g.ranges[0] != "bytes=0-1048575" || g.ranges[1] != "bytes=0-2097151" {
		t.Fatalf("ranges asked = %v", g.ranges)
	}
	if len(items) != 1 || items[0].IDs[0] != "CVE-2026-1090" {
		t.Fatalf("items = %+v", items)
	}
}

func TestCVEPlanBudgetNeverSplitsADeltaAndMakesProgress(t *testing.T) {
	mk := func(at string, n, from int) cveDelta {
		d := cveDelta{FetchTime: at, at: parseTime(at)}
		for i := 0; i < n; i++ {
			d.New = append(d.New, struct {
				ID string `json:"cveId"`
			}{fmt.Sprintf("CVE-2026-%d", from+i)})
		}
		return d
	}
	// newest first: 3 deltas of 300 records.
	deltas := []cveDelta{mk("2026-10-29T03:00:00Z", 300, 3000), mk("2026-10-29T02:00:00Z", 300, 2000), mk("2026-10-29T01:00:00Z", 300, 1000)}
	cursor := parseTime("2026-10-29T00:00:00Z")
	ids, next := cvePlan(deltas, cursor)
	if len(ids) != 600 || ids[0] != "CVE-2026-1000" || !next.Equal(parseTime("2026-10-29T02:00:00Z")) {
		t.Fatalf("got %d ids, first %s, cursor %v", len(ids), ids[0], next)
	}
	// A single huge delta is taken whole (up to the cap) so the cursor can pass it.
	ids, next = cvePlan([]cveDelta{mk("2026-10-29T03:00:00Z", 2000, 1000)}, cursor)
	if len(ids) != cveDeltaCap || !next.Equal(parseTime("2026-10-29T03:00:00Z")) {
		t.Fatalf("huge delta: %d ids, cursor %v", len(ids), next)
	}
	// First run: the newest records, newest delta's time as the cursor.
	ids, next = cvePlan(deltas, time.Time{})
	if len(ids) != 300 || !next.Equal(parseTime("2026-10-29T03:00:00Z")) || !slices.Contains(ids, "CVE-2026-3000") || slices.Contains(ids, "CVE-2026-2000") {
		t.Fatalf("first run: %d ids, %v", len(ids), next)
	}
	// Malformed ids are never requested.
	bad := mk("2026-10-29T03:00:00Z", 0, 0)
	bad.New = append(bad.New, struct {
		ID string `json:"cveId"`
	}{"../../etc/passwd"})
	if ids, _ := cvePlan([]cveDelta{bad}, cursor); len(ids) != 0 {
		t.Fatalf("bad id kept: %v", ids)
	}
}

func TestCVEFailuresKeepTheCursorButMissingRecordsAreSkipped(t *testing.T) {
	g := &cveGetter{
		log:     logOf(deltaJSON("2026-10-29T08:00:00.000Z", "CVE-2026-1005", "CVE-2026-1006")),
		records: map[string]string{recURL("CVE-2026-1006"): `{"cveMetadata":{"cveId":"CVE-2026-1006","state":"PUBLISHED"},"containers":{"cna":{"title":"Ok","descriptions":[{"lang":"en","value":"d"}]}}}`},
	}
	// CVE-2026-5 is gone (404): skipped, the rest is kept.
	items, v, err := Fetch(context.Background(), g, cveSource(), model.FeedState{}, now, time.Hour)
	if err != nil || len(items) != 1 || v.ETag == "" {
		t.Fatalf("404: %v %v %q", err, items, v.ETag)
	}
	// A server error ends the run and hands back the old cursor, so it is repeated.
	g.fail = map[string]error{recURL("CVE-2026-1006"): &httpx.StatusError{Code: 503, URL: "x"}}
	old := model.Validators{ETag: "cve:2026-10-29T07:00:00Z"}
	items, v, err = Fetch(context.Background(), g, cveSource(), model.FeedState{Validators: old, LastRun: now}, now, time.Hour)
	if err == nil || len(items) != 0 || v != old {
		t.Fatalf("503: %v %v %+v", err, items, v)
	}
}

func TestCVEConfigurationErrors(t *testing.T) {
	for _, u := range []string{"http://raw.githubusercontent.com/x/deltaLog.json", "https://example.test/feed.xml", ""} {
		src := model.Source{ID: "s", Type: "cve", URL: u}
		if _, _, err := Fetch(context.Background(), &cveGetter{}, src, model.FeedState{}, now, time.Hour); err == nil {
			t.Errorf("url %q accepted", u)
		}
	}
	g := &cveGetter{log: `{"not":"an array"}`}
	if _, _, err := Fetch(context.Background(), g, cveSource(), model.FeedState{}, now, time.Hour); err == nil {
		t.Error("a log that is not an array must be an error")
	}
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCVEProductsSkipPlaceholdersAndRepeatedVendors(t *testing.T) {
	var c cveContainer
	jsonUnmarshal(`{"affected":[{"vendor":"Unknown","product":"LetterPress"},{"vendor":"Adobe","product":"Adobe Commerce"},{"vendor":"Acme","product":"Server"},{"vendor":"n/a","product":"n/a"}]}`, &c)
	got := strings.Join(c.products(), "|")
	if got != "LetterPress|Adobe Commerce|Acme Server" {
		t.Errorf("products = %q", got)
	}
}
