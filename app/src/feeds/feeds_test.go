package feeds

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// fakeGetter returns a canned response and records the request it saw.
type fakeGetter struct {
	resp    *httpx.Response
	err     error
	url     string
	prev    model.Validators
	headers map[string]string
}

func (f *fakeGetter) Get(_ context.Context, rawURL string, prev model.Validators, headers map[string]string) (*httpx.Response, error) {
	f.url, f.prev, f.headers = rawURL, prev, headers
	return f.resp, f.err
}

func body(s string) *fakeGetter {
	return &fakeGetter{resp: &httpx.Response{Body: []byte(s), Validators: model.Validators{ETag: "new"}}}
}

var now = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func fetch(t *testing.T, g Getter, typ string, st model.FeedState) []model.Item {
	t.Helper()
	items, _, err := Fetch(context.Background(), g, model.Source{ID: "src", Type: typ, URL: "https://x.test/f"}, st, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestFetchUnknownType(t *testing.T) {
	_, _, err := Fetch(context.Background(), body(""), model.Source{ID: "s", Type: "nope"}, model.FeedState{}, now, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchNotModified(t *testing.T) {
	prev := model.Validators{ETag: "old"}
	g := &fakeGetter{resp: &httpx.Response{NotModified: true, Validators: prev}}
	items, v, err := Fetch(context.Background(), g, model.Source{ID: "s", Type: "rss", URL: "https://x.test"}, model.FeedState{Validators: prev}, now, time.Hour)
	if err != nil || items != nil || v != prev {
		t.Fatalf("items=%v validators=%v err=%v", items, v, err)
	}
	if g.prev != prev {
		t.Fatalf("previous validators not sent: %+v", g.prev)
	}
}

func TestFetchReturnsNewValidators(t *testing.T) {
	_, v, err := Fetch(context.Background(), body(`<rss/>`), model.Source{ID: "s", Type: "rss", URL: "https://x.test"}, model.FeedState{}, now, time.Hour)
	if err != nil || v.ETag != "new" {
		t.Fatalf("validators=%+v err=%v", v, err)
	}
}

func TestFetchErrors(t *testing.T) {
	boom := errors.New("boom")
	_, _, err := Fetch(context.Background(), &fakeGetter{err: boom}, model.Source{ID: "s", Type: "kev", URL: "u"}, model.FeedState{}, now, time.Hour)
	if !errors.Is(err, boom) {
		t.Fatalf("download error not wrapped: %v", err)
	}
	_, _, err = Fetch(context.Background(), body("not json"), model.Source{ID: "s", Type: "kev", URL: "u"}, model.FeedState{}, now, time.Hour)
	if err == nil {
		t.Fatal("bad json accepted")
	}
	_, _, err = Fetch(context.Background(), body("<html><body>hi</body></html>"), model.Source{ID: "s", Type: "rss", URL: "u"}, model.FeedState{}, now, time.Hour)
	if err == nil {
		t.Fatal("non-feed xml accepted")
	}
}

func TestPlaceholders(t *testing.T) {
	last := time.Date(2025, 12, 31, 23, 0, 0, 0, time.FixedZone("x", 3600)) // 22:00 UTC
	cases := []struct {
		typ, url string
		st       model.FeedState
		want     string
	}{
		{"rss", "https://x/?a={since}&u={since_unix}&d={since_date}&n={now}", model.FeedState{LastRun: last},
			"https://x/?a=2025-12-31T22:00:00Z&u=1767218400&d=2025-12-31&n=2026-01-02T03:04:05Z"},
		{"hn", "https://x/?f=created_at_i>{since_unix}", model.FeedState{},
			"https://x/?f=created_at_i>1767236645"}, // now - 24h
		{"nvd", "https://x/?s={since}&e={now}", model.FeedState{LastRun: last},
			"https://x/?s=2025-12-31T22:00:00.000&e=2026-01-02T03:04:05.000"},
	}
	for _, tc := range cases {
		g := body(`{}`)
		src := model.Source{ID: "s", Type: tc.typ, URL: tc.url}
		if _, _, err := Fetch(context.Background(), g, src, tc.st, now, 24*time.Hour); err != nil && tc.typ != "rss" {
			t.Fatal(err)
		}
		if g.url != tc.want {
			t.Errorf("%s: url = %s\n want %s", tc.typ, g.url, tc.want)
		}
	}
}

func TestAcceptHeaders(t *testing.T) {
	g := body(`{}`)
	src := model.Source{ID: "s", Type: "ghsa", URL: "u", Headers: map[string]string{"authorization": "Bearer t", "accept": "text/custom"}}
	Fetch(context.Background(), g, src, model.FeedState{}, now, time.Hour)
	want := map[string]string{"Accept": "text/custom", "Authorization": "Bearer t"}
	if !reflect.DeepEqual(g.headers, want) {
		t.Fatalf("headers = %v, want %v", g.headers, want)
	}

	g = body(`{}`)
	Fetch(context.Background(), g, model.Source{ID: "s", Type: "nvd", URL: "u"}, model.FeedState{}, now, time.Hour)
	if g.headers["Accept"] != "application/json" {
		t.Fatalf("default Accept = %q", g.headers["Accept"])
	}
}

const rssFixture = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel><title>Blog</title>
<item>
  <title>Symfony fixes CVE-2025-1111 &amp; friends</title>
  <link> https://blog.test/a </link>
  <description><![CDATA[<p>Details for <b>cve-2025-2222</b> and&nbsp;CVE-2025-1111.</p><script>x()</script>]]></description>
  <pubDate>Tue, 30 Dec 2025 10:00:00 +0100</pubDate>
</item>
<item>
  <title>Body only</title>
  <guid>https://blog.test/b</guid>
  <content:encoded>&lt;p&gt;Only &amp;amp; encoded&lt;/p&gt;</content:encoded>
  <pubDate>Tue, 30 Dec 2025 10:00:00 GMT</pubDate>
</item>
<item><title>  </title><link>https://blog.test/empty</link></item>
</channel></rss>`

func TestRSS(t *testing.T) {
	items := fetch(t, body(rssFixture), "rss", model.FeedState{})
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (empty title skipped)", len(items))
	}
	a := items[0]
	if a.SourceID != "src" || a.URL != "https://blog.test/a" || a.Title != "Symfony fixes CVE-2025-1111 & friends" {
		t.Errorf("item a = %+v", a)
	}
	if a.Summary != "Details for cve-2025-2222 and CVE-2025-1111." {
		t.Errorf("summary = %q", a.Summary)
	}
	if want := []string{"CVE-2025-1111", "CVE-2025-2222"}; !reflect.DeepEqual(a.IDs, want) {
		t.Errorf("ids = %v, want %v", a.IDs, want)
	}
	if want := time.Date(2025, 12, 30, 9, 0, 0, 0, time.UTC); !a.Published.Equal(want) {
		t.Errorf("published = %v", a.Published)
	}
	if a.Severity != model.SevUnknown {
		t.Errorf("severity = %v", a.Severity)
	}
	b := items[1]
	if b.URL != "https://blog.test/b" || b.Summary != "Only & encoded" {
		t.Errorf("item b = %+v", b)
	}
}

func TestAtom(t *testing.T) {
	const atom = `<?xml version="1.0" encoding="ISO-8859-1"?>
<feed xmlns="http://www.w3.org/2005/Atom">
 <entry>
  <title type="html">&lt;b&gt;Patch&lt;/b&gt; for GHSA-cfgh-2345-wxqr caf` + "\xe9" + `</title>
  <link rel="self" href="https://a.test/self"/>
  <link rel="alternate" href="https://a.test/post"/>
  <summary>Short summary</summary>
  <content>Long content</content>
  <updated>2025-12-31T08:30:00Z</updated>
 </entry>
</feed>`
	items := fetch(t, body(atom), "rss", model.FeedState{})
	if len(items) != 1 {
		t.Fatalf("got %d items", len(items))
	}
	it := items[0]
	if it.Title != "Patch for GHSA-cfgh-2345-wxqr café" || it.URL != "https://a.test/post" || it.Summary != "Short summary" {
		t.Errorf("item = %+v", it)
	}
	if !reflect.DeepEqual(it.IDs, []string{"GHSA-CFGH-2345-WXQR"}) {
		t.Errorf("ids = %v", it.IDs)
	}
	if !it.Published.Equal(time.Date(2025, 12, 31, 8, 30, 0, 0, time.UTC)) {
		t.Errorf("published = %v", it.Published)
	}
}

func TestHN(t *testing.T) {
	const fixture = `{"hits":[
	 {"objectID":"1","title":"CVE-2025-3333 exploited in the wild","url":"https://ex.test/p","story_text":null,"created_at_i":1767225600},
	 {"objectID":"2","title":"Ask HN: patching","url":null,"story_text":"<p>We saw CVE-2025-4444</p>","created_at_i":1767225700},
	 {"objectID":"3","title":"","url":"https://ex.test/none","created_at_i":1}
	]}`
	items := fetch(t, body(fixture), "hn", model.FeedState{})
	if len(items) != 2 {
		t.Fatalf("got %d items", len(items))
	}
	if items[0].URL != "https://ex.test/p" || !reflect.DeepEqual(items[0].IDs, []string{"CVE-2025-3333"}) {
		t.Errorf("item 0 = %+v", items[0])
	}
	if items[1].URL != "https://news.ycombinator.com/item?id=2" || items[1].Summary != "We saw CVE-2025-4444" {
		t.Errorf("item 1 = %+v", items[1])
	}
	if !items[0].Published.Equal(time.Unix(1767225600, 0)) {
		t.Errorf("published = %v", items[0].Published)
	}
	if !reflect.DeepEqual(items[1].IDs, []string{"CVE-2025-4444"}) {
		t.Errorf("ids = %v", items[1].IDs)
	}
}

func TestNVD(t *testing.T) {
	const fixture = `{"vulnerabilities":[
	 {"cve":{"id":"CVE-2025-5555","published":"2025-12-30T10:15:00.123",
	   "descriptions":[{"lang":"es","value":"Hola."},{"lang":"en","value":"Buffer overflow in Foo 1.2. Allows remote code execution."}],
	   "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}},
	 {"cve":{"id":"CVE-2025-6666","published":"2025-12-31T00:00:00.000",
	   "descriptions":[{"lang":"en","value":"Only v4 here"}],
	   "metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}},
	 {"cve":{"id":"CVE-2025-7777","descriptions":[{"lang":"en","value":"Old v3.0."}],
	   "metrics":{"cvssMetricV30":[{"cvssData":{"baseScore":5.0}}]}}},
	 {"cve":{"id":"CVE-2025-8888","descriptions":[]}}
	]}`
	items := fetch(t, body(fixture), "nvd", model.FeedState{})
	if len(items) != 4 {
		t.Fatalf("got %d items", len(items))
	}
	a := items[0]
	if a.Title != "CVE-2025-5555: Buffer overflow in Foo 1.2." || a.URL != "https://nvd.nist.gov/vuln/detail/CVE-2025-5555" {
		t.Errorf("item a = %+v", a)
	}
	if a.Summary != "Buffer overflow in Foo 1.2. Allows remote code execution." || a.Severity != model.SevCritical || a.CVSS != 9.8 {
		t.Errorf("item a = %+v", a)
	}
	if !reflect.DeepEqual(a.IDs, []string{"CVE-2025-5555"}) {
		t.Errorf("ids = %v", a.IDs)
	}
	if want := time.Date(2025, 12, 30, 10, 15, 0, 123_000_000, time.UTC); !a.Published.Equal(want) {
		t.Errorf("published = %v", a.Published)
	}
	if items[1].Severity != model.SevHigh || items[1].CVSS != 7.5 {
		t.Errorf("v4 fallback failed: %+v", items[1])
	}
	if items[2].Severity != model.SevMedium {
		t.Errorf("severity from score failed: %+v", items[2])
	}
	if items[3].Title != "CVE-2025-8888" || items[3].Severity != model.SevUnknown {
		t.Errorf("item d = %+v", items[3])
	}
}

func TestKEV(t *testing.T) {
	const fixture = `{"vulnerabilities":[
	 {"cveID":"CVE-2025-0001","vendorProject":"Acme","product":"Gate","vulnerabilityName":"Acme Gate RCE","shortDescription":"Lets attackers <b>run</b> code.","dateAdded":"2025-12-30"},
	 {"cveID":"CVE-2025-0002","vendorProject":"Old","product":"Thing","vulnerabilityName":"Old bug","shortDescription":"Old.","dateAdded":"2025-12-29"},
	 {"cveID":"CVE-2025-0003","vendorProject":"Odd","product":"Date","vulnerabilityName":"Bad date","shortDescription":"x","dateAdded":"soon"}
	]}`
	last := time.Date(2025, 12, 30, 18, 0, 0, 0, time.UTC) // same day as the first entry
	items := fetch(t, body(fixture), "kev", model.FeedState{LastRun: last})
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2: %+v", len(items), items)
	}
	a := items[0]
	if a.Title != "Acme Gate: Acme Gate RCE" || a.URL != "https://nvd.nist.gov/vuln/detail/CVE-2025-0001" {
		t.Errorf("item a = %+v", a)
	}
	if a.Summary != "Actively exploited (CISA KEV). Lets attackers run code." || a.Severity != model.SevHigh {
		t.Errorf("item a = %+v", a)
	}
	if !reflect.DeepEqual(a.IDs, []string{"CVE-2025-0001"}) || !a.Published.Equal(time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("item a = %+v", a)
	}
	if items[1].IDs[0] != "CVE-2025-0003" {
		t.Errorf("entry with bad date should be kept: %+v", items[1])
	}
}

func TestGHSA(t *testing.T) {
	const fixture = `[
	 {"ghsa_id":"GHSA-cfgh-2345-wxqr","cve_id":"CVE-2025-9999","summary":"RCE in http-kernel","description":"Fixes <i>also</i> CVE-2025-1234.",
	  "severity":"high","html_url":"https://github.com/advisories/GHSA-cfgh-2345-wxqr","published_at":"2025-12-30T12:00:00Z",
	  "cvss":{"score":8.1},
	  "vulnerabilities":[
	   {"package":{"ecosystem":"composer","name":"Symfony/HTTP-Kernel"},"vulnerable_version_range":">= 6.0, < 6.4.2","first_patched_version":"6.4.2"},
	   {"package":{"ecosystem":"Composer","name":"symfony/http-kernel"},"vulnerable_version_range":"< 5.4.30","first_patched_version":{"identifier":"5.4.30"}},
	   {"package":null},
	   {"package":{"ecosystem":"composer","name":"symfony/http-foundation"},"vulnerable_version_range":"not a range","first_patched_version":null}]},
	 {"ghsa_id":"GHSA-cccc-2222-3333","cve_id":null,"summary":"Prototype pollution","description":"",
	  "severity":"unknown","html_url":"https://github.com/advisories/GHSA-cccc-2222-3333","published_at":"2025-12-31T12:00:00Z",
	  "cvss":{"score":9.3},"vulnerabilities":[{"package":{"ecosystem":"npm","name":"lodash"},"vulnerable_version_range":"< 4.17.21"}]}
	]`
	items := fetch(t, body(fixture), "ghsa", model.FeedState{})
	if len(items) != 2 {
		t.Fatalf("got %d items", len(items))
	}
	a := items[0]
	if want := []string{"CVE-2025-9999", "CVE-2025-1234", "GHSA-CFGH-2345-WXQR"}; !reflect.DeepEqual(a.IDs, want) {
		t.Errorf("ids = %v, want %v", a.IDs, want)
	}
	wantAff := []model.Affected{
		{Ecosystem: "composer", Name: "symfony/http-kernel", Fixed: "6.4.2", Ranges: []model.Range{{Min: "6.0", Max: "6.4.2", MaxExcl: true}, {Max: "5.4.30", MaxExcl: true}}},
		{Ecosystem: "composer", Name: "symfony/http-foundation"},
	}
	if !reflect.DeepEqual(a.Affected, wantAff) {
		t.Errorf("affected = %+v, want %+v", a.Affected, wantAff)
	}
	wantFix := []model.Fix{
		{Kind: model.FixVersion, Detail: "6.4.2", URL: a.URL, Source: "src", Official: true},
		{Kind: model.FixVersion, Detail: "5.4.30", URL: a.URL, Source: "src", Official: true},
	}
	if !reflect.DeepEqual(a.Fixes, wantFix) {
		t.Errorf("fixes = %+v, want %+v", a.Fixes, wantFix)
	}
	if a.Severity != model.SevHigh || a.CVSS != 8.1 || a.Summary != "Fixes also CVE-2025-1234." || a.Title != "RCE in http-kernel" {
		t.Errorf("item a = %+v", a)
	}
	b := items[1]
	if !reflect.DeepEqual(b.IDs, []string{"GHSA-CCCC-2222-3333"}) || b.Severity != model.SevCritical || b.Summary != "Prototype pollution" {
		t.Errorf("item b = %+v", b)
	}
	if want := []model.Affected{{Ecosystem: "npm", Name: "lodash", Ranges: []model.Range{{Max: "4.17.21", MaxExcl: true}}}}; !reflect.DeepEqual(b.Affected, want) {
		t.Errorf("affected = %+v", b.Affected)
	}
	if b.Fixes != nil {
		t.Errorf("fixes = %+v, want none", b.Fixes)
	}
}

func TestPlainAndTruncate(t *testing.T) {
	if got := plain("a &lt;b&gt;x&lt;/b&gt; <!-- c --> 1 < 2\n\n  &amp;  <style>p{}</style>z"); got != "a x 1 < 2 & z" {
		t.Errorf("plain = %q", got)
	}
	long := strings.Repeat("é", 3000)
	it, ok := finish("s", model.Item{Title: "t", Summary: long})
	if !ok || len([]rune(it.Summary)) != maxText || !strings.HasSuffix(it.Summary, "…") {
		t.Errorf("summary runes = %d", len([]rune(it.Summary)))
	}
}

func TestParseTimeLayouts(t *testing.T) {
	want := time.Date(2025, 12, 30, 9, 0, 0, 0, time.UTC)
	for _, s := range []string{
		"Tue, 30 Dec 2025 10:00:00 +0100",
		"Tue, 30 Dec 2025 09:00:00 GMT",
		"Tue, 30 Dec 2025 09:00:00 +0000",
		"Tue, 30 Dec 2025 09:00 +0000",
		"30 Dec 2025 09:00:00 +0000",
		"2025-12-30T09:00:00Z",
		"2025-12-30T10:00:00.000+01:00",
		"2025-12-30T09:00:00",
		"2025-12-30 09:00:00",
	} {
		if got := parseTime(s); !got.Equal(want) {
			t.Errorf("parseTime(%q) = %v", s, got)
		}
	}
	if !parseTime("garbage").IsZero() {
		t.Error("garbage should give the zero time")
	}
}

func TestRecentDropsOldKeepsUndated(t *testing.T) {
	since := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	items := []model.Item{
		{Title: "old", Published: since.AddDate(0, 0, -30)},
		{Title: "lagging", Published: since.Add(-time.Hour)},
		{Title: "undated"},
	}
	got := recent(items, since)
	if len(got) != 2 || got[0].Title != "lagging" || got[1].Title != "undated" {
		t.Fatalf("got %+v", got)
	}
}

func TestPlainDropsEscapesAndBidiTricks(t *testing.T) {
	got := plain("Bug \x1b[31mred\x1b[0m \u202eevil\u202c in <b>PHP</b>\x07")
	if got != "Bug [31mred[0m evil in PHP" {
		t.Fatalf("got %q", got)
	}
}

func TestSourceTypeSet(t *testing.T) {
	for typ, fixture := range map[string]string{
		"kev":  `{"vulnerabilities":[{"cveID":"CVE-2025-0001","vendorProject":"A","product":"B","vulnerabilityName":"C","dateAdded":"2026-01-01"}]}`,
		"nvd":  `{"vulnerabilities":[{"cve":{"id":"CVE-2025-0002"}}]}`,
		"ghsa": `[{"ghsa_id":"GHSA-cfgh-2345-wxqr","summary":"s"}]`,
		"hn":   `{"hits":[{"objectID":"1","title":"t","url":"https://ex.test","created_at_i":1767225600}]}`,
	} {
		items := fetch(t, body(fixture), typ, model.FeedState{})
		if len(items) != 1 || items[0].SourceType != typ {
			t.Errorf("%s: items = %+v", typ, items)
		}
	}
}

func TestNVDAffectedAndFixes(t *testing.T) {
	const fixture = `{"vulnerabilities":[{"cve":{"id":"CVE-2025-1000","descriptions":[{"lang":"en","value":"Bug."}],
	 "configurations":[{"nodes":[{"cpeMatch":[
	  {"vulnerable":true,"criteria":"cpe:2.3:a:Example:Widget:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"1.4.2"},
	  {"vulnerable":true,"criteria":"cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*","versionStartExcluding":"2.0","versionEndIncluding":"2.1"},
	  {"vulnerable":true,"criteria":"cpe:2.3:a:example:gadget:3.1:*:*:*:*:*:*:*"},
	  {"vulnerable":true,"criteria":"cpe:2.3:a:example:everything:*:*:*:*:*:*:*:*"},
	  {"vulnerable":true,"criteria":"cpe:2.3:a:example:na:-:*:*:*:*:*:*:*"},
	  {"vulnerable":true,"criteria":"cpe:2.3:a:ex\\:corp:wid\\-get:1\\.0:*:*:*:*:*:*:*"},
	  {"vulnerable":false,"criteria":"cpe:2.3:o:example:os:*:*:*:*:*:*:*:*"},
	  {"vulnerable":true,"criteria":"cpe:2.3:a:short"}
	 ]}]}],
	 "references":[
	  {"url":"https://ex.test/patch","source":"s","tags":["Patch","Vendor Advisory","Third Party Advisory"]},
	  {"url":"https://ex.test/patch","source":"s","tags":["Patch"]},
	  {"url":"http://ex.test/mit","tags":["Mitigation"]},
	  {"url":"javascript:alert(1)","tags":["Patch"]},
	  {"url":"ftp://ex.test/x","tags":["Patch"]},
	  {"url":"https://ex.test/none","tags":["Exploit"]}
	 ]}}]}`
	items := fetch(t, body(fixture), "nvd", model.FeedState{})
	if len(items) != 1 {
		t.Fatalf("got %d items", len(items))
	}
	it := items[0]
	want := []model.Affected{
		{Ecosystem: "cpe", Name: "example:widget", Ranges: []model.Range{
			{Min: "1.0", Max: "1.4.2", MaxExcl: true},
			{Min: "2.0", MinExcl: true, Max: "2.1"},
		}},
		{Ecosystem: "cpe", Name: "example:gadget", Ranges: []model.Range{{Min: "3.1", Max: "3.1"}}},
		{Ecosystem: "cpe", Name: "example:everything", Ranges: []model.Range{{}}},
		{Ecosystem: "cpe", Name: "example:na", Ranges: []model.Range{{}}},
		{Ecosystem: "cpe", Name: "ex:corp:wid-get", Ranges: []model.Range{{Min: "1.0", Max: "1.0"}}},
	}
	if !reflect.DeepEqual(it.Affected, want) {
		t.Errorf("affected = %+v\nwant %+v", it.Affected, want)
	}
	wantFix := []model.Fix{
		{Kind: model.FixPatch, URL: "https://ex.test/patch", Source: "src"},
		{Kind: model.FixAdvisory, URL: "https://ex.test/patch", Source: "src", Official: true},
		{Kind: model.FixMitigation, URL: "http://ex.test/mit", Source: "src"},
	}
	if !reflect.DeepEqual(it.Fixes, wantFix) {
		t.Errorf("fixes = %+v\nwant %+v", it.Fixes, wantFix)
	}
}

func TestNVDCaps(t *testing.T) {
	var cpes, refs []string
	for i := 0; i < 60; i++ {
		cpes = append(cpes, fmt.Sprintf(`{"vulnerable":true,"criteria":"cpe:2.3:a:v:p%d:*:*:*:*:*:*:*:*"}`, i))
		refs = append(refs, fmt.Sprintf(`{"url":"https://ex.test/%d","tags":["Patch"]}`, i))
	}
	fixture := `{"vulnerabilities":[{"cve":{"id":"CVE-2025-2000","configurations":[{"nodes":[{"cpeMatch":[` +
		strings.Join(cpes, ",") + `]}]}],"references":[` + strings.Join(refs, ",") + `]}}]}`
	it := fetch(t, body(fixture), "nvd", model.FeedState{})[0]
	if len(it.Affected) != 50 || len(it.Fixes) != 20 {
		t.Fatalf("affected = %d, fixes = %d", len(it.Affected), len(it.Fixes))
	}
}

func TestKEVFixAndRansomware(t *testing.T) {
	long := strings.Repeat("é", 300)
	fixture := `{"vulnerabilities":[
	 {"cveID":"CVE-2025-0010","vendorProject":"Acme","product":"Gate","vulnerabilityName":"RCE","shortDescription":"Bad.","dateAdded":"2025-12-30",
	  "requiredAction":"Apply <b>updates</b> per vendor instructions.","knownRansomwareCampaignUse":"Known"},
	 {"cveID":"CVE-2025-0011","vendorProject":"Acme","product":"Door","vulnerabilityName":"XSS","shortDescription":"Bad.","dateAdded":"2025-12-30",
	  "requiredAction":"","knownRansomwareCampaignUse":"Unknown"},
	 {"cveID":"CVE-2025-0012","vendorProject":"Acme","product":"Lock","vulnerabilityName":"Long","shortDescription":"Bad.","dateAdded":"2025-12-30",
	  "requiredAction":"` + long + `"}
	]}`
	items := fetch(t, body(fixture), "kev", model.FeedState{})
	if len(items) != 3 {
		t.Fatalf("got %d items", len(items))
	}
	a := items[0]
	wantFix := []model.Fix{{Kind: model.FixAction, Detail: "Apply updates per vendor instructions.", URL: a.URL, Source: "src", Official: true}}
	if !reflect.DeepEqual(a.Fixes, wantFix) {
		t.Errorf("fixes = %+v", a.Fixes)
	}
	if a.Summary != "Actively exploited (CISA KEV). Bad. Known ransomware use." {
		t.Errorf("summary = %q", a.Summary)
	}
	if items[1].Fixes != nil || strings.Contains(items[1].Summary, "ransomware") {
		t.Errorf("item b = %+v", items[1])
	}
	if n := len([]rune(items[2].Fixes[0].Detail)); n != 200 {
		t.Errorf("action runes = %d, want 200", n)
	}
}

func TestKEVFieldsReachTheItem(t *testing.T) {
	fixture := `{"vulnerabilities":[{"cveID":"CVE-2025-0001","vendorProject":"Acme","product":"Widget","vulnerabilityName":"Widget RCE",
	"shortDescription":"Bad.","dateAdded":"2025-12-30","dueDate":"2026-01-20","requiredAction":"Apply updates per vendor instructions.","knownRansomwareCampaignUse":"Known"}]}`
	items := fetch(t, body(fixture), "kev", model.FeedState{})
	if len(items) != 1 || items[0].KEV == nil {
		t.Fatalf("items: %+v", items)
	}
	k := items[0].KEV
	if !k.Ransomware || k.Action != "Apply updates per vendor instructions." ||
		!k.DueDate.Equal(time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)) || !k.DateAdded.Equal(time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("kev: %+v", k)
	}
}
