package feeds

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// siteGetter serves canned bodies by URL and records every request.
type siteGetter struct {
	pages map[string]string
	errs  map[string]error
	reqs  []string
}

func (s *siteGetter) Get(_ context.Context, rawURL string, _ model.Validators, _ map[string]string) (*httpx.Response, error) {
	s.reqs = append(s.reqs, rawURL)
	if err := s.errs[rawURL]; err != nil {
		return nil, err
	}
	b, ok := s.pages[rawURL]
	if !ok {
		return nil, errors.New("404")
	}
	return &httpx.Response{Body: []byte(b), Validators: model.Validators{ETag: "csaf"}}, nil
}

const csafHost = "https://psirt.example.com"

func ago(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }

func csafFetch(t *testing.T, g Getter, url string) ([]model.Item, error) {
	t.Helper()
	items, _, err := Fetch(context.Background(), g, model.Source{ID: "vendor", Type: "csaf", URL: url}, model.FeedState{}, now, 30*24*time.Hour)
	return items, err
}

const advConcrete = `{
 "document": {"title": "FortiOS <b>auth</b> bypass", "aggregate_severity": {"text": "Moderate"},
  "notes": [{"category": "legal_disclaimer", "text": "ignore"}, {"category": "summary", "text": "An <i>auth</i> bypass."}],
  "references": [{"category": "external", "url": "https://other.example.org/x"}, {"category": "self", "url": "https://psirt.example.com/adv/fg-1?utm=1#top"}],
  "tracking": {"id": "FG-IR-23-001", "initial_release_date": "%s", "current_release_date": "%s"}},
 "product_tree": {"branches": [{"branches": [{"branches": [
   {"product": {"product_id": "P1", "product_identification_helper": {"cpe": "cpe:2.3:o:fortinet:fortios:7.0.12:*:*:*:*:*:*:*"}}},
   {"product": {"product_id": "P2", "product_identification_helper": {"cpe": "cpe:2.3:o:fortinet:fortios:7.0.13:*:*:*:*:*:*:*"}}},
   {"product": {"product_id": "PF", "product_identification_helper": {"cpe": "cpe:2.3:o:fortinet:fortios:7.0.14:*:*:*:*:*:*:*"}}},
   {"product": {"product_id": "PP", "product_identification_helper": {"purls": ["pkg:deb/x"]}}}
 ]}]}]},
 "vulnerabilities": [{"cve": "CVE-2023-1111",
   "scores": [{"cvss_v3": {"baseScore": 6.5}}, {"cvss_v3": {"baseScore": 9.8}}],
   "product_status": {"known_affected": ["P1", "PP"], "last_affected": ["P2"], "fixed": ["PF"]},
   "remediations": [
     {"category": "vendor_fix", "url": "https://psirt.example.com/fix?x=1", "product_ids": ["P1"]},
     {"category": "workaround", "details": "disable"},
     {"category": "none_available", "url": "https://psirt.example.com/n"}]}]}`

const advWildcard = `{
 "document": {"title": "Widget flaw", "aggregate_severity": {"text": "High"},
  "tracking": {"id": "W-1", "current_release_date": "%s"}},
 "product_tree": {"full_product_names": [{"product_id": "A", "product_identification_helper": {"cpe": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}}]},
 "vulnerabilities": [{"product_status": {"known_affected": ["A", "missing"]}}]}`

func csafSite() *siteGetter {
	recent := ago(2 * time.Hour)
	return &siteGetter{pages: map[string]string{
		csafHost + "/csaf/provider-metadata.json":    `{"distributions": [{"directory_url": "https://psirt.example.com/csaf/advisories/"}]}`,
		csafHost + "/csaf/advisories/changes.csv":    fmt.Sprintf("\"2023/fg-1.json\",\"%s\"\n\"w-1.json\",\"%s\"\n", recent, ago(3*time.Hour)),
		csafHost + "/csaf/advisories/2023/fg-1.json": fmt.Sprintf(advConcrete, recent, recent),
		csafHost + "/csaf/advisories/w-1.json":       fmt.Sprintf(advWildcard, recent),
	}}
}

func TestCSAFProviderMetadata(t *testing.T) {
	g := csafSite()
	items, err := csafFetch(t, g, csafHost+"/csaf/provider-metadata.json")
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	if want := []string{
		csafHost + "/csaf/provider-metadata.json",
		csafHost + "/csaf/advisories/changes.csv",
		csafHost + "/csaf/advisories/2023/fg-1.json",
		csafHost + "/csaf/advisories/w-1.json",
	}; !slices.Equal(g.reqs, want) {
		t.Fatalf("requests = %v", g.reqs)
	}

	a := items[0]
	if a.Title != "FortiOS auth bypass" || a.Summary != "An auth bypass." || a.SourceType != "csaf" || a.SourceID != "vendor" {
		t.Fatalf("item = %+v", a)
	}
	if a.URL != csafHost+"/adv/fg-1" {
		t.Fatalf("url = %q", a.URL)
	}
	if !slices.Equal(a.IDs, []string{"CVE-2023-1111", "FG-IR-23-001"}) {
		t.Fatalf("ids = %v", a.IDs)
	}
	if a.CVSS != 9.8 || a.Severity != model.SevCritical {
		t.Fatalf("cvss=%v sev=%v", a.CVSS, a.Severity)
	}
	if a.Published.IsZero() {
		t.Fatal("no publication date")
	}
	wantAff := []model.Affected{{Ecosystem: model.EcoCPE, Name: "fortinet:fortios", Ranges: []model.Range{
		{Min: "7.0.12", Max: "7.0.12"}, {Min: "7.0.13", Max: "7.0.13"}}}}
	if fmt.Sprint(a.Affected) != fmt.Sprint(wantAff) {
		t.Fatalf("affected = %+v", a.Affected)
	}
	wantFix := []model.Fix{
		{Kind: model.FixVersion, Detail: "7.0.14", URL: csafHost + "/fix", Source: "vendor", Official: true},
		{Kind: model.FixMitigation, URL: csafHost + "/csaf/advisories/2023/fg-1.json", Source: "vendor", Official: true},
	}
	if fmt.Sprint(a.Fixes) != fmt.Sprint(wantFix) {
		t.Fatalf("fixes = %+v", a.Fixes)
	}

	w := items[1]
	if w.Severity != model.SevHigh || w.CVSS != 0 || !slices.Equal(w.IDs, []string{"W-1"}) {
		t.Fatalf("wildcard item = %+v", w)
	}
	if w.URL != csafHost+"/csaf/advisories/w-1.json" || w.Published.IsZero() {
		t.Fatalf("wildcard url/date = %q %v", w.URL, w.Published)
	}
	if len(w.Affected) != 1 || w.Affected[0].Name != "acme:widget" || fmt.Sprint(w.Affected[0].Ranges) != fmt.Sprint([]model.Range{{}}) {
		t.Fatalf("wildcard affected = %+v", w.Affected)
	}
}

func TestCSAFDirectoryAndChangesURL(t *testing.T) {
	for _, u := range []string{csafHost + "/csaf/advisories/", csafHost + "/csaf/advisories/changes.csv"} {
		g := csafSite()
		items, err := csafFetch(t, g, u)
		if err != nil || len(items) != 2 {
			t.Fatalf("%s: items=%d err=%v", u, len(items), err)
		}
		if g.reqs[0] != csafHost+"/csaf/advisories/changes.csv" {
			t.Fatalf("%s: first request %q", u, g.reqs[0])
		}
	}
}

func TestCSAFCapAndSince(t *testing.T) {
	g := &siteGetter{pages: map[string]string{}}
	var csv strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&csv, "\"a%02d.json\",\"%s\"\n", i, ago(time.Duration(i+1)*time.Minute))
		g.pages[fmt.Sprintf("%s/d/a%02d.json", csafHost, i)] = fmt.Sprintf(`{"document":{"title":"t%d","tracking":{"id":"ID-%d","initial_release_date":"%s"}}}`, i, i, ago(time.Hour))
	}
	g.pages[csafHost+"/d/changes.csv"] = csv.String()
	items, err := csafFetch(t, g, csafHost+"/d/")
	if err != nil || len(items) != 60 || len(g.reqs) != 61 {
		t.Fatalf("items=%d requests=%d err=%v", len(items), len(g.reqs), err)
	}
	if g.reqs[1] != csafHost+"/d/a00.json" || g.reqs[60] != csafHost+"/d/a59.json" {
		t.Fatalf("not newest first: %s .. %s", g.reqs[1], g.reqs[60])
	}

	// since: only entries on or after LastRun-24h are fetched.
	g = &siteGetter{pages: map[string]string{
		csafHost + "/d/changes.csv": fmt.Sprintf("\"new.json\",\"%s\"\n\"edge.json\",\"%s\"\n\"old.json\",\"%s\"\n",
			ago(time.Hour), ago(25*time.Hour), ago(27*time.Hour)),
		csafHost + "/d/new.json":  `{"document":{"title":"new"}}`,
		csafHost + "/d/edge.json": `{"document":{"title":"edge"}}`,
		csafHost + "/d/old.json":  `{"document":{"title":"old"}}`,
	}}
	st := model.FeedState{LastRun: now.Add(-30 * time.Hour)} // cutoff 54h back keeps all
	items, _, err = Fetch(context.Background(), g, model.Source{ID: "v", Type: "csaf", URL: csafHost + "/d/"}, st, now, time.Hour)
	if err != nil || len(items) != 3 {
		t.Fatalf("items=%d err=%v reqs=%v", len(items), err, g.reqs)
	}
	st.LastRun = now.Add(-2 * time.Hour)
	g.reqs = nil
	items, _, err = Fetch(context.Background(), g, model.Source{ID: "v", Type: "csaf", URL: csafHost + "/d/"}, st, now, time.Hour)
	if err != nil || len(items) != 2 || slices.Contains(g.reqs, csafHost+"/d/old.json") {
		t.Fatalf("items=%d err=%v reqs=%v", len(items), err, g.reqs)
	}
}

func TestCSAFSkipsBadLinesAndAdvisories(t *testing.T) {
	r := ago(time.Hour)
	g := &siteGetter{
		pages: map[string]string{
			csafHost + "/d/changes.csv": "path,timestamp\n" +
				"garbage line with \"quote\n" +
				"\"nodate.json\",\"not a date\"\n" +
				"\"onlypath.json\"\n" +
				"\"broken.json\",\"" + r + "\"\n" +
				"\"gone.json\",\"" + r + "\"\n" +
				"\"ok.json\",\"" + r + "\"\n",
			csafHost + "/d/broken.json": `{not json`,
			csafHost + "/d/ok.json":     `{"document":{"title":"fine"}}`,
		},
		errs: map[string]error{csafHost + "/d/gone.json": errors.New("boom")},
	}
	items, err := csafFetch(t, g, csafHost+"/d/")
	if err != nil || len(items) != 1 || items[0].Title != "fine" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if len(items[0].Affected) != 0 || items[0].Severity != model.SevUnknown {
		t.Fatalf("item = %+v", items[0])
	}
}

func TestCSAFRefusesOtherHosts(t *testing.T) {
	g := &siteGetter{pages: map[string]string{
		csafHost + "/provider-metadata.json": `{"distributions": [{"directory_url": "https://evil.example.net/d/"}]}`,
	}}
	if _, err := csafFetch(t, g, csafHost+"/provider-metadata.json"); err == nil {
		t.Fatal("cross-host directory_url accepted")
	}
	if len(g.reqs) != 1 {
		t.Fatalf("requests = %v", g.reqs)
	}

	r := ago(time.Hour)
	g = &siteGetter{pages: map[string]string{
		csafHost + "/d/changes.csv": "\"https://evil.example.net/x.json\",\"" + r + "\"\n\"//evil.example.net/y.json\",\"" + r + "\"\n\"a.json\",\"" + r + "\"\n",
		csafHost + "/d/a.json": `{"document":{"title":"a","references":[{"category":"self","url":"https://evil.example.net/a"}]},
		  "product_tree":{"full_product_names":[{"product_id":"P","product_identification_helper":{"cpe":"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}}]},
		  "vulnerabilities":[{"product_status":{"known_affected":["P"],"fixed":["P"]},"remediations":[
		   {"category":"vendor_fix","url":"https://evil.example.net/fix","product_ids":["P"]},
		   {"category":"mitigation","url":"http://psirt.example.com/plain"}]}]}`,
	}}
	items, err := csafFetch(t, g, csafHost+"/d/")
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	for _, u := range g.reqs {
		if !strings.HasPrefix(u, csafHost+"/") {
			t.Fatalf("request left the host: %s", u)
		}
	}
	adv := csafHost + "/d/a.json"
	if items[0].URL != adv {
		t.Fatalf("url = %q", items[0].URL)
	}
	for _, f := range items[0].Fixes {
		if f.URL != adv {
			t.Fatalf("fix url = %q", f.URL)
		}
	}
	if len(items[0].Fixes) != 2 || items[0].Fixes[0].Detail != "1.0" {
		t.Fatalf("fixes = %+v", items[0].Fixes)
	}

	// Only https on the source host is accepted as a source URL.
	if _, err := csafFetch(t, g, "http://psirt.example.com/d/"); err == nil {
		t.Fatal("http source accepted")
	}
}

func TestCSAFStripsQueryFromLinks(t *testing.T) {
	r := ago(time.Hour)
	g := &siteGetter{pages: map[string]string{
		csafHost + "/d/changes.csv": "\"a.json?token=1#x\",\"" + r + "\"\n",
		csafHost + "/d/a.json":      `{"document":{"title":"a"},"vulnerabilities":[{"remediations":[{"category":"mitigation","url":"https://psirt.example.com/m?a=1#b"}]}]}`,
	}}
	items, err := csafFetch(t, g, csafHost+"/d/")
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%d err=%v reqs=%v", len(items), err, g.reqs)
	}
	if items[0].URL != csafHost+"/d/a.json" || items[0].Fixes[0].URL != csafHost+"/m" {
		t.Fatalf("url=%q fixes=%+v", items[0].URL, items[0].Fixes)
	}
}

func TestCSAFIndexFailure(t *testing.T) {
	boom := errors.New("boom")
	for _, u := range []string{csafHost + "/d/", csafHost + "/p/provider-metadata.json"} {
		g := &siteGetter{errs: map[string]error{csafHost + "/d/changes.csv": boom, csafHost + "/p/provider-metadata.json": boom}}
		_, v, err := Fetch(context.Background(), g, model.Source{ID: "v", Type: "csaf", URL: u}, model.FeedState{Validators: model.Validators{ETag: "old"}}, now, time.Hour)
		if err == nil || !errors.Is(err, boom) || v.ETag != "old" {
			t.Fatalf("%s: err=%v validators=%+v", u, err, v)
		}
	}
	g := &siteGetter{pages: map[string]string{csafHost + "/p/provider-metadata.json": `nope`}}
	if _, err := csafFetch(t, g, csafHost+"/p/provider-metadata.json"); err == nil {
		t.Fatal("bad provider metadata accepted")
	}
}

func TestTypesListBothKinds(t *testing.T) {
	ts := Types()
	if !slices.Contains(ts, "csaf") || !slices.Contains(ts, "rss") || !slices.IsSorted(ts) {
		t.Fatalf("types = %v", ts)
	}
}
