package feeds

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// scriptGetter answers each request with fn and keeps what was asked.
type scriptGetter struct {
	fn    func(u string, prev model.Validators) (*httpx.Response, error)
	asked []string
	prevs []model.Validators
}

func (s *scriptGetter) Get(_ context.Context, u string, prev model.Validators, _ map[string]string) (*httpx.Response, error) {
	s.asked = append(s.asked, u)
	s.prevs = append(s.prevs, prev)
	return s.fn(u, prev)
}

func nvdPage(total, start, count int) *httpx.Response {
	var b strings.Builder
	for i := 0; i < count; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"cve":{"id":"CVE-2026-%04d","published":"2026-01-01T00:00:00.000"}}`, start+i+1)
	}
	return &httpx.Response{Body: []byte(fmt.Sprintf(`{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"vulnerabilities":[%s]}`, count, start, total, b.String()))}
}

const nvdSource = "https://nvd.test/api?pubStartDate={since}&pubEndDate={now}"

func TestNVDWindowsSplitLongSpans(t *testing.T) {
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		days int
		want int
	}{{1, 1}, {119, 1}, {120, 2}, {300, 3}, {1031, 9}} {
		wins := nvdWindows(from, from.AddDate(0, 0, c.days))
		if len(wins) != c.want {
			t.Errorf("%d days: %d windows, want %d", c.days, len(wins), c.want)
		}
		if !wins[0][0].Equal(from) || !wins[len(wins)-1][1].Equal(from.AddDate(0, 0, c.days)) {
			t.Errorf("%d days: windows do not cover the span: %v", c.days, wins)
		}
		for i, w := range wins {
			if w[1].Sub(w[0]) > nvdMaxSpan {
				t.Errorf("%d days: window %d is longer than NVD accepts", c.days, i)
			}
			if i > 0 && !w[0].Equal(wins[i-1][1]) {
				t.Errorf("%d days: gap before window %d", c.days, i)
			}
		}
	}
}

func TestBackfillReachesBackInChunksAndPages(t *testing.T) {
	g := &scriptGetter{fn: func(u string, _ model.Validators) (*httpx.Response, error) {
		switch {
		case strings.Contains(u, "pubStartDate=2025-03-08") && strings.Contains(u, "startIndex=2"):
			return nvdPage(3, 2, 1), nil
		case strings.Contains(u, "pubStartDate=2025-03-08"):
			return nvdPage(3, 0, 2), nil // the first chunk has three results over two pages
		}
		return nvdPage(1, 0, 1), nil
	}}
	var steps [][2]int
	st := model.FeedState{LastRun: now.Add(-time.Hour), Backfill: now.AddDate(0, 0, -300)}
	src := model.Source{ID: "nvd", Type: "nvd", URL: nvdSource}
	out, err := FetchRange(context.Background(), g, src, st, now, 24*time.Hour, func(done, total int) { steps = append(steps, [2]int{done, total}) })
	if err != nil {
		t.Fatal(err)
	}
	if !out.Backfilled || !out.From.Equal(st.Backfill) {
		t.Fatalf("outcome = %+v", out)
	}
	if len(g.asked) != 4 { // chunk 1: two pages, chunks 2 and 3: one each
		t.Fatalf("requests = %v", g.asked)
	}
	if !strings.Contains(g.asked[0], "pubStartDate=2025-03-08") {
		t.Errorf("first chunk starts at the back-fill date: %s", g.asked[0])
	}
	if !strings.HasSuffix(g.asked[1], "&startIndex=2") {
		t.Errorf("second page = %s", g.asked[1])
	}
	if len(out.Items) != 3+1+1 {
		t.Errorf("items = %d", len(out.Items))
	}
	if fmt.Sprint(steps) != "[[1 3] [2 3] [3 3]]" {
		t.Errorf("progress = %v", steps)
	}
	for i, p := range g.prevs {
		if p != (model.Validators{}) {
			t.Errorf("request %d sent validators %+v: a back-fill must not ask for \"unchanged\"", i, p)
		}
	}
}

func TestBackfillIgnoresValidatorsAndSingleWindowKeepsThem(t *testing.T) {
	prev := model.Validators{ETag: "old"}
	notModified := func(string, model.Validators) (*httpx.Response, error) {
		return &httpx.Response{NotModified: true, Validators: prev}, nil
	}
	src := model.Source{ID: "n", Type: "kev", URL: "https://k.test/kev"}

	g := &scriptGetter{fn: notModified}
	if _, err := FetchRange(context.Background(), g, src, model.FeedState{Validators: prev, LastRun: now.Add(-time.Hour)}, now, time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	if g.prevs[0] != prev {
		t.Errorf("a normal fetch is conditional: %+v", g.prevs[0])
	}
	g = &scriptGetter{fn: func(string, model.Validators) (*httpx.Response, error) {
		return &httpx.Response{Body: []byte(`{"vulnerabilities":[]}`)}, nil
	}}
	st := model.FeedState{Validators: prev, LastRun: now.Add(-time.Hour), Backfill: now.AddDate(0, 0, -400)}
	if out, err := FetchRange(context.Background(), g, src, st, now, time.Hour, nil); err != nil || !out.Backfilled || g.prevs[0] != (model.Validators{}) {
		t.Errorf("a back-fill is unconditional: %+v %+v %v", out, g.prevs, err)
	}
	// A backfill that is not earlier than the normal window changes nothing.
	g = &scriptGetter{fn: notModified}
	st = model.FeedState{Validators: prev, LastRun: now.Add(-time.Hour), Backfill: now.Add(-time.Minute)}
	if out, err := FetchRange(context.Background(), g, src, st, now, time.Hour, nil); err != nil || out.Backfilled || g.prevs[0] != prev {
		t.Errorf("a later back-fill date is ignored: %+v %v", out, err)
	}
}

func TestFetchRangeStaysCompatibleWithFetch(t *testing.T) {
	g := body(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","published":"2026-01-02T00:00:00.000"}}]}`)
	items, _, err := Fetch(context.Background(), g, model.Source{ID: "n", Type: "nvd", URL: nvdSource}, model.FeedState{}, now, 24*time.Hour)
	if err != nil || len(items) != 1 || strings.Contains(g.url, "startIndex") {
		t.Fatalf("items=%d url=%s err=%v", len(items), g.url, err)
	}
}

func TestSourcesThatOnlyServeRecentItemsSaySo(t *testing.T) {
	for _, typ := range []string{"rss", "hn"} {
		g := body(emptyFeed[typ])
		out, err := FetchRange(context.Background(), g, model.Source{ID: typ + "-src", Type: typ, URL: "https://x.test/f"},
			model.FeedState{LastRun: now.Add(-time.Hour), Backfill: now.AddDate(-1, 0, 0)}, now, time.Hour, nil)
		if err != nil || !strings.Contains(out.Note, "cannot go back") || !out.Backfilled {
			t.Errorf("%s: %+v %v", typ, out, err)
		}
	}
	g := body(`{"vulnerabilities":[]}`)
	out, _ := FetchRange(context.Background(), g, model.Source{ID: "k", Type: "kev", URL: "https://x.test/f"},
		model.FeedState{LastRun: now.Add(-time.Hour), Backfill: now.AddDate(-1, 0, 0)}, now, time.Hour, nil)
	if out.Note != "" {
		t.Errorf("kev serves its whole list: %q", out.Note)
	}
}

var emptyFeed = map[string]string{
	"rss": `<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>`,
	"hn":  `{"hits":[]}`,
}

func ghsaPage(ids ...string) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf(`{"ghsa_id":"%s","summary":"s %s","published_at":"2026-01-02T00:00:00Z"}`, id, id))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestGHSAFollowsLinkHeader(t *testing.T) {
	g := &scriptGetter{fn: func(u string, _ model.Validators) (*httpx.Response, error) {
		switch {
		case strings.Contains(u, "after=p2"):
			return &httpx.Response{Body: []byte(ghsaPage("GHSA-cccc-2222-3333")), Link: `<https://api.test/advisories?after=p3>; rel="next"`}, nil
		case strings.Contains(u, "after=p3"):
			return &httpx.Response{Body: []byte(ghsaPage("GHSA-dddd-2222-3333"))}, nil
		}
		return &httpx.Response{Body: []byte(ghsaPage("GHSA-aaaa-2222-3333", "GHSA-bbbb-2222-3333")),
			Link:       `<https://api.test/advisories?after=p2>; rel="next", <https://api.test/advisories?after=z>; rel="last"`,
			Validators: model.Validators{ETag: "first"}}, nil
	}}
	var pages []int
	out, err := FetchRange(context.Background(), g, model.Source{ID: "ghsa", Type: "ghsa", URL: "https://api.test/advisories?published=%3E%3D{since_date}"},
		model.FeedState{}, now, 24*time.Hour, func(done, _ int) { pages = append(pages, done) })
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 4 || len(g.asked) != 3 || out.Validators.ETag != "first" || fmt.Sprint(pages) != "[2 3]" {
		t.Fatalf("items=%d asked=%v validators=%+v pages=%v", len(out.Items), g.asked, out.Validators, pages)
	}
}

func TestGHSAStaysOnItsOwnServer(t *testing.T) {
	g := &scriptGetter{fn: func(string, model.Validators) (*httpx.Response, error) {
		return &httpx.Response{Body: []byte(ghsaPage("GHSA-aaaa-2222-3333")), Link: `<https://evil.test/advisories?after=x>; rel="next"`}, nil
	}}
	out, err := FetchRange(context.Background(), g, model.Source{ID: "ghsa", Type: "ghsa", URL: "https://api.test/advisories"}, model.FeedState{}, now, 24*time.Hour, nil)
	if err != nil || len(g.asked) != 1 || len(out.Items) != 1 {
		t.Fatalf("asked=%v items=%d err=%v", g.asked, len(out.Items), err)
	}
}

func TestNextLink(t *testing.T) {
	cases := map[string]string{
		"":                                  "",
		`<https://a.test/?p=2>; rel="next"`: "https://a.test/?p=2",
		`<https://a.test/?p=1>; rel="prev", <https://a.test/?p=3>; rel="next"`: "https://a.test/?p=3",
		`<https://a.test/?p=9>; rel="last"`:                                    "",
	}
	for in, want := range cases {
		if got := nextLink(in); got != want {
			t.Errorf("nextLink(%q) = %q, want %q", in, got, want)
		}
	}
}
