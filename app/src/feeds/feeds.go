// Package feeds downloads a source and turns it into normalized items.
// Each source type has its own parser; Fetch picks the right one.
package feeds

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Getter is the part of httpx.Client that Fetch needs.
type Getter interface {
	Get(ctx context.Context, rawURL string, prev model.Validators, headers map[string]string) (*httpx.Response, error)
}

// parseFunc turns a response body into items. since is the start of the
// polling window; only some parsers use it.
type parseFunc func(body []byte, src model.Source, since time.Time) ([]model.Item, error)

// fetchFunc is the second kind of adapter, for sources that need several
// requests (an index, then one document per entry). It does its own
// downloading; Fetch stamps and filters what it returns like any other.
type fetchFunc func(ctx context.Context, g Getter, src model.Source, st model.FeedState, since time.Time) ([]model.Item, model.Validators, error)

type parser struct {
	parse  parseFunc
	accept string // default Accept header
}

const (
	acceptJSON = "application/json"
	nvdLayout  = "2006-01-02T15:04:05.000" // NVD wants UTC without a zone suffix
)

var parsers = map[string]parser{
	"rss":  {parseRSS, "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5"},
	"hn":   {parseHN, acceptJSON},
	"nvd":  {parseNVD, acceptJSON},
	"kev":  {parseKEV, acceptJSON},
	"ghsa": {parseGHSA, "application/vnd.github+json"},
}

// fetchers is consulted before parsers.
var fetchers = map[string]fetchFunc{
	"csaf": fetchCSAF,
	"cve":  fetchCVE,
}

// Types lists the source types Fetch understands, sorted, so config and
// doctor can validate them without a request.
func Types() []string {
	out := make([]string, 0, len(parsers)+len(fetchers))
	for t := range parsers {
		out = append(out, t)
	}
	for t := range fetchers {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// Fetch downloads src and returns its new items and the validators to store.
// The window starts at st.LastRun, or at now-lookback on the first run, or at
// st.Backfill when that reaches further back.
// On NotModified it returns no items and the previous validators; on error
// it also returns the previous validators, so callers can keep them.
//
// URL placeholders: {since} (RFC3339 UTC; NVD format for type nvd),
// {since_unix}, {since_date} (YYYY-MM-DD) and {now} (same format as {since}).
func Fetch(ctx context.Context, g Getter, src model.Source, st model.FeedState, now time.Time, lookback time.Duration) ([]model.Item, model.Validators, error) {
	o, err := FetchRange(ctx, g, src, st, now, lookback, nil)
	return o.Items, o.Validators, err
}

// Outcome is what a fetch returned and which part of history it asked for.
type Outcome struct {
	Items      []model.Item
	Validators model.Validators
	From       time.Time // start of the window that was asked for
	Backfilled bool      // the window reached back further than usual for a pending back-fill
	Note       string    // informational: what the source could not serve
}

// FetchRange is Fetch that also says what window it covered. progress, which
// may be nil, is told after each finished chunk of a long window or page of a
// paged answer; total is 0 when the number of pages is not known.
func FetchRange(ctx context.Context, g Getter, src model.Source, st model.FeedState, now time.Time, lookback time.Duration, progress func(done, total int)) (Outcome, error) {
	out := Outcome{Validators: st.Validators}
	f, isFetcher := fetchers[src.Type]
	p, isParser := parsers[src.Type]
	if !isFetcher && !isParser {
		return out, fmt.Errorf("feeds: source %q: unknown type %q", src.ID, src.Type)
	}
	since := st.LastRun
	if since.IsZero() {
		since = now.Add(-lookback)
	}
	prev := st.Validators
	if !st.Backfill.IsZero() && st.Backfill.Before(since) {
		since, prev, out.Backfilled = st.Backfill, model.Validators{}, true // a conditional GET would answer "unchanged"
	}
	out.From = since
	var (
		items  []model.Item
		valids model.Validators
	)
	if isFetcher {
		var err error
		items, valids, err = f(ctx, g, src, st, since)
		if err != nil {
			return out, fmt.Errorf("feeds: source %q: %w", src.ID, err)
		}
	} else {
		var notModified bool
		var err error
		items, valids, notModified, err = fetchPages(ctx, g, src, p, prev, since, now, progress)
		if err != nil {
			return out, fmt.Errorf("feeds: source %q: %w", src.ID, err)
		}
		if notModified {
			return out, nil
		}
	}
	if src.Type != "cve" { // its cursor, not the date, decides what is new
		items = recent(items, since)
	}
	for i := range items {
		items[i].SourceType = src.Type
		items[i].TitleOnly = src.MatchTitleOnly
		items[i].StructuredOnly = src.MatchStructured
	}
	if out.Backfilled && slices.Contains(recentOnly, src.Type) {
		out.Note = "cannot go back: only serves recent items"
	}
	out.Items, out.Validators = items, valids
	return out, nil
}

// recentOnly are the source types that cannot serve items older than a feed's
// own depth, whatever window is asked for.
var recentOnly = []string{"rss", "hn", "cve"}

// feedLag is how far before the window an item may be dated and still count,
// since feeds can publish entries late. Repeats are removed by deduplication.
const feedLag = 24 * time.Hour

// recent drops dated items older than the window: full-history feeds such
// as RSS would otherwise flood the first run. Undated items are kept.
func recent(items []model.Item, since time.Time) []model.Item {
	cutoff := since.Add(-feedLag)
	out := items[:0]
	for _, it := range items {
		if it.Published.IsZero() || !it.Published.Before(cutoff) {
			out = append(out, it)
		}
	}
	return out
}

// expand fills the time placeholders in the source URL.
func expand(src model.Source, since, now time.Time) string {
	layout := time.RFC3339
	if src.Type == "nvd" {
		layout = nvdLayout
	}
	since, now = since.UTC(), now.UTC()
	return strings.NewReplacer(
		"{since}", since.Format(layout),
		"{since_unix}", strconv.FormatInt(since.Unix(), 10),
		"{since_date}", since.Format(time.DateOnly),
		"{now}", now.Format(layout),
	).Replace(src.URL)
}

// mergeHeaders combines the default Accept header with the source headers.
// Source headers win; names are compared case-insensitively.
func mergeHeaders(accept string, user map[string]string) map[string]string {
	out := map[string]string{"Accept": accept}
	for k, v := range user {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}
