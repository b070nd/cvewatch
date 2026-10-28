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

// Types lists the source types Fetch understands, sorted, so config and
// doctor can validate them without a request.
func Types() []string {
	out := make([]string, 0, len(parsers))
	for t := range parsers {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// Fetch downloads src and returns its new items and the validators to store.
// The window starts at st.LastRun, or at now-lookback on the first run.
// On NotModified it returns no items and the previous validators; on error
// it also returns the previous validators, so callers can keep them.
//
// URL placeholders: {since} (RFC3339 UTC; NVD format for type nvd),
// {since_unix}, {since_date} (YYYY-MM-DD) and {now} (same format as {since}).
func Fetch(ctx context.Context, g Getter, src model.Source, st model.FeedState, now time.Time, lookback time.Duration) ([]model.Item, model.Validators, error) {
	p, ok := parsers[src.Type]
	if !ok {
		return nil, st.Validators, fmt.Errorf("feeds: source %q: unknown type %q", src.ID, src.Type)
	}
	since := st.LastRun
	if since.IsZero() {
		since = now.Add(-lookback)
	}
	resp, err := g.Get(ctx, expand(src, since, now), st.Validators, mergeHeaders(p.accept, src.Headers))
	if err != nil {
		return nil, st.Validators, fmt.Errorf("feeds: source %q: %w", src.ID, err)
	}
	if resp.NotModified {
		return nil, st.Validators, nil
	}
	items, err := p.parse(resp.Body, src, since)
	if err != nil {
		return nil, st.Validators, fmt.Errorf("feeds: source %q: parse %s: %w", src.ID, src.Type, err)
	}
	items = recent(items, since)
	for i := range items {
		items[i].SourceType = src.Type
		items[i].TitleOnly = src.MatchTitleOnly
		items[i].StructuredOnly = src.MatchStructured
	}
	return items, resp.Validators, nil
}

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
