package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

const (
	// nvdMaxSpan stays under the 120 consecutive days NVD accepts per query.
	nvdMaxSpan = 119 * 24 * time.Hour
	// maxPages bounds the pages followed for one window, so a server that
	// keeps answering "more" cannot hold a cycle forever.
	maxPages = 300
)

// fetchPages downloads a parser source from since to now. NVD windows longer
// than the API allows are cut into chunks and every answer is paged through;
// GitHub answers are followed along their Link header. A source that is not
// paged takes one request.
func fetchPages(ctx context.Context, g Getter, src model.Source, p parser, prev model.Validators, since, now time.Time, progress func(done, total int)) (items []model.Item, valids model.Validators, notModified bool, resume time.Time, err error) {
	headers := mergeHeaders(p.accept, src.Headers)
	note := func(done, total int) {
		if progress != nil {
			progress(done, total)
		}
	}
	parse := func(body []byte) error {
		its, err := p.parse(body, src, since)
		if err != nil {
			return fmt.Errorf("parse %s: %w", src.Type, err)
		}
		items = append(items, its...)
		return nil
	}

	switch src.Type {
	case "nvd":
		wins := nvdWindows(since, now)
		for i, w := range wins {
			u, v := expand(src, w[0], w[1]), model.Validators{}
			if len(wins) == 1 {
				v = prev
			}
			mark := len(items)
			// A window that fails keeps the ones before it: the next run resumes at its start.
			partial := func(err error) ([]model.Item, model.Validators, bool, time.Time, error) {
				if i == 0 {
					return nil, prev, false, time.Time{}, err
				}
				return items[:mark], prev, false, w[0], err
			}
			for start, page := 0, 0; page < maxPages; page++ {
				resp, err := g.Get(ctx, withStartIndex(u, start), v, headers)
				if err != nil {
					return partial(err)
				}
				if resp.NotModified {
					return nil, prev, true, time.Time{}, nil
				}
				if err := parse(resp.Body); err != nil {
					return partial(err)
				}
				if len(wins) == 1 && page == 0 {
					valids = resp.Validators
				}
				next, more := nvdNext(resp.Body, start)
				if !more {
					break
				}
				start, v = next, model.Validators{}
			}
			if len(wins) > 1 {
				note(i+1, len(wins))
			}
		}
		return items, valids, false, time.Time{}, nil

	case "ghsa":
		first := expand(src, since, now)
		resp, err := g.Get(ctx, first, prev, headers)
		if err != nil {
			return nil, prev, false, time.Time{}, err
		}
		if resp.NotModified {
			return nil, prev, true, time.Time{}, nil
		}
		valids = resp.Validators
		if err := parse(resp.Body); err != nil {
			return nil, prev, false, time.Time{}, err
		}
		for page := 1; page < maxPages; page++ {
			next := nextLink(resp.Link)
			if next == "" || !sameServer(next, first) {
				break
			}
			if resp, err = g.Get(ctx, next, model.Validators{}, headers); err != nil {
				return nil, prev, false, time.Time{}, err
			}
			if err := parse(resp.Body); err != nil {
				return nil, prev, false, time.Time{}, err
			}
			note(page+1, 0)
		}
		return items, valids, false, time.Time{}, nil
	}

	resp, err := g.Get(ctx, expand(src, since, now), prev, headers)
	if err != nil {
		return nil, prev, false, time.Time{}, err
	}
	if resp.NotModified {
		return nil, prev, true, time.Time{}, nil
	}
	if err := parse(resp.Body); err != nil {
		return nil, prev, false, time.Time{}, err
	}
	return items, resp.Validators, false, time.Time{}, nil
}

// nvdWindows cuts from..to into spans NVD accepts. A span that is empty or
// reversed stays one window, as a single request.
func nvdWindows(from, to time.Time) [][2]time.Time {
	var out [][2]time.Time
	for start := from; ; {
		end := start.Add(nvdMaxSpan)
		if !end.Before(to) {
			return append(out, [2]time.Time{start, to})
		}
		out = append(out, [2]time.Time{start, end})
		start = end
	}
}

// nvdNext reads how many results a page held and says where the next page
// starts, if the answer announces more than has been read.
func nvdNext(body []byte, start int) (next int, more bool) {
	var r struct {
		TotalResults    int               `json:"totalResults"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Vulnerabilities) == 0 {
		return 0, false
	}
	next = start + len(r.Vulnerabilities)
	return next, next < r.TotalResults
}

// withStartIndex asks for a later page; the first page keeps the URL as configured.
func withStartIndex(raw string, start int) string {
	if start == 0 {
		return raw
	}
	sep := "&"
	if !strings.Contains(raw, "?") {
		sep = "?"
	}
	return raw + sep + "startIndex=" + strconv.Itoa(start)
}

// nextLink returns the rel="next" target of a Link header, or "".
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		return strings.Trim(strings.TrimSpace(target), "<>")
	}
	return ""
}

// sameServer keeps a paged answer from sending the client to another server.
func sameServer(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	return ea == nil && eb == nil && ua.Host != "" && strings.EqualFold(ua.Host, ub.Host)
}
