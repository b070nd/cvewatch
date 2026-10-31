package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// The cve source reads the CVE Program's own records (the cvelistV5
// repository), which every CVE-issuing vendor writes itself: Adobe, Cisco,
// Microsoft, Oracle and hundreds more. A record appears here when the vendor
// publishes it, before NVD adds its analysis.
//
// deltaLog.json lists, newest first, every change in five-minute steps. It is
// about 35 MB, so only the head is requested (a Range request) and the range
// grows until it reaches the last change already handled. Records are then
// fetched one by one, oldest first. The place reached is kept as an opaque
// cursor, so a failed or interrupted run repeats instead of losing records.
const (
	cveCursorPrefix = "cve:"
	cveFirstRange   = 1 << 20  // bytes of the delta log requested first
	cveMaxRange     = 12 << 20 // most bytes requested; older changes are lost
	cveBudget       = 500      // records fetched per run; a delta is never split
	cveFirstRun     = 100      // newest records taken when there is no cursor
	cveDeltaCap     = 1500     // records taken from one delta
	cveMaxAffected  = 5        // products named in a title
)

var cveID = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,})$`)

// cveDelta is one entry of deltaLog.json. Only new records are used: a record
// is fetched once, when it is first published.
type cveDelta struct {
	FetchTime string `json:"fetchTime"`
	New       []struct {
		ID string `json:"cveId"`
	} `json:"new"`
	at time.Time
}

func fetchCVE(ctx context.Context, g Getter, src model.Source, st model.FeedState, _ time.Time) ([]model.Item, model.Validators, error) {
	base, err := url.Parse(strings.TrimSpace(src.URL))
	if err != nil || base.Host == "" || !strings.EqualFold(base.Scheme, "https") || path.Base(base.Path) != "deltaLog.json" {
		return nil, st.Validators, errors.New("cve: url must be the https address of cvelistV5 cves/deltaLog.json")
	}
	dir := cleanURL(base)
	dir.Path = path.Dir(base.Path) + "/"
	headers := mergeHeaders(acceptJSON, src.Headers)

	cursor := cveCursor(st.Validators.ETag)
	deltas, err := cveDeltas(ctx, g, base, headers, cursor)
	if err != nil {
		return nil, st.Validators, err
	}
	ids, next := cvePlan(deltas, cursor)
	if !next.After(cursor) {
		return nil, st.Validators, nil // nothing new since the last run
	}

	var items []model.Item
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, st.Validators, err
		}
		it, ok, err := fetchCVERecord(ctx, g, src.ID, dir, id, headers)
		if err != nil {
			return nil, st.Validators, err // keep the cursor: the whole window is repeated
		}
		if ok {
			items = append(items, it)
		}
	}
	return items, model.Validators{ETag: cveCursorPrefix + next.UTC().Format(time.RFC3339Nano)}, nil
}

func cveCursor(s string) time.Time {
	if rest, ok := strings.CutPrefix(s, cveCursorPrefix); ok {
		return parseTime(rest)
	}
	return time.Time{}
}

// cveDeltas returns the deltas newer than cursor, newest first. It asks for a
// growing head of the log until it holds a delta at or before cursor (or the
// whole log, or the size limit). Hitting the limit leaves a gap; NVD and the
// other sources cover what a week-long outage missed.
func cveDeltas(ctx context.Context, g Getter, logURL *url.URL, headers map[string]string, cursor time.Time) ([]cveDelta, error) {
	for size := cveFirstRange; ; size *= 2 {
		size = min(size, cveMaxRange)
		h := maps.Clone(headers)
		h["Range"] = "bytes=0-" + strconv.Itoa(size-1)
		resp, err := g.Get(ctx, logURL.String(), model.Validators{}, h)
		if err != nil {
			return nil, fmt.Errorf("delta log: %w", err)
		}
		whole := len(resp.Body) < size // a shorter answer is the complete file
		deltas, covered, err := parseCVEDeltas(resp.Body, cursor, whole)
		if err != nil {
			return nil, fmt.Errorf("delta log: %w", err)
		}
		if covered || whole || size >= cveMaxRange {
			return deltas, nil
		}
	}
}

// parseCVEDeltas reads the JSON array from the front. A body cut off by the
// range ends in half an entry, which is ignored. covered says that an entry at
// or before cursor was seen, so nothing newer can be missing.
func parseCVEDeltas(body []byte, cursor time.Time, whole bool) (deltas []cveDelta, covered bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, false, errors.New("not a JSON array")
	}
	for dec.More() {
		var d cveDelta
		if err := dec.Decode(&d); err != nil {
			if whole {
				return nil, false, fmt.Errorf("decode json: %w", err)
			}
			return deltas, false, nil // cut off by the range
		}
		if d.at = parseTime(d.FetchTime); d.at.IsZero() {
			continue
		}
		if !d.at.After(cursor) {
			return deltas, true, nil
		}
		deltas = append(deltas, d)
	}
	return deltas, whole, nil
}

// cvePlan picks the record ids to fetch and the cursor to store afterwards.
// With no cursor it takes the newest cveFirstRun records. Otherwise it goes
// oldest first and stops after the delta that fills the budget, so the rest
// follows on the next run.
func cvePlan(deltas []cveDelta, cursor time.Time) (ids []string, next time.Time) {
	next = cursor
	if len(deltas) == 0 {
		return nil, next
	}
	seen := map[string]bool{}
	take := func(d cveDelta) {
		for i, n := range d.New {
			if i >= cveDeltaCap {
				break
			}
			if cveID.MatchString(n.ID) && !seen[n.ID] {
				seen[n.ID] = true
				ids = append(ids, n.ID)
			}
		}
	}
	if cursor.IsZero() {
		next = deltas[0].at // deltas are newest first
		for _, d := range deltas {
			if len(ids) >= cveFirstRun {
				break
			}
			take(d)
		}
		slices.Reverse(ids)
		return ids, next
	}
	for i := len(deltas) - 1; i >= 0 && len(ids) < cveBudget; i-- {
		take(deltas[i])
		next = deltas[i].at
	}
	return ids, next
}

// cveRecordURL is where a record lives: cves/<year>/<number/1000>xxx/<id>.json.
// It is built from the id, never taken from the log, so every request stays
// under the directory of the configured URL.
func cveRecordURL(dir *url.URL, id string) string {
	m := cveID.FindStringSubmatch(id)
	n, _ := strconv.Atoi(m[2])
	return dir.JoinPath(m[1], strconv.Itoa(n/1000)+"xxx", id+".json").String()
}

// fetchCVERecord downloads and reads one record. A record that is gone (404,
// rejected and removed) is skipped; any other failure ends the run.
func fetchCVERecord(ctx context.Context, g Getter, srcID string, dir *url.URL, id string, headers map[string]string) (model.Item, bool, error) {
	resp, err := g.Get(ctx, cveRecordURL(dir, id), model.Validators{}, headers)
	if err != nil {
		var se *httpx.StatusError
		if errors.As(err, &se) && (se.Code == 404 || se.Code == 410) {
			return model.Item{}, false, nil
		}
		return model.Item{}, false, fmt.Errorf("%s: %w", id, err)
	}
	var rec cveRecord
	if err := json.Unmarshal(resp.Body, &rec); err != nil {
		return model.Item{}, false, nil // one unreadable record must not block the rest
	}
	it, ok := rec.item(srcID)
	return it, ok, nil
}

// cveRecord is the part of a CVE JSON 5 record we use.
type cveRecord struct {
	Meta struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cveContainer   `json:"cna"`
		ADP []cveContainer `json:"adp"`
	} `json:"containers"`
}

type cveContainer struct {
	Title        string `json:"title"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Affected   []cveAffected `json:"affected"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Metrics []struct {
		V31 *cveScore `json:"cvssV3_1"`
		V40 *cveScore `json:"cvssV4_0"`
		V30 *cveScore `json:"cvssV3_0"`
		V20 *cveScore `json:"cvssV2_0"`
	} `json:"metrics"`
}

type cveScore struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cveAffected struct {
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	CPEs     []string `json:"cpes"`
	Versions []struct {
		Version         string `json:"version"`
		Status          string `json:"status"`
		LessThan        string `json:"lessThan"`
		LessThanOrEqual string `json:"lessThanOrEqual"`
		VersionType     string `json:"versionType"`
	} `json:"versions"`
}

func (r cveRecord) item(srcID string) (model.Item, bool) {
	id := strings.ToUpper(strings.TrimSpace(r.Meta.ID))
	if !cveID.MatchString(id) || !strings.EqualFold(r.Meta.State, "PUBLISHED") {
		return model.Item{}, false
	}
	cna := r.Containers.CNA
	desc := cna.description()
	products := cna.products()
	title := cna.Title
	if title == "" {
		title = firstSentence(plain(desc))
	}
	// Titles name the flaw, not always every product, and tech matching on
	// titles is what keeps feeds like this quiet: name the missing products.
	var missing []string
	for _, p := range products {
		if !strings.Contains(strings.ToLower(title), strings.ToLower(p)) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		title = strings.Join(missing, ", ") + " - " + title
	}
	summary := desc
	if len(products) > 0 {
		summary += "\nAffected: " + strings.Join(products, ", ")
	}
	it := model.Item{
		Title:     id + ": " + title,
		URL:       "https://www.cve.org/CVERecord?id=" + id,
		Summary:   summary,
		Affected:  r.affected(),
		Fixes:     r.fixes(srcID),
		Published: parseTime(r.Meta.Published),
	}
	rt, label := r.rating()
	rate(&it, rt, label)
	return finish(srcID, it, id)
}

func (c cveContainer) description() string {
	for _, d := range c.Descriptions {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			return d.Value
		}
	}
	return ""
}

// products lists "Vendor Product" for the affected entries, without repeats.
func (c cveContainer) products() []string {
	var out []string
	for _, a := range c.Affected {
		vendor, product := strings.TrimSpace(a.Vendor), strings.TrimSpace(a.Product)
		p := product
		if !placeholder(vendor) && !strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
			p = strings.TrimSpace(vendor + " " + product) // "Adobe Commerce" stays, "Server" becomes "Acme Server"
		}
		if p != "" && !placeholder(p) && !slices.Contains(out, p) && len(out) < cveMaxAffected {
			out = append(out, p)
		}
	}
	return out
}

// placeholder reports the values CNAs write when they do not know the vendor
// or product.
func placeholder(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "unknown", "n/a", "na", "none", "unspecified", "-":
		return true
	}
	return false
}

// affected keeps products that carry CPE names, as NVD data does. Vendors
// without CPEs write free text ("2.4.9, 2.4.8-p5, ..."), which is not turned
// into ranges: those findings stay unchecked for a person to confirm.
func (r cveRecord) affected() []model.Affected {
	var list []model.Affected
	for _, c := range append([]cveContainer{r.Containers.CNA}, r.Containers.ADP...) {
		for _, a := range c.Affected {
			ranges, clean := a.ranges()
			for _, cpe := range a.CPEs {
				name, ver, ok := cpeProduct(cpe)
				if !ok {
					continue
				}
				e := model.Affected{Ecosystem: "cpe", Name: name}
				switch {
				case clean:
					e.Ranges = ranges
				case ver != "":
					e.Ranges = []model.Range{{Min: ver, Max: ver}}
				}
				if len(list) < maxAffected || slices.ContainsFunc(list, func(x model.Affected) bool { return x.Name == name }) {
					list = addAffected(list, e)
				}
			}
		}
	}
	return list
}

var cleanVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~_-]*$`)

// ranges turns the affected versions of one product into ranges. It gives up
// (clean false) when any affected entry is not a plain version, so a partly
// understood list can never claim that a version is safe.
func (a cveAffected) ranges() (out []model.Range, clean bool) {
	for _, v := range a.Versions {
		if !strings.EqualFold(v.Status, "affected") {
			continue
		}
		if t := strings.ToLower(v.VersionType); t != "" && t != "semver" && t != "custom" {
			return nil, false
		}
		var r model.Range
		switch {
		case v.LessThan != "" || v.LessThanOrEqual != "":
			top, excl := v.LessThanOrEqual, false
			if v.LessThan != "" {
				top, excl = v.LessThan, true
			}
			if !cleanVersion.MatchString(top) {
				return nil, false
			}
			r.Max, r.MaxExcl = top, excl
			if v.Version != "" && v.Version != "0" {
				if !cleanVersion.MatchString(v.Version) {
					return nil, false
				}
				r.Min = v.Version
			}
		case cleanVersion.MatchString(v.Version):
			r.Min, r.Max = v.Version, v.Version
		default:
			return nil, false
		}
		out = append(out, r)
	}
	return out, len(out) > 0
}

// fixes turns tagged references into fixes, as the NVD parser does.
func (r cveRecord) fixes(srcID string) []model.Fix {
	var out []model.Fix
	for _, c := range append([]cveContainer{r.Containers.CNA}, r.Containers.ADP...) {
		for _, ref := range c.References {
			u, err := url.Parse(strings.TrimSpace(ref.URL))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			for _, tag := range ref.Tags {
				f := model.Fix{URL: u.String(), Source: srcID}
				switch strings.ToLower(tag) {
				case "patch":
					f.Kind = model.FixPatch
				case "vendor-advisory":
					f.Kind, f.Official = model.FixAdvisory, true
				case "mitigation":
					f.Kind = model.FixMitigation
				default:
					continue
				}
				if len(out) < maxFixes && !slices.ContainsFunc(out, func(e model.Fix) bool { return e.Kind == f.Kind && e.URL == f.URL }) {
					out = append(out, f)
				}
			}
		}
	}
	return out
}
