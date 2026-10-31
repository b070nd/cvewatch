package feeds

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

const maxCSAFAdvisories = 60 // advisory files requested per run

// csafDoc is the part of a CSAF 2.0 advisory we use.
type csafDoc struct {
	Document struct {
		Title             string `json:"title"`
		AggregateSeverity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
		References []struct {
			Category string `json:"category"`
			URL      string `json:"url"`
		} `json:"references"`
		Tracking struct {
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches         []csafBranch  `json:"branches"`
		FullProductNames []csafProduct `json:"full_product_names"`
		Relationships    []struct {
			FullProductName csafProduct `json:"full_product_name"`
		} `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []csafVuln `json:"vulnerabilities"`
}

type csafBranch struct {
	Branches []csafBranch `json:"branches"`
	Product  *csafProduct `json:"product"`
}

type csafProduct struct {
	ID     string `json:"product_id"`
	Helper struct {
		CPE string `json:"cpe"`
	} `json:"product_identification_helper"`
}

type csafScore struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type csafVuln struct {
	CVE    string `json:"cve"`
	Scores []struct {
		CVSSv2 csafScore `json:"cvss_v2"`
		CVSSv3 csafScore `json:"cvss_v3"`
		CVSSv4 csafScore `json:"cvss_v4"`
	} `json:"scores"`
	ProductStatus struct {
		KnownAffected []string `json:"known_affected"`
		FirstAffected []string `json:"first_affected"`
		LastAffected  []string `json:"last_affected"`
		Fixed         []string `json:"fixed"`
	} `json:"product_status"`
	Remediations []struct {
		Category   string   `json:"category"`
		URL        string   `json:"url"`
		ProductIDs []string `json:"product_ids"`
	} `json:"remediations"`
}

// fetchCSAF reads a CSAF 2.0 provider: the index (changes.csv, found through
// provider-metadata.json when needed), then one advisory file per entry in
// the window. Every request stays on the host of src.URL.
func fetchCSAF(ctx context.Context, g Getter, src model.Source, st model.FeedState, since time.Time) ([]model.Item, model.Validators, error) {
	base, err := url.Parse(strings.TrimSpace(src.URL))
	if err != nil || base.Host == "" || !strings.EqualFold(base.Scheme, "https") {
		return nil, st.Validators, errors.New("csaf: url must be an https URL")
	}
	headers := mergeHeaders(acceptJSON, src.Headers)

	var dir, index *url.URL
	switch {
	case strings.HasSuffix(base.Path, "/changes.csv"):
		index = cleanURL(base)
		d := *index
		d.Path, d.RawPath = strings.TrimSuffix(d.Path, "changes.csv"), ""
		dir = &d
	case strings.HasSuffix(base.Path, "/"):
		dir = cleanURL(base)
	default:
		resp, err := g.Get(ctx, base.String(), model.Validators{}, headers)
		if err != nil {
			return nil, st.Validators, fmt.Errorf("provider metadata: %w", err)
		}
		var meta struct {
			Distributions []struct {
				DirectoryURL string `json:"directory_url"`
			} `json:"distributions"`
		}
		if err := json.Unmarshal(resp.Body, &meta); err != nil {
			return nil, st.Validators, fmt.Errorf("provider metadata: decode json: %w", err)
		}
		if len(meta.Distributions) == 0 {
			return nil, st.Validators, errors.New("provider metadata: no distributions")
		}
		d, ok := sameHost(base, meta.Distributions[0].DirectoryURL)
		if !ok {
			return nil, st.Validators, errors.New("provider metadata: directory_url is missing or not on the provider host")
		}
		dir = d
		dir.Path = strings.TrimSuffix(dir.Path, "/") + "/"
	}
	if index == nil {
		index = dir.JoinPath("changes.csv")
	}

	resp, err := g.Get(ctx, index.String(), st.Validators, headers)
	if err != nil {
		return nil, st.Validators, fmt.Errorf("changes.csv: %w", err)
	}
	if resp.NotModified {
		return nil, st.Validators, nil
	}

	var items []model.Item
	for _, e := range csafEntries(resp.Body, since.Add(-feedLag)) {
		if err := ctx.Err(); err != nil {
			return nil, st.Validators, err
		}
		ref, err := url.Parse(e.path)
		if err != nil || ref.IsAbs() || ref.Host != "" {
			continue
		}
		advURL, ok := sameHost(base, dir.ResolveReference(ref).String())
		if !ok {
			continue
		}
		r, err := g.Get(ctx, advURL.String(), model.Validators{}, headers)
		if err != nil {
			continue
		}
		var doc csafDoc
		if json.Unmarshal(r.Body, &doc) != nil {
			continue
		}
		if it, ok := doc.item(src.ID, base, advURL.String()); ok {
			items = append(items, it)
		}
	}
	return items, resp.Validators, nil
}

type csafEntry struct {
	path string
	at   time.Time
}

// csafEntries reads changes.csv lines such as
// "2023/cisco-sa-abc.json","2023-10-01T12:00:00Z". Entries older than cutoff
// and malformed lines (a header counts as one) are dropped; the newest
// maxCSAFAdvisories are returned, newest first.
func csafEntries(data []byte, cutoff time.Time) []csafEntry {
	var out []csafEntry
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		r := csv.NewReader(strings.NewReader(line))
		r.FieldsPerRecord = -1
		rec, err := r.Read()
		if err != nil || len(rec) < 2 {
			continue
		}
		p, at := strings.TrimSpace(rec[0]), parseTime(rec[1])
		if p == "" || at.IsZero() || at.Before(cutoff) {
			continue
		}
		out = append(out, csafEntry{p, at})
	}
	slices.SortStableFunc(out, func(a, b csafEntry) int { return b.at.Compare(a.at) })
	if len(out) > maxCSAFAdvisories {
		out = out[:maxCSAFAdvisories]
	}
	return out
}

// sameHost parses raw and returns it without query and fragment when it is
// an https URL on the host of base.
func sameHost(base *url.URL, raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil || !strings.EqualFold(u.Host, base.Host) {
		return nil, false
	}
	return cleanURL(u), true
}

func cleanURL(u *url.URL) *url.URL {
	c := *u
	c.RawQuery, c.Fragment, c.RawFragment, c.ForceQuery = "", "", "", false
	return &c
}

// item turns one advisory into an item. advURL is the advisory file's own URL.
func (d csafDoc) item(srcID string, base *url.URL, advURL string) (model.Item, bool) {
	link := advURL
	for _, ref := range d.Document.References {
		if ref.Category != "self" {
			continue
		}
		if u, ok := sameHost(base, ref.URL); ok {
			link = u.String()
			break
		}
	}

	var ids []string
	var rs []model.Rating
	for _, v := range d.Vulnerabilities {
		ids = append(ids, v.CVE)
		for _, s := range v.Scores {
			for _, c := range []struct {
				s   csafScore
				ver string
			}{{s.CVSSv4, model.CVSS40}, {s.CVSSv3, model.CVSS30}, {s.CVSSv2, model.CVSS20}} {
				rs = append(rs, ratingOf(c.s.BaseScore, c.s.Version, c.s.VectorString, model.ScoreCSAF, c.ver))
			}
		}
	}
	ids = append(ids, d.Document.Tracking.ID)

	published := parseTime(d.Document.Tracking.InitialReleaseDate)
	if published.IsZero() {
		published = parseTime(d.Document.Tracking.CurrentReleaseDate)
	}

	it := model.Item{
		Title:     d.Document.Title,
		URL:       link,
		Summary:   d.summary(),
		Affected:  d.affected(),
		Fixes:     d.fixes(srcID, base, advURL),
		Published: published,
	}
	r := model.BestRating(rs...)
	label := d.Document.AggregateSeverity.Text
	if r.Valid() {
		label = "" // the score decides, the document's label only fills in when there is none
	}
	rate(&it, r, label)
	return finish(srcID, it, ids...)
}

func (d csafDoc) summary() string {
	for _, n := range d.Document.Notes {
		if n.Category == "summary" || n.Category == "description" {
			return n.Text
		}
	}
	return ""
}

// products maps product ids to their products, walking the branches.
func (d csafDoc) products() map[string]csafProduct {
	m := map[string]csafProduct{}
	add := func(p csafProduct) {
		if p.ID != "" {
			m[p.ID] = p
		}
	}
	var walk func([]csafBranch)
	walk = func(bs []csafBranch) {
		for _, b := range bs {
			if b.Product != nil {
				add(*b.Product)
			}
			walk(b.Branches)
		}
	}
	walk(d.ProductTree.Branches)
	for _, p := range d.ProductTree.FullProductNames {
		add(p)
	}
	for _, r := range d.ProductTree.Relationships {
		add(r.FullProductName)
	}
	return m
}

// csafCPE reads a CPE 2.3 string; other forms (CPE 2.2, purls) are ignored.
func csafCPE(p csafProduct) (name, ver string, ok bool) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.Helper.CPE)), "cpe:2.3:") {
		return "", "", false
	}
	return cpeProduct(p.Helper.CPE)
}

// affected lists the products named in known_affected, first_affected and
// last_affected, merged by vendor:product.
func (d csafDoc) affected() []model.Affected {
	prods := d.products()
	var list []model.Affected
	for _, v := range d.Vulnerabilities {
		for _, id := range slices.Concat(v.ProductStatus.KnownAffected, v.ProductStatus.FirstAffected, v.ProductStatus.LastAffected) {
			name, ver, ok := csafCPE(prods[id])
			if !ok {
				continue
			}
			if len(list) >= maxAffected && !slices.ContainsFunc(list, func(e model.Affected) bool { return e.Name == name }) {
				continue
			}
			list = addAffected(list, model.Affected{Ecosystem: model.EcoCPE, Name: name, Ranges: []model.Range{{Min: ver, Max: ver}}})
		}
	}
	return list
}

// fixes turns vendor_fix, mitigation and workaround remediations into fixes.
func (d csafDoc) fixes(srcID string, base *url.URL, advURL string) []model.Fix {
	prods := d.products()
	var out []model.Fix
	for _, v := range d.Vulnerabilities {
		for _, r := range v.Remediations {
			f := model.Fix{Source: srcID, Official: true, URL: advURL}
			if u, ok := sameHost(base, r.URL); ok {
				f.URL = u.String()
			}
			switch r.Category {
			case "vendor_fix":
				if strings.TrimSpace(r.URL) == "" {
					continue
				}
				f.Kind, f.Detail = model.FixVersion, fixedVersion(v, r.ProductIDs, prods)
			case "mitigation", "workaround":
				f.Kind = model.FixMitigation
			default:
				continue
			}
			if len(out) < maxFixes && !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	return out
}

// fixedVersion is the version of the first fixed product with a concrete CPE
// version, preferring products the remediation itself lists.
func fixedVersion(v csafVuln, remediated []string, prods map[string]csafProduct) string {
	fixed := v.ProductStatus.Fixed
	pick := func(ids []string) string {
		for _, id := range ids {
			if _, ver, ok := csafCPE(prods[id]); ok && ver != "" {
				return ver
			}
		}
		return ""
	}
	var both []string
	for _, id := range fixed {
		if slices.Contains(remediated, id) {
			both = append(both, id)
		}
	}
	if ver := pick(both); ver != "" {
		return ver
	}
	return pick(fixed)
}
