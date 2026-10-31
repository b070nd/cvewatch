package feeds

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// nvdResponse is the part of the NVD API 2.0 answer we use.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Metrics struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V40 []nvdMetric `json:"cvssMetricV40"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetric struct {
	Type         string `json:"type"`         // Primary is NVD's own analysis, Secondary a CNA's score
	BaseSeverity string `json:"baseSeverity"` // CVSS 2.0 keeps its label here, the others inside cvssData
	CVSSData     struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

func parseNVD(body []byte, src model.Source, _ time.Time) ([]model.Item, error) {
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	var items []model.Item
	for _, v := range r.Vulnerabilities {
		if it, ok := v.CVE.item(src.ID); ok {
			items = append(items, it)
		}
	}
	return items, nil
}

func (c nvdCVE) item(srcID string) (model.Item, bool) {
	if strings.TrimSpace(c.ID) == "" {
		return model.Item{}, false
	}
	desc := c.description()
	title := c.ID
	if s := firstSentence(plain(desc)); s != "" {
		title += ": " + s
	}
	it := model.Item{
		Title:     title,
		URL:       "https://nvd.nist.gov/vuln/detail/" + c.ID,
		Summary:   desc,
		Affected:  c.affected(),
		Fixes:     c.fixes(srcID),
		Published: parseTime(c.Published),
	}
	r, label := c.rating()
	rate(&it, r, label)
	return finish(srcID, it, c.ID)
}

func (c nvdCVE) description() string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// firstSentence cuts s after the first period that is followed by a space.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

const (
	maxAffected = 50 // products kept per item
	maxFixes    = 20 // fixes kept per item
)

// affected lists the vulnerable products, merged by vendor:product. The
// operator logic of NVD configurations is ignored: every vulnerable match counts.
func (c nvdCVE) affected() []model.Affected {
	var list []model.Affected
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				name, ver, ok := cpeProduct(m.Criteria)
				if !m.Vulnerable || !ok {
					continue
				}
				a := model.Affected{Ecosystem: "cpe", Name: name, Ranges: []model.Range{m.rng(ver)}}
				if len(list) >= maxAffected && !slices.ContainsFunc(list, func(e model.Affected) bool { return e.Name == name }) {
					continue
				}
				list = addAffected(list, a)
			}
		}
	}
	return list
}

// rng is the affected range of one match: its bounds, else the exact
// version in the CPE, else every version.
func (m nvdCPEMatch) rng(cpeVersion string) model.Range {
	var r model.Range
	r.Min, r.MinExcl = firstNonEmpty(m.VersionStartIncluding, m.VersionStartExcluding), m.VersionStartIncluding == ""
	r.Max, r.MaxExcl = firstNonEmpty(m.VersionEndIncluding, m.VersionEndExcluding), m.VersionEndIncluding == ""
	if r.Min == "" {
		r.MinExcl = false
	}
	if r.Max == "" {
		r.MaxExcl = false
	}
	if r == (model.Range{}) && cpeVersion != "" {
		r.Min, r.Max = cpeVersion, cpeVersion
	}
	return r
}

// cpeProduct reads "cpe:2.3:part:vendor:product:version:..." and returns
// "vendor:product" and the version ("" when it is "*" or "-"), lower-case and unescaped.
func cpeProduct(criteria string) (name, ver string, ok bool) {
	f := splitCPE(strings.ToLower(strings.TrimSpace(criteria)))
	if len(f) < 5 || f[0] != "cpe" {
		return "", "", false
	}
	vendor, product := unescapeCPE(f[3]), unescapeCPE(f[4])
	if vendor == "" || product == "" {
		return "", "", false
	}
	if len(f) > 5 && f[5] != "*" && f[5] != "-" {
		ver = unescapeCPE(f[5])
	}
	return vendor + ":" + product, ver, true
}

// splitCPE splits on colons that are not escaped, keeping the escapes.
func splitCPE(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ':':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// unescapeCPE drops the backslash in front of an escaped character.
func unescapeCPE(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// fixes turns tagged references into fixes, one per tag and URL.
func (c nvdCVE) fixes(srcID string) []model.Fix {
	var out []model.Fix
	for _, ref := range c.References {
		u, err := url.Parse(strings.TrimSpace(ref.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		for _, tag := range ref.Tags {
			f := model.Fix{URL: u.String(), Source: srcID}
			switch tag {
			case "Patch":
				f.Kind = model.FixPatch
			case "Vendor Advisory":
				f.Kind, f.Official = model.FixAdvisory, true
			case "Mitigation":
				f.Kind = model.FixMitigation
			default:
				continue
			}
			if len(out) < maxFixes && !slices.ContainsFunc(out, func(e model.Fix) bool { return e.Kind == f.Kind && e.URL == f.URL }) {
				out = append(out, f)
			}
		}
	}
	return out
}
