package feeds

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/version"
)

// ghsaAdvisory is one entry of the GitHub advisories REST answer.
type ghsaAdvisory struct {
	GHSAID      string    `json:"ghsa_id"`
	CVEID       *string   `json:"cve_id"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt string    `json:"published_at"`
	CVSS        ghsaScore `json:"cvss"` // the older single score, normally the 3.x one
	CVSSLevels  struct {
		V3 ghsaScore `json:"cvss_v3"`
		V4 ghsaScore `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Vulnerabilities []struct {
		Package *struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableRange string `json:"vulnerable_version_range"`
		// FirstPatched is a plain string or an object with an identifier.
		FirstPatched json.RawMessage `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

type ghsaScore struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector_string"`
}

func parseGHSA(body []byte, src model.Source, _ time.Time) ([]model.Item, error) {
	var advisories []ghsaAdvisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	var items []model.Item
	for _, a := range advisories {
		var ids []string
		if a.CVEID != nil {
			ids = append(ids, *a.CVEID)
		}
		ids = append(ids, a.GHSAID)

		affected, fixes := a.affected(src.ID)
		it := model.Item{
			Title:     a.Summary,
			URL:       a.HTMLURL,
			Summary:   firstNonEmpty(a.Description, a.Summary),
			Affected:  affected,
			Fixes:     fixes,
			Published: parseTime(a.PublishedAt),
		}
		rate(&it, a.rating(), a.Severity)
		it, ok := finish(src.ID, it, ids...)
		if ok {
			items = append(items, it)
		}
	}
	return items, nil
}

// affected returns the vulnerable packages, merged by ecosystem and name,
// and a fix entry for every patched version named. A range that does not
// parse leaves the package in without ranges.
func (a ghsaAdvisory) affected(srcID string) ([]model.Affected, []model.Fix) {
	var list []model.Affected
	var fixes []model.Fix
	for _, v := range a.Vulnerabilities {
		if v.Package == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(v.Package.Name))
		if name == "" {
			continue
		}
		ranges, err := version.ParseRange(v.VulnerableRange)
		if err != nil {
			ranges = nil
		}
		fixed := firstPatched(v.FirstPatched)
		list = addAffected(list, model.Affected{
			Ecosystem: strings.ToLower(strings.TrimSpace(v.Package.Ecosystem)),
			Name:      name,
			Ranges:    ranges,
			Fixed:     fixed,
		})
		if fixed != "" {
			f := model.Fix{Kind: model.FixVersion, Detail: fixed, URL: a.HTMLURL, Source: srcID, Official: true}
			if !slices.Contains(fixes, f) {
				fixes = append(fixes, f)
			}
		}
	}
	return list, fixes
}

// firstPatched reads first_patched_version, which is a string, an object
// with an identifier, or null.
func firstPatched(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var o struct {
		Identifier string `json:"identifier"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return strings.TrimSpace(o.Identifier)
	}
	return ""
}
