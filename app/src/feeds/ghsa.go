package feeds

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cvewatch/src/model"
)

// ghsaAdvisory is one entry of the GitHub advisories REST answer.
type ghsaAdvisory struct {
	GHSAID      string  `json:"ghsa_id"`
	CVEID       *string `json:"cve_id"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	HTMLURL     string  `json:"html_url"`
	PublishedAt string  `json:"published_at"`
	CVSS        struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Vulnerabilities []struct {
		Package *struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"vulnerabilities"`
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

		it, ok := finish(src.ID, model.Item{
			Title:     a.Summary,
			URL:       a.HTMLURL,
			Summary:   firstNonEmpty(a.Description, a.Summary),
			Packages:  a.packages(),
			Published: parseTime(a.PublishedAt),
			Severity:  severityOf(a.Severity, a.CVSS.Score),
			CVSS:      a.CVSS.Score,
		}, ids...)
		if ok {
			items = append(items, it)
		}
	}
	return items, nil
}

// packages returns the affected package names, lower-case and without duplicates.
func (a ghsaAdvisory) packages() []string {
	var names []string
	seen := map[string]bool{}
	for _, v := range a.Vulnerabilities {
		if v.Package == nil {
			continue
		}
		n := strings.ToLower(strings.TrimSpace(v.Package.Name))
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}
