package feeds

import (
	"encoding/json"
	"fmt"
	"time"

	"cvewatch/src/model"
)

// kevResponse is the part of the CISA KEV catalog we use.
type kevResponse struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		ShortDescription  string `json:"shortDescription"`
		DateAdded         string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// parseKEV keeps entries added on or after the day of since. The catalog is
// not filterable by URL, so this is where the polling window is applied.
// Entries with an unreadable date are kept, so none is missed.
func parseKEV(body []byte, src model.Source, since time.Time) ([]model.Item, error) {
	var r kevResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	y, m, d := since.UTC().Date()
	sinceDay := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)

	var items []model.Item
	for _, v := range r.Vulnerabilities {
		added, err := time.Parse(time.DateOnly, v.DateAdded)
		if err == nil && added.Before(sinceDay) {
			continue
		}
		it, ok := finish(src.ID, model.Item{
			Title:     fmt.Sprintf("%s %s: %s", v.VendorProject, v.Product, v.VulnerabilityName),
			URL:       "https://nvd.nist.gov/vuln/detail/" + v.CVEID,
			Summary:   "Actively exploited (CISA KEV). " + v.ShortDescription,
			Published: added,
			Severity:  model.SevHigh,
		}, v.CVEID)
		if ok {
			items = append(items, it)
		}
	}
	return items, nil
}
