package feeds

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
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
		DueDate           string `json:"dueDate"`
		RequiredAction    string `json:"requiredAction"`
		RansomwareUse     string `json:"knownRansomwareCampaignUse"`
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
		link := "https://nvd.nist.gov/vuln/detail/" + v.CVEID
		summary := "Actively exploited (CISA KEV). " + v.ShortDescription
		if v.RansomwareUse == "Known" {
			summary += " Known ransomware use."
		}
		var fixes []model.Fix
		if action := truncate(plain(v.RequiredAction), 200); action != "" {
			fixes = []model.Fix{{Kind: model.FixAction, Detail: action, URL: link, Source: src.ID, Official: true}}
		}
		kev := &model.KEV{DateAdded: added, Action: truncate(plain(v.RequiredAction), 200), Ransomware: v.RansomwareUse == "Known"}
		if due, err := time.Parse(time.DateOnly, v.DueDate); err == nil {
			kev.DueDate = due
		}
		it, ok := finish(src.ID, model.Item{
			Title:     fmt.Sprintf("%s %s: %s", v.VendorProject, v.Product, v.VulnerabilityName),
			URL:       link,
			Summary:   summary,
			Fixes:     fixes,
			KEV:       kev,
			Published: added,
			Severity:  model.SevHigh,
		}, v.CVEID)
		if ok {
			items = append(items, it)
		}
	}
	return items, nil
}
