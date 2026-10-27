package feeds

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cvewatch/src/model"
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
	Metrics struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V40 []nvdMetric `json:"cvssMetricV40"`
		V30 []nvdMetric `json:"cvssMetricV30"`
	} `json:"metrics"`
}

type nvdMetric struct {
	CVSSData struct {
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
	m := c.metric()
	return finish(srcID, model.Item{
		Title:     title,
		URL:       "https://nvd.nist.gov/vuln/detail/" + c.ID,
		Summary:   desc,
		Published: parseTime(c.Published),
		Severity:  severityOf(m.CVSSData.BaseSeverity, m.CVSSData.BaseScore),
		CVSS:      m.CVSSData.BaseScore,
	}, c.ID)
}

func (c nvdCVE) description() string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// metric returns the first available CVSS metric, newest v3.x first.
func (c nvdCVE) metric() nvdMetric {
	for _, list := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V40, c.Metrics.V30} {
		if len(list) > 0 {
			return list[0]
		}
	}
	return nvdMetric{}
}

// firstSentence cuts s after the first period that is followed by a space.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}
