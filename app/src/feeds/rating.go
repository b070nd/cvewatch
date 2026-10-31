package feeds

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// rated is a rating with the severity label the source printed beside it.
type rated struct {
	r     model.Rating
	label string
}

// best picks by model.BestRating and returns the label that came with it.
func best(cands []rated) (model.Rating, string) {
	rs := make([]model.Rating, len(cands))
	for i, c := range cands {
		rs[i] = c.r
	}
	b := model.BestRating(rs...)
	for _, c := range cands {
		if c.r == b {
			return b, c.label
		}
	}
	return b, ""
}

// ratingOf builds a rating from what a feed wrote. The version comes from the
// field, else the vector prefix, else fallback (the metric's own name).
func ratingOf(score float64, version, vector, source, fallback string) model.Rating {
	vector = model.CleanVector(vector)
	v := model.NormVersion(version)
	if v == "" {
		v = model.VectorVersion(vector)
	}
	if v == "" {
		v = fallback
	}
	return model.Rating{Score: score, Version: v, Vector: vector, Source: source}
}

// rating is the best CVSS metric of the record. NVD's own (Primary) metrics
// rank above the CNA's (Secondary), then the newest version wins.
func (c nvdCVE) rating() (model.Rating, string) {
	var cands []rated
	for _, g := range []struct {
		list []nvdMetric
		ver  string
	}{{c.Metrics.V40, model.CVSS40}, {c.Metrics.V31, model.CVSS31}, {c.Metrics.V30, model.CVSS30}, {c.Metrics.V2, model.CVSS20}} {
		for _, m := range g.list {
			source := model.ScoreNVD
			if strings.EqualFold(m.Type, "Secondary") {
				source = model.ScoreNVDSecondary
			}
			d := m.CVSSData
			cands = append(cands, rated{ratingOf(d.BaseScore, d.Version, d.VectorString, source, g.ver), firstNonEmpty(d.BaseSeverity, m.BaseSeverity)})
		}
	}
	return best(cands)
}

// NVDRatings reads the ratings out of an NVD API 2.0 answer, keyed by CVE id.
// Ids without a usable metric are absent. The ledger uses it to rate issues
// that arrived from a source without a score.
func NVDRatings(body []byte) (map[string]model.Rating, error) {
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	out := map[string]model.Rating{}
	for _, v := range r.Vulnerabilities {
		if rt, _ := v.CVE.rating(); rt.Valid() {
			out[strings.ToUpper(strings.TrimSpace(v.CVE.ID))] = rt
		}
	}
	return out, nil
}

// rating is the best score of the record: the CNA's own containers rank above
// the ADP ones, then the newest version wins.
func (r cveRecord) rating() (model.Rating, string) {
	var cands []rated
	add := func(c cveContainer, source string) {
		for _, m := range c.Metrics {
			for _, s := range []struct {
				s   *cveScore
				ver string
			}{{m.V40, model.CVSS40}, {m.V31, model.CVSS31}, {m.V30, model.CVSS30}, {m.V20, model.CVSS20}} {
				if s.s != nil {
					cands = append(cands, rated{ratingOf(s.s.BaseScore, s.s.Version, s.s.VectorString, source, s.ver), s.s.BaseSeverity})
				}
			}
		}
	}
	add(r.Containers.CNA, model.ScoreCNA)
	for _, c := range r.Containers.ADP {
		add(c, model.ScoreADP)
	}
	return best(cands)
}

// rating is the best of the advisory's scores: CVSS 4.0, 3.x, then the older
// single score, which is the 3.x one again and ranks last when it has no vector.
func (a ghsaAdvisory) rating() model.Rating {
	var rs []model.Rating
	for _, s := range []ghsaScore{a.CVSSLevels.V4, a.CVSSLevels.V3, a.CVSS} {
		rs = append(rs, ratingOf(s.Score, "", s.Vector, model.ScoreGHSA, ""))
	}
	return model.BestRating(rs...)
}
