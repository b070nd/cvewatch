// Package cvss rates issues that no feed scored, from NVD's public CVE API.
// Only CVE ids are ever sent, one request each, so the host's rate limit
// (config http.host_rates) paces the calls.
package cvss

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/b070nd/cvewatch/app/src/feeds"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Getter is the part of httpx.Client that Lookup needs.
type Getter = feeds.Getter

const (
	endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// MaxPerCycle bounds the requests of one call: NVD allows about 5 per 30
	// seconds without a key, and the rest follow on the next cycles.
	MaxPerCycle = 5
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Lookup asks NVD for the rating of each CVE id, at most MaxPerCycle ids in
// the order given. It returns the ratings found by upper-case id and the ids
// NVD answered for, rated or not, so callers can avoid asking again soon. If
// a request fails it stops there and returns what it has with the error.
// Errors never contain the URL.
func Lookup(ctx context.Context, g Getter, ids []string) (map[string]model.Rating, []string, error) {
	found := map[string]model.Rating{}
	var answered []string
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !cvePattern.MatchString(id) {
			continue
		}
		if len(answered) >= MaxPerCycle {
			break
		}
		resp, err := g.Get(ctx, endpoint+"?cveId="+url.QueryEscape(id), model.Validators{}, map[string]string{"Accept": "application/json"})
		if err != nil {
			var se *httpx.StatusError
			if errors.As(err, &se) && se.Code == 404 {
				answered = append(answered, id) // NVD does not know the id
				continue
			}
			return found, answered, fmt.Errorf("cvss: %s: request failed", id)
		}
		ratings, err := feeds.NVDRatings(resp.Body)
		if err != nil {
			return found, answered, fmt.Errorf("cvss: %s: malformed response", id)
		}
		answered = append(answered, id)
		if r, ok := ratings[id]; ok {
			found[id] = r
		}
	}
	return found, answered, nil
}
