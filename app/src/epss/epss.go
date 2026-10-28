// Package epss fetches EPSS exploit-prediction scores from FIRST's API.
// Only CVE ids are ever sent to the service.
package epss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Getter is the part of httpx.Client that Scores needs.
type Getter interface {
	Get(ctx context.Context, rawURL string, prev model.Validators, headers map[string]string) (*httpx.Response, error)
}

const (
	endpoint    = "https://api.first.org/data/v1/epss"
	batchSize   = 50 // ids per request, the API's limit
	maxRequests = 20 // per call; ids past batchSize*maxRequests are ignored
	maxIDs      = batchSize * maxRequests
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// apiResponse is the part of FIRST's reply that we read. Numbers arrive as strings.
type apiResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// Scores returns EPSS scores keyed by upper-case CVE id. Input that is not a
// CVE id is dropped and never sent. Ids FIRST does not know are absent from
// the map. If a batch fails, Scores stops there and returns the scores
// gathered so far together with the error.
func Scores(ctx context.Context, g Getter, ids []string) (map[string]model.EPSS, error) {
	clean := cleanIDs(ids)
	out := map[string]model.EPSS{}
	for n, start := 1, 0; start < len(clean); n, start = n+1, start+batchSize {
		batch := clean[start:min(start+batchSize, len(clean))]
		if err := fetchBatch(ctx, g, batch, out); err != nil {
			return out, fmt.Errorf("epss: batch %d: %w", n, err)
		}
	}
	return out, nil
}

// cleanIDs upper-cases, filters, de-duplicates and sorts ids, then keeps the first maxIDs.
func cleanIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if cvePattern.MatchString(id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return out[:min(len(out), maxIDs)]
}

// fetchBatch requests one batch and adds its valid scores to out. Errors never
// contain the URL: a transport error may echo it, so its text is dropped.
func fetchBatch(ctx context.Context, g Getter, batch []string, out map[string]model.EPSS) error {
	rawURL := endpoint + "?cve=" + strings.Join(batch, ",")
	resp, err := g.Get(ctx, rawURL, model.Validators{}, map[string]string{"Accept": "application/json"})
	if err != nil || resp == nil {
		return errors.New("request failed")
	}
	var body apiResponse
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return fmt.Errorf("malformed response: %w", err)
	}
	if body.Status != "OK" {
		return fmt.Errorf("unexpected status %q", body.Status)
	}
	for _, d := range body.Data {
		key := strings.ToUpper(strings.TrimSpace(d.CVE))
		score, okScore := unitInterval(d.EPSS)
		pct, okPct := unitInterval(d.Percentile)
		if key == "" || !okScore || !okPct {
			continue
		}
		// An unreadable date leaves Date zero; the score is still useful.
		date, _ := time.Parse(time.DateOnly, d.Date)
		out[key] = model.EPSS{Score: score, Percentile: pct, Date: date}
	}
	return nil
}

// unitInterval parses a decimal string and reports whether it lies in 0..1.
// NaN fails the comparison and is rejected.
func unitInterval(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v, err == nil && v >= 0 && v <= 1
}
