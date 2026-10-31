package cvss

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

type fake struct {
	bodies map[string]string // by CVE id
	errs   map[string]error
	asked  []string
}

func (f *fake) Get(_ context.Context, u string, _ model.Validators, _ map[string]string) (*httpx.Response, error) {
	f.asked = append(f.asked, u)
	id := u[strings.LastIndex(u, "=")+1:]
	if err := f.errs[id]; err != nil {
		return nil, err
	}
	return &httpx.Response{Body: []byte(f.bodies[id])}, nil
}

func nvd(id, metrics string) string {
	return `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"` + id + `","metrics":` + metrics + `}}]}`
}

const v31 = `{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}]}`

func TestLookupRatesWhatNVDHasAndReportsWhatItAnswered(t *testing.T) {
	f := &fake{
		bodies: map[string]string{"CVE-2026-1001": nvd("CVE-2026-1001", v31), "CVE-2026-1002": nvd("CVE-2026-1002", `{}`)},
		errs:   map[string]error{"CVE-2026-1003": &httpx.StatusError{Code: 404, URL: "x"}},
	}
	got, answered, err := Lookup(context.Background(), f, []string{"cve-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "not-an-id", "GHSA-aaaa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-2026-1001"].Score != 9.8 || got["CVE-2026-1001"].Version != "3.1" || got["CVE-2026-1001"].Source != model.ScoreNVD {
		t.Fatalf("found = %+v", got)
	}
	if strings.Join(answered, ",") != "CVE-2026-1001,CVE-2026-1002,CVE-2026-1003" {
		t.Fatalf("answered = %v: unrated and unknown ids count, so they are not asked again soon", answered)
	}
	if len(f.asked) != 3 || f.asked[0] != endpoint+"?cveId=CVE-2026-1001" {
		t.Fatalf("asked = %v: only CVE ids are sent", f.asked)
	}
}

func TestLookupStopsAtTheCapAndAtAFailure(t *testing.T) {
	f := &fake{bodies: map[string]string{}, errs: map[string]error{"CVE-2026-1003": errors.New("dial tcp services.nvd.nist.gov: refused")}}
	var ids []string
	for _, n := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		ids = append(ids, "CVE-2026-100"+n)
		f.bodies["CVE-2026-100"+n] = nvd("CVE-2026-100"+n, v31)
	}
	got, answered, err := Lookup(context.Background(), f, ids)
	if err == nil || strings.Contains(err.Error(), "nist.gov") || strings.Contains(err.Error(), "cveId") {
		t.Fatalf("a failure is reported without the address: %v", err)
	}
	if len(got) != 2 || len(answered) != 2 || len(f.asked) != 3 {
		t.Fatalf("what came before the failure is kept: got=%d answered=%v asked=%d", len(got), answered, len(f.asked))
	}

	f = &fake{bodies: f.bodies}
	_, answered, err = Lookup(context.Background(), f, ids)
	if err != nil || len(answered) != MaxPerCycle || len(f.asked) != MaxPerCycle {
		t.Fatalf("at most %d per call: answered=%d asked=%d err=%v", MaxPerCycle, len(answered), len(f.asked), err)
	}
}

func TestLookupRejectsAMalformedAnswer(t *testing.T) {
	f := &fake{bodies: map[string]string{"CVE-2026-1001": "<html>rate limited</html>"}}
	got, answered, err := Lookup(context.Background(), f, []string{"CVE-2026-1001"})
	if err == nil || len(got) != 0 || len(answered) != 0 {
		t.Fatalf("got=%v answered=%v err=%v", got, answered, err)
	}
}
