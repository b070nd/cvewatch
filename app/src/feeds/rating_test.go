package feeds

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

func nvdItem(t *testing.T, metrics string) model.Item {
	t.Helper()
	items, err := parseNVD([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-98432","descriptions":[{"lang":"en","value":"Linux kernel TCP use-after-free."}],"metrics":`+metrics+`}}]}`), model.Source{ID: "nvd"}, time.Time{})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	return items[0]
}

type want struct {
	score   float64
	version string
	source  string
	sev     model.Severity
}

func checkRating(t *testing.T, it model.Item, w want) {
	t.Helper()
	if it.CVSS != w.score || it.CVSSVersion != w.version || it.CVSSSource != w.source || it.Severity != w.sev {
		t.Fatalf("rating = %v v%q %q sev=%v, want %+v (vector %q)", it.CVSS, it.CVSSVersion, it.CVSSSource, it.Severity, w, it.CVSSVector)
	}
}

const (
	vec31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vec40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	vec30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	vec20 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
)

func TestNVDRatingPicksPrimaryThenNewestVersion(t *testing.T) {
	v31p := `{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"` + vec31 + `","baseScore":9.8,"baseSeverity":"CRITICAL"}}`
	v40s := `{"source":"security@vendor.example","type":"Secondary","cvssData":{"version":"4.0","vectorString":"` + vec40 + `","baseScore":9.3,"baseSeverity":"CRITICAL"}}`
	v30p := `{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.0","vectorString":"` + vec30 + `","baseScore":7.5,"baseSeverity":"HIGH"}}`
	v2p := `{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"` + vec20 + `","baseScore":7.5},"baseSeverity":"HIGH","exploitabilityScore":10.0}`
	v40p := `{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"4.0","vectorString":"` + vec40 + `","baseScore":9.3,"baseSeverity":"CRITICAL"}}`

	cases := []struct {
		name    string
		metrics string
		want    want
		vector  string
	}{
		{"primary 3.1 beats a secondary 4.0", `{"cvssMetricV31":[` + v31p + `],"cvssMetricV40":[` + v40s + `],"cvssMetricV2":[` + v2p + `]}`, want{9.8, "3.1", "nvd", model.SevCritical}, vec31},
		{"primary 4.0 beats primary 3.1", `{"cvssMetricV31":[` + v31p + `],"cvssMetricV40":[` + v40p + `]}`, want{9.3, "4.0", "nvd", model.SevCritical}, vec40},
		{"3.1 beats 3.0 and 2.0", `{"cvssMetricV30":[` + v30p + `],"cvssMetricV31":[` + v31p + `],"cvssMetricV2":[` + v2p + `]}`, want{9.8, "3.1", "nvd", model.SevCritical}, vec31},
		{"3.0 beats 2.0", `{"cvssMetricV30":[` + v30p + `],"cvssMetricV2":[` + v2p + `]}`, want{7.5, "3.0", "nvd", model.SevHigh}, vec30},
		{"only 2.0, label at the metric", `{"cvssMetricV2":[` + v2p + `]}`, want{7.5, "2.0", "nvd", model.SevHigh}, vec20},
		{"only a secondary is still used", `{"cvssMetricV40":[` + v40s + `]}`, want{9.3, "4.0", "nvd-secondary", model.SevCritical}, vec40},
		{"no metrics", `{}`, want{0, "", "", model.SevUnknown}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			it := nvdItem(t, c.metrics)
			checkRating(t, it, c.want)
			if it.CVSSVector != c.vector {
				t.Errorf("vector = %q, want %q", it.CVSSVector, c.vector)
			}
		})
	}
}

func TestNVDRatingV2HasNoCriticalAndFillsMissingFields(t *testing.T) {
	// no label, no version in cvssData: the list name and the score decide
	it := nvdItem(t, `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":10.0}}]}`)
	checkRating(t, it, want{10, "2.0", "nvd", model.SevHigh})
}

func TestNVDRatingDropsAHostileVector(t *testing.T) {
	it := nvdItem(t, `{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N [x](http://evil) \u001b[31m","baseScore":5.0}}]}`)
	if it.CVSS != 5 || it.CVSSVector != "" {
		t.Fatalf("score kept, vector dropped: %v %q", it.CVSS, it.CVSSVector)
	}
}

func TestNVDRatingsByID(t *testing.T) {
	body := `{"totalResults":2,"vulnerabilities":[
	 {"cve":{"id":"CVE-2026-1111","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"` + vec31 + `","baseScore":9.8}}]}}},
	 {"cve":{"id":"cve-2026-2222","metrics":{}}}]}`
	got, err := NVDRatings([]byte(body))
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v err=%v", got, err)
	}
	if r := got["CVE-2026-1111"]; r.Score != 9.8 || r.Version != "3.1" || r.Vector != vec31 || r.Source != model.ScoreNVD {
		t.Fatalf("rating = %+v", r)
	}
	if _, err := NVDRatings([]byte("<html>")); err == nil {
		t.Fatal("a body that is not JSON is an error")
	}
}

func cveRecItem(t *testing.T, containers string) model.Item {
	t.Helper()
	var r cveRecord
	rec := `{"cveMetadata":{"cveId":"CVE-2026-98432","state":"PUBLISHED","datePublished":"2026-10-01T00:00:00.000Z"},"containers":` + containers + `}`
	if err := json.Unmarshal([]byte(rec), &r); err != nil {
		t.Fatal(err)
	}
	it, ok := r.item("cve-records")
	if !ok {
		t.Fatal("record not accepted")
	}
	return it
}

func TestCVERecordRating(t *testing.T) {
	cna31 := `{"cvssV3_1":{"version":"3.1","vectorString":"` + vec31 + `","baseScore":9.8,"baseSeverity":"CRITICAL"}}`
	cna20 := `{"cvssV2_0":{"version":"2.0","vectorString":"` + vec20 + `","baseScore":7.5}}`
	cna40 := `{"cvssV4_0":{"version":"4.0","vectorString":"` + vec40 + `","baseScore":9.3,"baseSeverity":"CRITICAL"}}`
	adp40 := `{"title":"CISA ADP Vulnrichment","metrics":[` + cna40 + `]}`
	base := `"title":"UAF","descriptions":[{"lang":"en","value":"A flaw."}]`

	cases := []struct {
		name       string
		containers string
		want       want
	}{
		{"the CNA's 3.1 beats an ADP 4.0", `{"cna":{` + base + `,"metrics":[` + cna31 + `]},"adp":[` + adp40 + `]}`, want{9.8, "3.1", "cna", model.SevCritical}},
		{"newest version inside the CNA container", `{"cna":{` + base + `,"metrics":[` + cna31 + `,` + cna40 + `]}}`, want{9.3, "4.0", "cna", model.SevCritical}},
		{"only 2.0 has no critical band", `{"cna":{` + base + `,"metrics":[` + cna20 + `]}}`, want{7.5, "2.0", "cna", model.SevHigh}},
		{"ADP alone is used and labelled", `{"cna":{` + base + `},"adp":[` + adp40 + `]}`, want{9.3, "4.0", "adp", model.SevCritical}},
		{"nothing", `{"cna":{` + base + `}}`, want{0, "", "", model.SevUnknown}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkRating(t, cveRecItem(t, c.containers), c.want) })
	}
	if it := cveRecItem(t, `{"cna":{`+base+`,"metrics":[`+cna31+`]}}`); it.CVSSVector != vec31 {
		t.Errorf("vector = %q", it.CVSSVector)
	}
}

func TestGHSARating(t *testing.T) {
	adv := func(scores string) model.Item {
		items, err := parseGHSA([]byte(`[{"ghsa_id":"GHSA-cfgh-2345-wxqr","cve_id":"CVE-2026-98432","summary":"RCE","severity":"critical","html_url":"https://github.com/advisories/GHSA-cfgh-2345-wxqr",`+scores+`,"vulnerabilities":[]}]`), model.Source{ID: "ghsa"}, time.Time{})
		if err != nil || len(items) != 1 {
			t.Fatalf("items=%d err=%v", len(items), err)
		}
		return items[0]
	}
	v3 := `"cvss_v3":{"vector_string":"` + vec31 + `","score":9.8}`
	v4 := `"cvss_v4":{"vector_string":"` + vec40 + `","score":9.3}`
	t.Run("4.0 and 3.1 present: 4.0", func(t *testing.T) {
		it := adv(`"cvss":{"vector_string":"` + vec31 + `","score":9.8},"cvss_severities":{` + v3 + `,` + v4 + `}`)
		checkRating(t, it, want{9.3, "4.0", "ghsa", model.SevCritical})
		if it.CVSSVector != vec40 {
			t.Errorf("vector = %q", it.CVSSVector)
		}
	})
	t.Run("4.0 null", func(t *testing.T) {
		checkRating(t, adv(`"cvss":{"vector_string":"`+vec31+`","score":9.8},"cvss_severities":{`+v3+`,"cvss_v4":{"vector_string":null,"score":null}}`), want{9.8, "3.1", "ghsa", model.SevCritical})
	})
	t.Run("legacy cvss only", func(t *testing.T) {
		checkRating(t, adv(`"cvss":{"vector_string":"`+vec30+`","score":7.5}`), want{7.5, "3.0", "ghsa", model.SevCritical}) // the advisory's own label wins
	})
	t.Run("legacy score without a vector keeps no version", func(t *testing.T) {
		checkRating(t, adv(`"cvss":{"score":8.1}`), want{8.1, "", "ghsa", model.SevCritical})
	})
}

func TestCSAFRatingAllVersions(t *testing.T) {
	doc := func(scores string) model.Item {
		var d csafDoc
		if err := json.Unmarshal([]byte(`{"document":{"title":"Widget","aggregate_severity":{"text":"Important"},"tracking":{"id":"W-1","initial_release_date":"2026-10-01T00:00:00Z"}},"vulnerabilities":[`+scores+`]}`), &d); err != nil {
			t.Fatal(err)
		}
		base, _ := url.Parse("https://psirt.example.com/csaf/")
		it, ok := d.item("vendor", base, "https://psirt.example.com/csaf/w-1.json")
		if !ok {
			t.Fatal("not accepted")
		}
		return it
	}
	v2 := `"cvss_v2":{"version":"2.0","vectorString":"` + vec20 + `","baseScore":7.5}`
	v3 := `"cvss_v3":{"version":"3.1","vectorString":"` + vec31 + `","baseScore":9.8}`
	v4 := `"cvss_v4":{"version":"4.0","vectorString":"` + vec40 + `","baseScore":9.3}`
	checkRating(t, doc(`{"cve":"CVE-2026-1","scores":[{`+v2+`,`+v3+`,`+v4+`}]}`), want{9.3, "4.0", "csaf", model.SevCritical})
	checkRating(t, doc(`{"cve":"CVE-2026-1","scores":[{`+v2+`}]}`), want{7.5, "2.0", "csaf", model.SevHigh})
	checkRating(t, doc(`{"cve":"CVE-2026-1","scores":[{"cvss_v3":{"version":"3.1","baseScore":5.0}}]},{"cve":"CVE-2026-2","scores":[{`+v3+`}]}`), want{9.8, "3.1", "csaf", model.SevCritical})
	// no score: the document's label alone
	checkRating(t, doc(`{"cve":"CVE-2026-1"}`), want{0, "", "", model.SevHigh})
}

func TestTextRating(t *testing.T) {
	cases := []struct {
		name, text string
		ids        []string
		score      float64
		version    string
		ok         bool
	}{
		{"plain", "Researchers rate it CVSS 9.8 and urge patching.", []string{"CVE-2026-1"}, 9.8, "", true},
		{"colon", "CVSS: 7.5 (high)", nil, 7.5, "", true},
		{"version and score", "It carries a CVSS v4.0 base score of 9.3.", nil, 9.3, "4.0", true},
		{"version without v", "CVSS 3.1 score 8.8, network exploitable", nil, 8.8, "3.1", true},
		{"score ends a sentence", "The flaw has a CVSS 9.8.", nil, 9.8, "", true},
		{"ten", "CVSS score 10.0 flaw", nil, 10, "", true},
		{"a vector is not a score", "Vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil, 0, "", false},
		{"no digits", "A critical CVSS score was assigned.", nil, 0, "", false},
		{"roundup of several CVEs", "CVSS 9.8", []string{"CVE-2026-1", "CVE-2026-2"}, 0, "", false},
		{"a longer number", "CVSS 9.8.1 is not a score", nil, 0, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, ok := textRating(c.text, c.ids)
			if ok != c.ok || r.Score != c.score || r.Version != c.version || (ok && r.Source != model.ScoreText) {
				t.Fatalf("textRating = %+v ok=%v", r, ok)
			}
		})
	}
}

func TestFinishRatesAnArticleFromItsText(t *testing.T) {
	it, ok := finish("news", model.Item{Title: "Kernel flaw CVE-2026-98432 rated CVSS 9.8", Summary: "x"})
	if !ok || it.CVSS != 9.8 || it.CVSSSource != model.ScoreText || it.Severity != model.SevCritical {
		t.Fatalf("item = %+v", it)
	}
	// a feed's own score is never replaced by the text
	it, _ = finish("nvd", model.Item{Title: "Flaw CVSS 9.8", CVSS: 5, CVSSSource: model.ScoreNVD, Severity: model.SevMedium})
	if it.CVSS != 5 || it.CVSSSource != model.ScoreNVD || it.Severity != model.SevMedium {
		t.Fatalf("item = %+v", it)
	}
}
