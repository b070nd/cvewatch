package pipeline_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

const nvdAPI = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

const nvdRated = `{"vulnerabilities":[{"cve":{"id":"CVE-2026-1111","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}]}`

func cvssRig(t *testing.T, settings string) *testkit.Rig {
	files := map[string]string{
		"config/techs.yaml": "techs:\n  - name: php\n", "sources/s.yaml": sources,
		"config/projects/shop.yaml": "name: shop\nenvs: [prod]\ntechs: [{name: php}]\n",
	}
	if settings != "" {
		files["config/config.yaml"] = settings
	}
	return testkit.NewRig(t, files, map[string]string{feedURL: rss, nvdAPI + "CVE-2026-1111": nvdRated})
}

func asked(g *testkit.Rig, prefix string) int {
	n := 0
	for _, u := range g.Getter.Asked {
		if strings.HasPrefix(u, prefix) {
			n++
		}
	}
	return n
}

func TestUnratedIssueGetsItsScoreFromNVD(t *testing.T) {
	g := cvssRig(t, "")
	res := g.Run()
	v := g.Ledger.Vuln("CVE-2026-1111")
	if v == nil || v.CVSS != 9.8 || v.CVSSVersion != "3.1" || v.CVSSSource != model.ScoreNVD || !strings.HasPrefix(v.CVSSVector, "CVSS:3.1/") || res.Rated != 1 {
		t.Fatalf("an RSS item has no score; NVD supplies it: %+v res=%+v", v, res)
	}
	if v.Severity != model.SevCritical || v.CVSSChecked.IsZero() {
		t.Fatalf("severity follows the score and the lookup is remembered: %+v", v)
	}
	if n := asked(g, nvdAPI); n != 1 {
		t.Fatalf("only the tracked CVE is asked: %v", g.Getter.Asked)
	}

	g.Run()
	if n := asked(g, nvdAPI); n != 1 {
		t.Fatalf("a rated issue is not asked again: %d requests", n)
	}
}

func TestIssueNVDCannotRateYetIsAskedAgainOnlyAfterADay(t *testing.T) {
	g := cvssRig(t, "")
	g.Serve(nvdAPI+"CVE-2026-1111", `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-1111","metrics":{}}}]}`)
	if res := g.Run(); res.Rated != 0 {
		t.Fatalf("nothing to rate yet: %+v", res)
	}
	g.Run()
	if n := asked(g, nvdAPI); n != 1 {
		t.Fatalf("remembered in the ledger, not repeated within a day: %d requests", n)
	}
	g.Now = g.Now.Add(25 * time.Hour)
	g.Serve(nvdAPI+"CVE-2026-1111", nvdRated)
	if res := g.Run(); res.Rated != 1 || g.Ledger.Vuln("CVE-2026-1111").CVSS != 9.8 {
		t.Fatalf("NVD analysed it meanwhile: %+v", res)
	}
}

func TestCVSSEnrichmentCanBeSwitchedOff(t *testing.T) {
	g := cvssRig(t, "enrich: {cvss: false}\n")
	res := g.Run()
	if asked(g, nvdAPI) != 0 || res.Rated != 0 || g.Ledger.Vuln("CVE-2026-1111").CVSS != 0 {
		t.Fatalf("switched off: asked=%v res=%+v", g.Getter.Asked, res)
	}
}

func TestCVSSEnrichmentSkipsIssuesASourceAlreadyRated(t *testing.T) {
	g := cvssRig(t, "")
	g.Serve(feedURL, `<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>`)
	g.Serve(nvdURL, `{"vulnerabilities":[{"cve":{"id":"CVE-2026-1111","published":"{{NVD_NOW}}",
	"descriptions":[{"lang":"en","value":"PHP flaw."}],
	"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionEndExcluding":"8.2.30"}]}]}],
	"metrics":{"cvssMetricV2":[{"type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P","baseScore":7.5},"baseSeverity":"HIGH"}]}}}]}`)
	g.Reload()
	g.Run()
	v := g.Ledger.Vuln("CVE-2026-1111")
	if v == nil || v.CVSS != 7.5 || v.CVSSVersion != "2.0" || asked(g, nvdAPI) != 0 {
		t.Fatalf("a source's own score is kept and nothing is asked: %+v asked=%v", v, g.Getter.Asked)
	}
}

func TestCVSSLookupFailureIsOnlyAWarning(t *testing.T) {
	g := cvssRig(t, "")
	g.Getter.Errs = map[string]error{nvdAPI + "CVE-2026-1111": errors.New("timeout")}
	res := g.Run()
	v := g.Ledger.Vuln("CVE-2026-1111")
	if res.Rated != 0 || v == nil || v.CVSS != 0 || !v.CVSSChecked.IsZero() || len(res.Failed) != 0 {
		t.Fatalf("the cycle goes on and the lookup is retried next time: %+v %+v", res, v)
	}
	delete(g.Getter.Errs, nvdAPI+"CVE-2026-1111")
	if res := g.Run(); res.Rated != 1 {
		t.Fatalf("retry: %+v", res)
	}
}
