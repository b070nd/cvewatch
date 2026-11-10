package feeds

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/relevance"
)

func TestMagentoCPEUpdatesReachVersionJudgement(t *testing.T) {
	const fixture = `{"vulnerabilities":[{"cve":{"id":"CVE-2024-20758",
	 "descriptions":[{"lang":"en","value":"Adobe Commerce through 2.4.7-beta3; related to CVE-2024-20759"}],
	 "configurations":[{"nodes":[{"cpeMatch":[
	 {"vulnerable":true,"criteria":"cpe:2.3:a:adobe:commerce:-:*:*:*:*:*:*:*"},
	 {"vulnerable":true,"criteria":"cpe:2.3:a:adobe:commerce:2.4.7:beta3:*:*:*:*:*:*"},
	 {"vulnerable":true,"criteria":"cpe:2.3:a:adobe:commerce:2.4.6:p4:*:*:*:*:*:*"}
	 ]}]}]}}]}`
	it := fetch(t, body(fixture), "nvd", model.FeedState{})[0]
	if len(it.IDs) != 1 || it.IDs[0] != "CVE-2024-20758" {
		t.Fatalf("description references became identities: %v", it.IDs)
	}
	j := relevance.New([]model.Tech{{Name: "magento", CPE: []string{"adobe:commerce"}}})
	for _, tc := range []struct {
		version string
		want    model.Applicability
	}{
		{"2.4.7-p10", model.AppNotAffected},
		{"2.4.7-beta3", model.AppAffected},
		{"2.4.6-p4", model.AppAffected},
	} {
		t.Run(tc.version, func(t *testing.T) {
			v := j.Judge(it, []relevance.Target{{Project: "shop", Env: model.EnvProd, Techs: []model.ProjectTech{{Name: "magento", Version: tc.version}}}})
			if len(v.Matches) != 1 || v.Matches[0].Applies != tc.want {
				t.Fatalf("verdict = %+v, want %s", v, tc.want)
			}
		})
	}
}

func TestKEVProductIdentityConstrainsPHPAndPackageMatches(t *testing.T) {
	j := relevance.New([]model.Tech{{Name: "php", CPE: []string{"php:php"}}})
	targets := []relevance.Target{{Project: "shop", Env: model.EnvProd,
		Techs:    []model.ProjectTech{{Name: "php", Version: "8.2.35"}},
		Packages: []model.Package{{Ecosystem: "composer", Name: "composer/composer", Version: "2.10.2"}},
	}}
	for _, product := range []string{"Craft CMS", "Roundcube Webmail", "ProjectSend", "PHPMailer", "PHP"} {
		t.Run(product, func(t *testing.T) {
			fixture := fmt.Sprintf(`{"vulnerabilities":[{"cveID":"CVE-2026-10001","vendorProject":"PHP Group","product":%q,
			 "vulnerabilityName":"PHP injection","shortDescription":"PHP and composer/composer mentioned in passing","dateAdded":"2025-12-30"}]}`, product)
			it := fetch(t, body(fixture), "kev", model.FeedState{})[0]
			v := j.Judge(it, targets)
			if product == "PHP" {
				if len(v.Matches) != 1 || len(v.Matches[0].Installed) != 1 || v.Matches[0].Installed[0].Via != "tech" || v.Matches[0].Applies != model.AppUnknown {
					t.Fatalf("PHP identity must match only the tech, with unknown versions: %+v", v)
				}
			} else if v.Relevant() {
				t.Fatalf("uninstalled product matched PHP or an incidental package: %+v", v)
			}
		})
	}
}

func TestCVEProductWithoutCPEBlocksIncidentalPackage(t *testing.T) {
	var r cveRecord
	if err := json.Unmarshal([]byte(`{"cveMetadata":{"cveId":"CVE-2026-10003","state":"PUBLISHED"},"containers":{"cna":{
	 "title":"baserCMS command injection","descriptions":[{"lang":"en","value":"baserCMS uses composer/composer unsafely"}],
	 "affected":[{"vendor":"baserCMS","product":"baserCMS"}]}}}`), &r); err != nil {
		t.Fatal(err)
	}
	it, ok := r.item("cve-records")
	if !ok || len(it.Products) != 1 {
		t.Fatalf("missing explicit product: %+v", it)
	}
	v := relevance.New(nil).Judge(it, []relevance.Target{{Project: "shop", Env: model.EnvProd,
		Packages: []model.Package{{Ecosystem: "composer", Name: "composer/composer", Version: "2.10.2"}},
	}})
	if v.Relevant() {
		t.Fatalf("baserCMS prose matched an unrelated package: %+v", v)
	}
	// Explicit package identity remains useful without a CPE or version range.
	r.Containers.CNA.Affected[0].Product = "composer/composer"
	it, _ = r.item("cve-records")
	v = relevance.New(nil).Judge(it, []relevance.Target{{Project: "shop", Env: model.EnvProd,
		Packages: []model.Package{{Ecosystem: "composer", Name: "composer/composer", Version: "2.10.2"}},
	}})
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppUnknown {
		t.Fatalf("explicit scoped package identity was lost: %+v", v)
	}
}
