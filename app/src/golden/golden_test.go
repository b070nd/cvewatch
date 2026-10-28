// Package golden replays synthetic NVD, GitHub advisory, KEV and news items
// through the shipped configuration and checks what the tool decides: match,
// no match, or unchecked. It is the safety net for noise: a wrong CPE name, a
// weakened exclude or a version-ordering mistake fails CI here before a
// stranger sees a noisy first run.
//
// To add a case, append to the cases table below with a builder for the feed
// type. Fixtures are synthetic; never paste real advisories with personal data.
package golden

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

const (
	nvdURL  = "https://golden.test/nvd"
	ghsaURL = "https://golden.test/ghsa"
	kevURL  = "https://golden.test/kev"
	rssURL  = "https://golden.test/news"
)

// Sources mirror the shipped feed settings that matter for noise.
const sources = `sources:
  - {id: nvd, type: nvd, url: '` + nvdURL + `', match_structured: true, match_title_only: true}
  - {id: ghsa, type: ghsa, url: '` + ghsaURL + `'}
  - {id: kev, type: kev, url: '` + kevURL + `'}
  - {id: news, type: rss, url: '` + rssURL + `'}
`

// nvd builds one NVD CVE. cpe is "vendor:product"; endExcl is the first fixed version.
func nvd(id, desc, cpe, endExcl string) string {
	cfg := ""
	if cpe != "" {
		cfg = `"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:` + cpe + `:*:*:*:*:*:*:*:*","versionEndExcluding":"` + endExcl + `"}]}]}],`
	}
	return `{"vulnerabilities":[{"cve":{"id":"` + id + `","published":"{{NVD_NOW}}",` + cfg + `"descriptions":[{"lang":"en","value":"` + desc + `"}],"references":[]}}]}`
}

// ghsa builds one GitHub advisory for a package.
func ghsa(ghsaID, cve, eco, pkg, rng string) string {
	return `[{"ghsa_id":"` + ghsaID + `","cve_id":"` + cve + `","summary":"Flaw in ` + pkg + `","description":"x","severity":"high",
	"html_url":"https://github.test/advisories/` + ghsaID + `","published_at":"{{RFC_NOW}}",
	"vulnerabilities":[{"package":{"ecosystem":"` + eco + `","name":"` + pkg + `"},"vulnerable_version_range":"` + rng + `","first_patched_version":"9.9.9"}]}]`
}

func news(title, link string) string {
	return `<?xml version="1.0"?><rss version="2.0"><channel><item><title>` + title + `</title><link>` + link + `</link>
	<description>Details inside.</description><pubDate>{{RSS_NOW}}</pubDate></item></channel></rss>`
}

func kev(id, vendor, product, name string) string {
	return `{"vulnerabilities":[{"cveID":"` + id + `","vendorProject":"` + vendor + `","product":"` + product + `","vulnerabilityName":"` + name + `",
	"shortDescription":"Exploited.","dateAdded":"{{TODAY}}","dueDate":"2026-11-17","requiredAction":"Apply updates.","knownRansomwareCampaignUse":"Unknown"}]}`
}

type want struct {
	Env     model.Env
	Applies model.Applicability
}

type tcase struct {
	name string
	url  string // which feed serves the body
	body string
	id   string // the vulnerability id the case is about
	// want lists the expected findings; empty means none at all.
	want []want
}

var prodDev = func(a model.Applicability) []want {
	return []want{{model.EnvDev, a}, {model.EnvProd, a}}
}

var cases = []tcase{
	// --- NVD product data decides, with versions ---
	{"nvd php inside the affected range", nvdURL, nvd("CVE-2099-0001", "PHP flaw.", "php:php", "8.2.30"), "CVE-2099-0001", prodDev(model.AppAffected)},
	{"nvd php already fixed", nvdURL, nvd("CVE-2099-0002", "PHP flaw.", "php:php", "8.2.5"), "CVE-2099-0002", prodDev(model.AppNotAffected)},
	{"nvd nginx inside the range", nvdURL, nvd("CVE-2099-0003", "nginx flaw.", "nginx:nginx", "1.25.4"), "CVE-2099-0003", prodDev(model.AppAffected)},
	{"nvd go series 1.22 is only partly inside a patch-level bound", nvdURL, nvd("CVE-2099-0004", "Go flaw.", "golang:go", "1.22.5"), "CVE-2099-0004", prodDev(model.AppUnknown)},
	{"nvd python inside the range", nvdURL, nvd("CVE-2099-0005", "Python flaw.", "python:python", "3.11.9"), "CVE-2099-0005", prodDev(model.AppAffected)},
	{"nvd adobe commerce reaches magento", nvdURL, nvd("CVE-2099-0006", "Commerce flaw.", "adobe:commerce", "2.4.7"), "CVE-2099-0006", prodDev(model.AppAffected)},

	// --- noise that must stay out ---
	{"nvd moodle plugin written in PHP is not PHP", nvdURL, nvd("CVE-2099-0010", "A Moodle block, written in PHP, has XSS.", "moodle:moodle", "5.0"), "CVE-2099-0010", nil},
	{"nvd entry without product data waits instead of matching words", nvdURL, nvd("CVE-2099-0011", "PHP application CMS flaw.", "", ""), "CVE-2099-0011", nil},
	{"news about a wordpress plugin mentioning PHP", rssURL, news("Gallery plugin for WordPress allows PHP code injection CVE-2099-0012", "https://news.test/wp"), "CVE-2099-0012", nil},
	{"news about an unrelated product", rssURL, news("Photo editor CVE-2099-0013 lets attackers crash the app", "https://news.test/photo"), "CVE-2099-0013", nil},

	// --- packages in lockfiles, in each ecosystem ---
	{"composer package from the lockfile", ghsaURL, ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2099-0020", "composer", "symfony/http-kernel", ">= 6.4.0, < 6.4.2"), "CVE-2099-0020", prodDev(model.AppAffected)},
	{"composer dev package matters in dev only", ghsaURL, ghsa("GHSA-aaaa-bbbb-dddd", "CVE-2099-0021", "composer", "phpunit/phpunit", "< 10.1.0"), "CVE-2099-0021", []want{{model.EnvDev, model.AppAffected}}},
	{"npm package from the lockfile", ghsaURL, ghsa("GHSA-aaaa-bbbb-eeee", "CVE-2099-0022", "npm", "lodash", "< 4.17.21"), "CVE-2099-0022", prodDev(model.AppAffected)},
	{"npm package already patched", ghsaURL, ghsa("GHSA-aaaa-bbbb-ffff", "CVE-2099-0023", "npm", "lodash", "< 4.17.0"), "CVE-2099-0023", prodDev(model.AppNotAffected)},
	{"pypi names match across pip, PyPI and underscores", ghsaURL, ghsa("GHSA-aaaa-bbbb-gggg", "CVE-2099-0024", "pip", "Django_REST.framework", "< 3.15.0"), "CVE-2099-0024", prodDev(model.AppAffected)},
	{"maven package from the gradle lockfile", ghsaURL, ghsa("GHSA-aaaa-bbbb-hhhh", "CVE-2099-0025", "maven", "org.apache.logging.log4j:log4j-core", "< 2.17.1"), "CVE-2099-0025", prodDev(model.AppAffected)},
	{"go module from go.mod", ghsaURL, ghsa("GHSA-aaaa-bbbb-jjjj", "CVE-2099-0026", "go", "golang.org/x/net", "< 0.17.0"), "CVE-2099-0026", prodDev(model.AppAffected)},
	{"a package we do not use", ghsaURL, ghsa("GHSA-aaaa-bbbb-kkkk", "CVE-2099-0027", "npm", "left-pad", "< 9.0.0"), "CVE-2099-0027", nil},
	{"the word PHP in a package advisory is not a PHP advisory", ghsaURL, ghsa("GHSA-aaaa-bbbb-mmmm", "CVE-2099-0028", "composer", "acme/php-widget", "< 2.0.0"), "CVE-2099-0028", nil},

	// --- sources without versions stay unchecked ---
	{"news about PHP stays unchecked", rssURL, news("PHP remote code execution flaw under attack CVE-2099-0030", "https://news.test/php"), "CVE-2099-0030", prodDev(model.AppUnknown)},
	{"KEV listing of PHP is a text match until NVD analyses it", kevURL, kev("CVE-2099-0031", "PHP Group", "PHP", "PHP Memory Corruption Vulnerability"), "CVE-2099-0031", prodDev(model.AppUnknown)},
}

func newRig(t *testing.T, c tcase) *testkit.Rig {
	t.Helper()
	files := map[string]string{"sources/s.yaml": sources}
	files["config/projects/stack.yaml"] = read(t, "testdata/stack.yaml")
	for _, f := range []string{"composer.lock", "package-lock.json", "requirements.txt", "gradle.lockfile", "go.mod"} {
		files["lock/"+f] = read(t, "testdata/lock/"+f)
	}
	// no techs.yaml: the shipped one is what is under test
	return testkit.NewRig(t, files, map[string]string{c.url: c.body})
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGolden(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newRig(t, c)
			g.Run()
			got := map[model.Env]model.Applicability{}
			for _, f := range g.Findings(c.id) {
				if f.Project == "stack" {
					got[f.Env] = f.Applies
				}
			}
			if len(got) != len(c.want) {
				t.Fatalf("%s: findings %v, want %v", c.id, got, c.want)
			}
			for _, w := range c.want {
				if got[w.Env] != w.Applies {
					t.Errorf("%s in %s: %q, want %q (all: %v)", c.id, w.Env, got[w.Env], w.Applies, got)
				}
			}
		})
	}
}

// TestShippedCPENamesAreKnownGood fails when techs.yaml carries a product name
// that is not on the independently written list. A typo there would hide real
// advisories without any error.
func TestShippedCPENamesAreKnownGood(t *testing.T) {
	good := map[string]bool{}
	f, err := os.Open("testdata/cpe-known-good.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			if parts := strings.Fields(line); len(parts) == 2 {
				good[parts[0]+" "+parts[1]] = true
			}
		}
	}

	cfg, err := config.Load(t.TempDir()) // an empty root loads the shipped defaults
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DefaultTechs {
		t.Fatal("expected the shipped techs")
	}
	for _, tech := range cfg.Techs {
		for _, cpe := range tech.CPE {
			if !good[strings.ToLower(tech.Name)+" "+cpe] {
				t.Errorf("techs.yaml says %s has CPE %q, which is not on the known-good list: a wrong name hides real advisories", tech.Name, cpe)
			}
		}
	}
}

// TestEveryKnownCPEHasACase makes sure each product name on the list is
// exercised end to end: an NVD advisory naming it must produce a finding for
// the stack, which fails if techs.yaml drops or misspells the name.
func TestEveryKnownCPEHasACase(t *testing.T) {
	f, err := os.Open("testdata/cpe-known-good.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		n++
		c := tcase{url: nvdURL, id: "CVE-2099-9000", body: nvd("CVE-2099-9000", "Synthetic flaw.", parts[1], "999")}
		g := newRig(t, c)
		g.Run()
		if len(g.Findings(c.id)) == 0 {
			t.Errorf("an advisory naming %s (%s) produced no finding: techs.yaml must map it to %s", parts[1], parts[0], parts[0])
		}
	}
	if n == 0 {
		t.Fatal("empty known-good list")
	}
}
