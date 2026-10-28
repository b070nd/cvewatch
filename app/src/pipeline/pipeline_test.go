package pipeline_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

const (
	feedURL = "https://ex.test/feed"
	nvdURL  = "https://ex.test/nvd"
	kevURL  = "https://ex.test/kev"
	sources = "sources:\n  - {id: feed, type: rss, url: '" + feedURL + "'}\n  - {id: nvd, type: nvd, url: '" + nvdURL + "'}\n  - {id: kev, type: kev, url: '" + kevURL + "'}\n"
	phpTech = "techs:\n  - name: php\n    cpe: [php:php]\n"
)

const rss = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CVE-2026-1111: PHP-FPM remote code execution</title><link>https://ex.test/a</link><description>Critical bug.</description></item>
<item><title>Weeknight pasta recipes</title><link>https://ex.test/b</link><description>Tasty.</description></item>
<item><title>symfony/http-kernel header injection (CVE-2026-2222)</title><link>https://ex.test/c</link><description>Fixed in 6.4.2.</description></item>
</channel></rss>`

func rig(t *testing.T, techs string, projects map[string]string, bodies map[string]string) *testkit.Rig {
	files := map[string]string{"config/techs.yaml": techs, "sources/s.yaml": sources}
	for name, body := range projects {
		files["config/projects/"+name+".yaml"] = body
	}
	return testkit.NewRig(t, files, bodies)
}

func nvdBody(id, desc, cpe, endExcl string) string {
	return `{"vulnerabilities":[{"cve":{"id":"` + id + `","published":"{{NVD_NOW}}",
	"descriptions":[{"lang":"en","value":"` + desc + `"}],
	"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:` + cpe + `:*:*:*:*:*:*:*:*","versionEndExcluding":"` + endExcl + `"}]}]}],
	"references":[{"url":"https://php.test/release","source":"vendor","tags":["Vendor Advisory"]}]}}]}`
}

func TestCycle(t *testing.T) {
	g := rig(t, "techs:\n  - name: php\n", map[string]string{
		"shop":       "name: shop\nenvs: [dev, prod]\ntechs: [{name: php, version: '8.2'}]\nlockfiles: [{type: composer, path: composer.lock}]\n",
		"middleware": "name: middleware\nenvs: [prod]\ntechs: [{name: php}]\n"},
		map[string]string{feedURL: rss})
	g.Write("composer.lock", `{"packages":[{"name":"symfony/http-kernel","version":"v6.4.1"}]}`)
	g.Reload()

	res := g.Run()
	// php item -> shop dev+prod, middleware prod; symfony item -> shop dev+prod. The recipe is ignored.
	if res.Items != 3 || res.New != 3 || res.Findings != 5 || res.Alerted != 5 {
		t.Fatalf("first run: %+v", res)
	}
	if len(g.Channel.Batches) != 1 || len(g.Channel.Batches[0]) != 2 {
		t.Fatalf("want one batch of two alerts, got %v", g.Channel.Batches)
	}
	if _, err := os.Stat(filepath.Join(g.Runner.Cfg.AlertsDir, "2026", "2026-10-27-php-cve-2026-1111.md")); err != nil {
		t.Fatalf("report missing: %v", err)
	}

	// Mark a fix, then add a tech that matches the old recipe item.
	if _, err := g.Ledger.SetStatus("CVE-2026-1111", "shop", model.EnvDev, model.StatusFixed, "v8.2.30", g.Now); err != nil {
		t.Fatal(err)
	}
	g.Write("config/techs.yaml", "techs:\n  - name: php\n  - name: pasta\n")
	g.Reload()

	res = g.Run()
	if res.New != 0 || res.Findings != 0 || res.Alerted != 0 || len(g.Channel.Batches) != 1 {
		t.Fatalf("second run must be quiet and must not re-judge old items: %+v", res)
	}
	for _, f := range g.Findings("CVE-2026-1111") {
		if f.Project == "shop" && f.Env == model.EnvDev && f.Status != model.StatusFixed {
			t.Fatal("fix status was reset")
		}
	}
	if n, err := g.Runner.Audit.Verify(); err != nil || n != 4 { // detected x2, alerted x2
		t.Fatalf("audit: n=%d err=%v", n, err)
	}
}

const sameIssue = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CVE-2026-3333: PHP-FPM remote code execution lets attackers run arbitrary code</title><link>https://ex.test/nvd-entry</link><description>NVD text.</description></item>
<item><title>Critical PHP-FPM remote code execution flaw lets attackers run arbitrary code</title><link>https://ex.test/news</link><description>News article.</description></item>
</channel></rss>`

func TestSameIssueIsAggregated(t *testing.T) {
	g := rig(t, "techs:\n  - name: php\n", map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php}]\n"},
		map[string]string{feedURL: sameIssue})
	res := g.Run()
	if res.Merged != 1 || res.Findings != 1 || len(g.Ledger.Relevant()) != 1 {
		t.Fatalf("want one merged issue with one finding: %+v", res)
	}
	if v := g.Ledger.Relevant()[0]; len(v.Refs) != 2 || v.Refs[0].Kind != model.RefArticle {
		t.Fatalf("both articles must be referenced as articles: %+v", v.Refs)
	}
}

func TestLateRangesTurnUnknownIntoAffectedAndAddFix(t *testing.T) {
	news := `<?xml version="1.0"?><rss version="2.0"><channel><item><title>CVE-2026-5555: PHP flaw lets attackers run code</title>
	<link>https://ex.test/news5</link><description>Reported today.</description></item></channel></rss>`
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{feedURL: news})

	g.Run()
	f := g.Findings("CVE-2026-5555")
	if len(f) != 1 || f[0].Applies != model.AppUnknown {
		t.Fatalf("a news item alone cannot decide the version: %+v", f)
	}

	g.Serve(nvdURL, nvdBody("CVE-2026-5555", "PHP flaw lets attackers run code.", "php:php", "8.2.30"))
	res := g.Run()
	f = g.Findings("CVE-2026-5555")
	if f[0].Applies != model.AppAffected || len(f[0].Reasons) == 0 {
		t.Fatalf("late NVD ranges must update the finding: %+v", f[0])
	}
	if v := g.Ledger.Vuln("CVE-2026-5555"); len(v.Fixes) != 1 || !v.Fixes[0].Official || len(v.Refs) != 2 || res.Findings != 0 {
		t.Fatalf("fix evidence and the second report must be merged, not duplicated: %+v res=%+v", v, res)
	}
}

func TestNotAffectedIsRecordedButNeverAlerted(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.3.1'}]\n"},
		map[string]string{nvdURL: nvdBody("CVE-2026-6666", "PHP flaw.", "php:php", "8.2.30")})
	res := g.Run()
	f := g.Findings("CVE-2026-6666")
	if len(f) != 1 || f[0].Applies != model.AppNotAffected || res.Alerted != 0 || len(g.Channel.Batches) != 0 {
		t.Fatalf("8.3.1 is outside < 8.2.30: finding kept, nobody alerted: %+v res=%+v", f, res)
	}
}

func TestCPEDataKeepsOtherProductsOut(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{nvdURL: nvdBody("CVE-2026-7777", "Moodle plugin, a PHP application.", "moodle:moodle", "5.0")})
	if res := g.Run(); res.Findings != 0 {
		t.Fatalf("an advisory naming Moodle is not about PHP: %+v", res)
	}
}

func TestEachEnvironmentRunsItsOwnVersion(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": `name: shop
envs: [dev, prod]
techs: [{name: php, version: '8.3'}]
environments:
  prod: {techs: {php: '8.2.10'}}
  dev: {techs: {php: '8.3.1'}}
`}, map[string]string{nvdURL: nvdBody("CVE-2026-8888", "PHP flaw.", "php:php", "8.2.30")})
	res := g.Run()
	got := map[model.Env]model.Applicability{}
	for _, f := range g.Findings("CVE-2026-8888") {
		got[f.Env] = f.Applies
	}
	if got[model.EnvProd] != model.AppAffected || got[model.EnvDev] != model.AppNotAffected || res.Alerted != 1 {
		t.Fatalf("prod runs 8.2.10 (affected), dev 8.3.1 (not): %v alerted=%d", got, res.Alerted)
	}
}

func TestInventoryChangeReconcilesFindings(t *testing.T) {
	project := func(v string) string {
		return "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '" + v + "'}]\n"
	}
	g := rig(t, phpTech, map[string]string{"shop": project("8.2.10")},
		map[string]string{nvdURL: nvdBody("CVE-2026-9999", "PHP flaw.", "php:php", "8.2.30")})
	g.Run()
	if f := g.Findings("CVE-2026-9999")[0]; f.Applies != model.AppAffected {
		t.Fatalf("starts affected: %+v", f)
	}

	g.Write("config/projects/shop.yaml", project("8.2.31")) // upgraded and declared
	g.Reload()
	res := g.Run()
	f := g.Findings("CVE-2026-9999")[0]
	last := f.History[len(f.History)-1]
	if res.Reconciled != 1 || f.Applies != model.AppNotAffected || f.Matched[0] != "php@8.2.31" || last.Action != "inventory" ||
		!strings.Contains(last.Note, "8.2.10 → php@8.2.31") {
		t.Fatalf("an upgrade must re-check the finding and say so: res=%+v finding=%+v", res, f)
	}
	if res := g.Run(); res.Reconciled != 0 {
		t.Fatalf("nothing changed, nothing to reconcile: %+v", res)
	}
}

func TestDevPackagesCountOnlyInDevelopmentEnvironments(t *testing.T) {
	g := rig(t, "techs:\n  - name: php\n", map[string]string{"shop": "name: shop\nenvs: [dev, prod]\nlockfiles: [{type: composer, path: composer.lock}]\n"},
		map[string]string{feedURL: `<?xml version="1.0"?><rss version="2.0"><channel><item><title>phpunit/phpunit flaw CVE-2026-4444</title><link>https://ex.test/p</link><description>x</description></item></channel></rss>`})
	g.Write("composer.lock", `{"packages":[],"packages-dev":[{"name":"phpunit/phpunit","version":"10.0.0"}]}`)
	g.Reload()
	g.Run()
	f := g.Findings("CVE-2026-4444")
	if len(f) != 1 || f[0].Env != model.EnvDev {
		t.Fatalf("a dev-only package matters in dev, not in prod: %+v", f)
	}
}

func TestKEVListingSurvivesAnEarlierNVDEntry(t *testing.T) {
	kev := `{"vulnerabilities":[{"cveID":"CVE-2026-5151","vendorProject":"PHP Group","product":"PHP","vulnerabilityName":"PHP RCE",
	"shortDescription":"Bad.","dateAdded":"{{TODAY}}","dueDate":"2026-11-17","requiredAction":"Apply updates.","knownRansomwareCampaignUse":"Unknown"}]}`
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{nvdURL: nvdBody("CVE-2026-5151", "PHP flaw.", "php:php", "8.2.30")})
	g.Run()
	g.Serve(kevURL, kev) // same CVE, same NVD detail URL as the entry above
	g.Run()
	v := g.Ledger.Vuln("CVE-2026-5151")
	if v.KEV == nil || v.KEV.DueDate.Format("2006-01-02") != "2026-11-17" {
		t.Fatalf("a KEV listing after the NVD entry must be recorded: %+v", v.KEV)
	}
}

func TestEPSSIsOptInAndOnlyAsksForTrackedCVEs(t *testing.T) {
	first := "https://api.first.org/data/v1/epss?cve=CVE-2026-6161"
	body := `{"status":"OK","data":[{"cve":"CVE-2026-6161","epss":"0.91","percentile":"0.99","date":"2026-10-27"}]}`
	proj := map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"}
	files := map[string]string{"config/techs.yaml": phpTech, "sources/s.yaml": sources, "config/projects/shop.yaml": proj["shop"]}
	off := testkit.NewRig(t, files, map[string]string{nvdURL: nvdBody("CVE-2026-6161", "PHP flaw.", "php:php", "8.2.30"), first: body})
	off.Run()
	for _, u := range off.Getter.Asked {
		if strings.Contains(u, "first.org") {
			t.Fatal("EPSS must not be contacted unless enabled")
		}
	}

	files["config/config.yaml"] = "enrich: {epss: true}\n"
	on := testkit.NewRig(t, files, map[string]string{nvdURL: nvdBody("CVE-2026-6161", "PHP flaw.", "php:php", "8.2.30"), first: body})
	res := on.Run()
	v := on.Ledger.Vuln("CVE-2026-6161")
	if v.EPSS == nil || v.EPSS.Score != 0.91 || res.Enriched != 1 {
		t.Fatalf("score must be recorded: %+v res=%+v", v.EPSS, res)
	}
}

func TestChannelsAreIndependent(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{nvdURL: nvdBody("CVE-2026-7171", "PHP flaw.", "php:php", "8.2.30")})
	mail := &testkit.Channel{Label: "email", Err: errors.New("smtp down")}
	g.Runner.Channels = append(g.Runner.Channels, pipeline.Delivery{Channel: mail})

	g.Run()
	if g.Channel.Alerts() != 1 || mail.Alerts() != 0 {
		t.Fatalf("slack delivered, email failed: slack=%d email=%d", g.Channel.Alerts(), mail.Alerts())
	}
	mail.Err = nil
	g.Run()
	if g.Channel.Alerts() != 1 || mail.Alerts() != 1 {
		t.Fatalf("the retry must go only to the channel that missed it: slack=%d email=%d", g.Channel.Alerts(), mail.Alerts())
	}
	f := g.Findings("CVE-2026-7171")[0]
	if !f.Delivered("slack") || !f.Delivered("email") {
		t.Fatalf("delivery must be recorded per channel: %+v", f.Alerted)
	}
}

func TestDigestGoesOutOncePerDay(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{nvdURL: nvdBody("CVE-2026-7272", "PHP flaw.", "php:php", "8.2.30")})
	g.Write("config/config.yaml", "notify:\n  digest: {daily_at: '08:00', env: prod}\n")
	g.Reload()

	g.Run() // 12:00, after 08:00: the day's digest
	g.Run() // 13:00, same day
	if len(g.Channel.Digests) != 1 || g.Channel.Digests[0].Open != 1 || g.Channel.Digests[0].Items[0].ID != "CVE-2026-7272" {
		t.Fatalf("one digest per day: %+v", g.Channel.Digests)
	}
	g.Now = g.Now.Add(24 * time.Hour)
	g.Run()
	if len(g.Channel.Digests) != 2 {
		t.Fatalf("a new day brings a new digest: %d", len(g.Channel.Digests))
	}
}

func TestCycleRecordsFeedAndChannelHealth(t *testing.T) {
	g := rig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{nvdURL: nvdBody("CVE-2026-7272", "PHP flaw.", "php:php", "8.2.30"), feedURL: rss})
	g.Getter.Errs = map[string]error{kevURL: errors.New("kev is down")}
	mail := &testkit.Channel{Label: "email", Err: errors.New("smtp down")}
	g.Runner.Channels = append(g.Runner.Channels, pipeline.Delivery{Channel: mail})

	g.Run()
	g.Run()
	cycles, sources, channels, _ := g.Ledger.Health()
	if len(cycles) != 2 || cycles[1].Failed != 1 || cycles[1].Items == 0 {
		t.Fatalf("cycles = %+v", cycles)
	}
	if h := sources["kev"]; h.Failures != 2 || !strings.Contains(h.LastError, "kev is down") || !h.LastSuccess.IsZero() {
		t.Errorf("kev health = %+v", h)
	}
	if h := sources["feed"]; h.Failures != 0 || h.LastSuccess.IsZero() || h.Items != 3 {
		t.Errorf("feed health = %+v", h)
	}
	if h := channels["email"]; h.Failures != 2 || !strings.Contains(h.LastError, "smtp down") {
		t.Errorf("email health = %+v", h)
	}
	if h := channels["slack"]; h.Failures != 0 || h.LastSuccess.IsZero() {
		t.Errorf("slack health = %+v", h)
	}

	mail.Err = nil
	g.Run()
	if _, _, channels, _ = g.Ledger.Health(); channels["email"].Failures != 0 {
		t.Errorf("a success must reset the failure count: %+v", channels["email"])
	}
}
