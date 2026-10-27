package pipeline

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
)

const rss = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CVE-2026-1111: PHP-FPM remote code execution</title><link>https://ex.test/a</link><description>Critical bug.</description></item>
<item><title>Weeknight pasta recipes</title><link>https://ex.test/b</link><description>Tasty.</description></item>
<item><title>symfony/http-kernel header injection (CVE-2026-2222)</title><link>https://ex.test/c</link><description>Fixed in 6.4.2.</description></item>
</channel></rss>`

// fakeGetter serves a body per URL, so tests can change what a feed says between runs.
type fakeGetter struct{ bodies map[string]string }

func (g *fakeGetter) Get(_ context.Context, u string, _ model.Validators, _ map[string]string) (*httpx.Response, error) {
	return &httpx.Response{Body: []byte(g.bodies[u])}, nil
}

type fakeNotifier struct{ batches [][]notify.Alert }

func (f *fakeNotifier) Send(_ context.Context, b []notify.Alert) error {
	f.batches = append(f.batches, b)
	return nil
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

type rig struct {
	t    *testing.T
	root string
	l    *ledger.Ledger
	get  *fakeGetter
	n    *fakeNotifier
	r    *Runner
	now  time.Time
}

func newRig(t *testing.T, techs string, projects map[string]string, bodies map[string]string) *rig {
	t.Helper()
	root := t.TempDir()
	write(t, root, "config/techs.yaml", techs)
	write(t, root, "sources/s.yaml", "sources:\n  - {id: feed, type: rss, url: 'https://ex.test/feed'}\n  - {id: nvd, type: nvd, url: 'https://ex.test/nvd'}\n")
	for name, body := range projects {
		write(t, root, "config/projects/"+name+".yaml", body)
	}
	for u, empty := range map[string]string{"https://ex.test/feed": `<rss version="2.0"><channel></channel></rss>`, "https://ex.test/nvd": `{"vulnerabilities":[]}`} {
		if _, ok := bodies[u]; !ok {
			bodies[u] = empty
		}
	}
	g := &rig{t: t, root: root, get: &fakeGetter{bodies}, n: &fakeNotifier{}, l: ledger.New(ledger.State{}),
		now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	g.reload()
	return g
}

// reload re-reads config, as every real cycle does.
func (g *rig) reload() {
	cfg, err := config.Load(g.root)
	if err != nil {
		g.t.Fatal(err)
	}
	g.r = &Runner{Cfg: cfg, Ledger: g.l, Save: func() error { return nil }, Getter: g.get, Notifier: g.n,
		Audit: audit.Open(cfg.DataDir), Now: func() time.Time { return g.now },
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
}

func (g *rig) run() Result {
	g.t.Helper()
	res, err := g.r.Run(context.Background())
	if err != nil {
		g.t.Fatal(err)
	}
	g.now = g.now.Add(time.Hour)
	return res
}

func TestCycle(t *testing.T) {
	root := t.TempDir()
	_ = root
	g := newRig(t, "techs:\n  - name: php\n", map[string]string{"shop": "name: shop\nenvs: [dev, prod]\ntechs: [{name: php, version: '8.2'}]\nlockfiles: [{type: composer, path: composer.lock}]\n",
		"middleware": "name: middleware\nenvs: [prod]\ntechs: [{name: php}]\n"},
		map[string]string{"https://ex.test/feed": rss})
	write(t, g.root, "composer.lock", `{"packages":[{"name":"symfony/http-kernel","version":"v6.4.1"}]}`)
	g.reload()

	res := g.run()
	// php item -> shop dev+prod, middleware prod; symfony item -> shop dev+prod. The recipe is ignored.
	if res.Items != 3 || res.New != 3 || res.Findings != 5 || res.Alerted != 5 {
		t.Fatalf("first run: %+v", res)
	}
	if len(g.n.batches) != 1 || len(g.n.batches[0]) != 2 {
		t.Fatalf("want one batch of two alerts, got %v", g.n.batches)
	}
	if _, err := os.Stat(filepath.Join(g.r.Cfg.AlertsDir, "2026", "2026-10-27-php-cve-2026-1111.md")); err != nil {
		t.Fatalf("report missing: %v", err)
	}

	// Mark a fix, then add a tech that matches the old recipe item.
	if _, err := g.l.SetStatus("CVE-2026-1111", "shop", model.EnvDev, model.StatusFixed, "v8.2.30", g.now); err != nil {
		t.Fatal(err)
	}
	write(t, g.root, "config/techs.yaml", "techs:\n  - name: php\n  - name: pasta\n")
	g.reload()

	res = g.run()
	if res.New != 0 || res.Findings != 0 || res.Alerted != 0 || len(g.n.batches) != 1 {
		t.Fatalf("second run must be quiet and must not re-judge old items: %+v", res)
	}
	for _, f := range g.l.FindingsOf("CVE-2026-1111") {
		if f.Project == "shop" && f.Env == model.EnvDev && f.Status != model.StatusFixed {
			t.Fatal("fix status was reset")
		}
	}
	if n, err := g.r.Audit.Verify(); err != nil || n != 4 { // detected x2, alerted x2
		t.Fatalf("audit: n=%d err=%v", n, err)
	}
}

const sameIssue = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CVE-2026-3333: PHP-FPM remote code execution lets attackers run arbitrary code</title><link>https://ex.test/nvd</link><description>NVD text.</description></item>
<item><title>Critical PHP-FPM remote code execution flaw lets attackers run arbitrary code</title><link>https://ex.test/news</link><description>News article.</description></item>
</channel></rss>`

func TestSameIssueIsAggregated(t *testing.T) {
	g := newRig(t, "techs:\n  - name: php\n", map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php}]\n"},
		map[string]string{"https://ex.test/feed": sameIssue})
	res := g.run()
	if res.Merged != 1 || res.Findings != 1 || len(g.l.Relevant()) != 1 {
		t.Fatalf("want one merged issue with one finding: %+v", res)
	}
	if v := g.l.Relevant()[0]; len(v.Refs) != 2 || v.Refs[0].Kind != model.RefArticle {
		t.Fatalf("both articles must be referenced as articles: %+v", v.Refs)
	}
}

func nvdBody(id, desc, cpe, endExcl string) string {
	return `{"vulnerabilities":[{"cve":{"id":"` + id + `","published":"2026-10-27T00:00:00.000",
	"descriptions":[{"lang":"en","value":"` + desc + `"}],
	"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:` + cpe + `:*:*:*:*:*:*:*:*","versionEndExcluding":"` + endExcl + `"}]}]}],
	"references":[{"url":"https://php.test/release","source":"vendor","tags":["Vendor Advisory"]}]}}]}`
}

const phpTech = "techs:\n  - name: php\n    cpe: [php:php]\n"

func TestLateRangesTurnUnknownIntoAffectedAndAddFix(t *testing.T) {
	news := `<?xml version="1.0"?><rss version="2.0"><channel><item><title>CVE-2026-5555: PHP flaw lets attackers run code</title>
	<link>https://ex.test/news5</link><description>Reported today.</description></item></channel></rss>`
	g := newRig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{"https://ex.test/feed": news})

	g.run()
	f := g.l.FindingsOf("CVE-2026-5555")
	if len(f) != 1 || f[0].Applies != model.AppUnknown {
		t.Fatalf("a news item alone cannot decide the version: %+v", f)
	}

	g.get.bodies["https://ex.test/nvd"] = nvdBody("CVE-2026-5555", "PHP flaw lets attackers run code.", "php:php", "8.2.30")
	res := g.run()
	f = g.l.FindingsOf("CVE-2026-5555")
	if f[0].Applies != model.AppAffected || len(f[0].Reasons) == 0 {
		t.Fatalf("late NVD ranges must update the finding: %+v", f[0])
	}
	if v := g.l.Vuln("CVE-2026-5555"); len(v.Fixes) != 1 || !v.Fixes[0].Official || len(v.Refs) != 2 || res.Findings != 0 {
		t.Fatalf("fix evidence and the second report must be merged, not duplicated: %+v res=%+v", v, res)
	}
}

func TestNotAffectedIsRecordedButNeverAlerted(t *testing.T) {
	g := newRig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.3.1'}]\n"},
		map[string]string{"https://ex.test/nvd": nvdBody("CVE-2026-6666", "PHP flaw.", "php:php", "8.2.30")})
	res := g.run()
	f := g.l.FindingsOf("CVE-2026-6666")
	if len(f) != 1 || f[0].Applies != model.AppNotAffected || res.Alerted != 0 || len(g.n.batches) != 0 {
		t.Fatalf("8.3.1 is outside < 8.2.30: finding kept, nobody alerted: %+v res=%+v", f, res)
	}
}

func TestCPEDataKeepsOtherProductsOut(t *testing.T) {
	g := newRig(t, phpTech, map[string]string{"shop": "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2.10'}]\n"},
		map[string]string{"https://ex.test/nvd": nvdBody("CVE-2026-7777", "Moodle plugin, a PHP application.", "moodle:moodle", "5.0")})
	if res := g.run(); res.Findings != 0 {
		t.Fatalf("an advisory naming Moodle is not about PHP: %+v", res)
	}
}

func TestHostileLinksAreDropped(t *testing.T) {
	for _, u := range []string{"javascript:alert(1)", "https://a.test/x>|<!channel>", "https://a.test/a b", "ftp://a.test/x", "https:///nohost"} {
		if safeURL(u) {
			t.Errorf("%q must be refused", u)
		}
	}
	if !safeURL("https://a.test/path?q=1") {
		t.Error("plain https link refused")
	}
}
