package pipeline

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cvewatch/src/audit"
	"cvewatch/src/config"
	"cvewatch/src/httpx"
	"cvewatch/src/model"
	"cvewatch/src/notify"
	"cvewatch/src/store"
)

const rss = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CVE-2026-1111: PHP-FPM remote code execution</title><link>https://ex.test/a</link><description>Critical bug.</description></item>
<item><title>Weeknight pasta recipes</title><link>https://ex.test/b</link><description>Tasty.</description></item>
<item><title>symfony/http-kernel header injection (CVE-2026-2222)</title><link>https://ex.test/c</link><description>Fixed in 6.4.2.</description></item>
</channel></rss>`

type fakeGetter struct{ body string }

func (g fakeGetter) Get(context.Context, string, model.Validators, map[string]string) (*httpx.Response, error) {
	return &httpx.Response{Body: []byte(g.body)}, nil
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

func TestCycle(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config/techs.yaml", "techs:\n  - name: php\n")
	write(t, root, "sources/s.yaml", "sources:\n  - {id: feed, type: rss, url: 'https://ex.test/feed'}\n")
	write(t, root, "composer.lock", `{"packages":[{"name":"symfony/http-kernel","version":"v6.4.1"}]}`)
	write(t, root, "config/projects/shop.yaml",
		"name: shop\nenvs: [dev, prod]\ntechs: [{name: php, version: '8.2'}]\nlockfiles: [{type: composer, path: "+
			filepath.Join(root, "composer.lock")+"}]\n")
	write(t, root, "config/projects/middleware.yaml", "name: middleware\nenvs: [prod]\ntechs: [{name: php}]\n")

	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := &fakeNotifier{}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r := &Runner{Cfg: cfg, Store: st, Getter: fakeGetter{rss}, Notifier: n, Audit: audit.Open(cfg.DataDir), Now: func() time.Time { return now },
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// php item -> shop dev+prod, middleware prod; symfony item -> shop dev+prod. The recipe is ignored.
	if res.Items != 3 || res.New != 3 || res.Findings != 5 || res.Alerted != 5 {
		t.Fatalf("first run: %+v", res)
	}
	if len(n.batches) != 1 || len(n.batches[0]) != 2 {
		t.Fatalf("want one batch of two alerts, got %v", n.batches)
	}
	if _, err := os.Stat(filepath.Join(cfg.AlertsDir, "2026", "2026-10-27-php-cve-2026-1111.md")); err != nil {
		t.Fatalf("report missing: %v", err)
	}

	// Mark one fix applied, then add a tech that matches the old recipe item.
	if _, err := Resolve(st, cfg.AlertsDir, audit.Open(cfg.DataDir), "tester", Change{ID: "cve-2026-1111", Project: "shop", Env: model.EnvDev, Status: model.StatusFixed, Note: "v8.2.30"}, now); err != nil {
		t.Fatal(err)
	}
	write(t, root, "config/techs.yaml", "techs:\n  - name: php\n  - name: pasta\n")
	if cfg, err = config.Load(root); err != nil {
		t.Fatal(err)
	}
	r.Cfg = cfg

	res, err = r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.New != 0 || res.Findings != 0 || res.Alerted != 0 || len(n.batches) != 1 {
		t.Fatalf("second run must be quiet and must not re-judge old items: %+v", res)
	}
	for _, f := range st.FindingsOf("CVE-2026-1111") {
		if f.Project == "shop" && f.Env == model.EnvDev && f.Status != model.StatusFixed {
			t.Fatal("fix status was reset")
		}
	}
	// detected x2, alerted x2, one status change, all in an intact chain
	if n, err := audit.Open(cfg.DataDir).Verify(); err != nil || n != 5 {
		t.Fatalf("audit: n=%d err=%v", n, err)
	}
	body, _ := os.ReadFile(filepath.Join(cfg.AlertsDir, "2026", "2026-10-27-php-cve-2026-1111.md"))
	if !strings.Contains(string(body), "[x] dev") {
		t.Fatalf("report does not show the fix:\n%s", body)
	}
}

const sameIssue = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CVE-2026-3333: PHP-FPM remote code execution lets attackers run arbitrary code</title><link>https://ex.test/nvd</link><description>NVD text.</description></item>
<item><title>Critical PHP-FPM remote code execution flaw lets attackers run arbitrary code</title><link>https://ex.test/news</link><description>News article.</description></item>
</channel></rss>`

func TestSameIssueIsAggregated(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config/techs.yaml", "techs:\n  - name: php\n")
	write(t, root, "sources/s.yaml", "sources:\n  - {id: feed, type: rss, url: 'https://ex.test/feed'}\n")
	write(t, root, "config/projects/shop.yaml", "name: shop\nenvs: [prod]\ntechs: [{name: php}]\n")
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := &Runner{Cfg: cfg, Store: st, Getter: fakeGetter{sameIssue}, Now: time.Now,
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Merged != 1 || res.Findings != 1 || len(st.Relevant()) != 1 {
		t.Fatalf("want one merged issue with one finding: %+v", res)
	}
	if v := st.Relevant()[0]; len(v.Refs) != 2 {
		t.Fatalf("both articles must be referenced: %+v", v.Refs)
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
