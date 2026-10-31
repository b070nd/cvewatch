package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/store"
)

// newRoot builds a folder whose data and alerts stay inside it. files maps a
// path under the root to its content. Notification variables are cleared so
// the developer's environment cannot leak in.
func newRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	for _, v := range []string{"SLACK_WEBHOOK_URL", "CW_HOOK", "CW_HOOK_SECRET", "CW_MAIL_USER", "CW_MAIL_PASS"} {
		t.Setenv(v, "")
	}
	root := t.TempDir()
	put(t, root, "config/config.yaml", "data_dir: data\nalerts_dir: alerts\n"+files["config/config.yaml"])
	delete(files, "config/config.yaml")
	for rel, content := range files {
		put(t, root, rel, content)
	}
	return root
}

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func find(t *testing.T, r Report, group, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Group == group && c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %s: %s in %+v", group, name, r.Checks)
	return Check{}
}

func want(t *testing.T, r Report, group, name string, s Status) Check {
	t.Helper()
	c := find(t, r, group, name)
	if c.Status != s {
		t.Fatalf("%s: %s is %s (%s), want %s", group, name, c.Status, c.Detail, s)
	}
	return c
}

// fakeGetter answers by URL substring and records the URLs asked.
type fakeGetter struct {
	cpe  string // body for CPE lookups
	err  error  // returned for every request when set
	feed string // body for anything else
	urls []string
}

func (f *fakeGetter) Get(_ context.Context, u string, _ model.Validators, _ map[string]string) (*httpx.Response, error) {
	f.urls = append(f.urls, u)
	if f.err != nil {
		return nil, f.err
	}
	if strings.Contains(u, "/cpes/") {
		return &httpx.Response{Body: []byte(f.cpe)}, nil
	}
	return &httpx.Response{Body: []byte(f.feed)}, nil
}

func TestRunMinimalRoot(t *testing.T) {
	root := newRoot(t, nil)
	r := Run(context.Background(), root, Options{})
	if r.Failed() {
		t.Fatalf("minimal root fails: %+v", r.Checks)
	}
	want(t, r, "config", "loads", OK)
	if c := want(t, r, "config", "techs come from", OK); c.Detail != "shipped defaults" {
		t.Errorf("techs detail = %q", c.Detail)
	}
	if c := want(t, r, "config", "sources come from", OK); c.Detail != "shipped defaults" {
		t.Errorf("sources detail = %q", c.Detail)
	}
	want(t, r, "techs", "names", OK)
	want(t, r, "techs", "NVD product names", Skip)
	want(t, r, "state", "data directory", OK)
	want(t, r, "state", "alerts directory", OK)
	want(t, r, "state", "state", OK)
	want(t, r, "audit", "log", OK)
	want(t, r, "notify", "channels", Warn)
	want(t, r, "policy", "rules", Skip)
	ok, warn, fail := r.Counts()
	if ok == 0 || warn == 0 || fail != 0 {
		t.Errorf("counts = %d %d %d", ok, warn, fail)
	}
	// Probe files must not be left behind.
	if m, _ := filepath.Glob(filepath.Join(root, "data", ".doctor-*")); len(m) > 0 {
		t.Errorf("probe files left: %v", m)
	}
}

func TestRunConfigError(t *testing.T) {
	root := newRoot(t, map[string]string{"config/config.yaml": "bogus_key: 1\n"})
	r := Run(context.Background(), root, Options{})
	if len(r.Checks) != 1 || r.Checks[0].Status != Fail || !strings.Contains(r.Checks[0].Detail, "bogus_key") {
		t.Fatalf("checks = %+v", r.Checks)
	}
	if !r.Failed() {
		t.Error("Failed() = false")
	}
}

func TestRunCustomFilesAndWarnings(t *testing.T) {
	root := newRoot(t, map[string]string{
		"config/techs.yaml":      "techs:\n  - {name: php, cpe: [\"php:php\"]}\n",
		"sources/s.yaml":         "sources:\n  - {id: kev, type: kev, url: \"https://example.com/kev.json\", disabled: true}\n",
		"config/projects/a.yaml": "name: a\ntechs:\n  - {name: ghost}\n",
	})
	r := Run(context.Background(), root, Options{})
	if c := find(t, r, "config", "techs come from"); c.Detail != "config/techs.yaml" {
		t.Errorf("techs detail = %q", c.Detail)
	}
	if c := find(t, r, "config", "sources come from"); c.Detail != "sources/*.yaml" {
		t.Errorf("sources detail = %q", c.Detail)
	}
	if c := want(t, r, "config", "warning", Warn); !strings.Contains(c.Detail, "ghost") {
		t.Errorf("warning = %q", c.Detail)
	}
	want(t, r, "sources", "kev", Skip)
}

func TestTypoCPEFails(t *testing.T) {
	root := newRoot(t, map[string]string{"config/techs.yaml": "techs:\n  - {name: php, cpe: [\"php:php:\"]}\n  - {name: go, cpe: [\"Golang:go\"]}\n  - {name: ok, cpe: [\"vendor:product\"]}\n"})
	r := Run(context.Background(), root, Options{})
	if !r.Failed() {
		t.Fatal("typo CPE passed")
	}
	c := want(t, r, "config", "loads", Fail)
	for _, w := range []string{`"php:php:"`, `"Golang:go"`} {
		if !strings.Contains(c.Detail, w) {
			t.Errorf("detail %q misses %s", c.Detail, w)
		}
	}
}

func TestBadSourceTypeFails(t *testing.T) {
	root := newRoot(t, map[string]string{"sources/s.yaml": "sources:\n  - {id: weird, type: carrier-pigeon, url: \"https://example.com/x\"}\n"})
	r := Run(context.Background(), root, Options{})
	if c := want(t, r, "sources", "weird", Fail); !strings.Contains(c.Detail, "carrier-pigeon") {
		t.Errorf("detail = %q", c.Detail)
	}
}

func TestInventoryProblems(t *testing.T) {
	root := newRoot(t, nil)
	req := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(req, []byte("flask==2.0.1\nrequests>=2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	put(t, root, "config/projects/shop.yaml", "name: shop\nenvs: [prod]\ntechs:\n  - {name: php, version: \"8.2\"}\nlockfiles:\n"+
		"  - {type: composer, path: "+quote(filepath.Join(root, "missing.lock"))+"}\n"+
		"  - {type: pip, path: "+quote(req)+"}\n")
	put(t, root, "config/projects/empty.yaml", "name: empty\nenvs: [prod]\n")

	r := Run(context.Background(), root, Options{})
	c := want(t, r, "inventory", "lockfile", Fail)
	if !strings.Contains(c.Detail, "shop: composer") || !strings.Contains(c.Detail, "missing.lock") {
		t.Errorf("lockfile detail = %q", c.Detail)
	}
	c = want(t, r, "inventory", "skipped entries", Warn)
	if !strings.Contains(c.Detail, "1 entries skipped") || !strings.Contains(c.Detail, "requests") {
		t.Errorf("skipped detail = %q", c.Detail)
	}
	if c := want(t, r, "inventory", "shop/prod", OK); c.Detail != "1 techs, 1 packages" {
		t.Errorf("summary = %q", c.Detail)
	}
	want(t, r, "inventory", "empty", Warn)
	for _, c := range r.Checks {
		if c.Name == "empty/prod" {
			t.Error("empty project should not get an ok summary")
		}
	}
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestBusyStateWarns(t *testing.T) {
	root := newRoot(t, nil)
	held, err := store.OpenFile(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	r := Run(context.Background(), root, Options{})
	if c := want(t, r, "state", "state", Warn); !strings.Contains(c.Detail, "daemon") {
		t.Errorf("detail = %q", c.Detail)
	}
	if r.Failed() {
		t.Errorf("busy must not fail: %+v", r.Checks)
	}
}

func TestStateCounts(t *testing.T) {
	root := newRoot(t, nil)
	st, err := store.OpenFile(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := st.Load()
	s.SchemaVersion = 1
	s.Vulns = map[string]*model.Vulnerability{"CVE-1": {ID: "CVE-1"}}
	if err := st.Save(s); err != nil {
		t.Fatal(err)
	}
	st.Close()
	r := Run(context.Background(), root, Options{})
	if c := want(t, r, "state", "state", OK); !strings.Contains(c.Detail, "1 vulnerabilities, 0 findings, schema version 1") {
		t.Errorf("detail = %q", c.Detail)
	}
}

func TestDataDirNotWritable(t *testing.T) {
	root := newRoot(t, nil)
	// A file where the data directory should be cannot be fixed by creating it.
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), root, Options{})
	want(t, r, "state", "data directory", Fail)
	want(t, r, "state", "state", Fail)
}

func TestAuditLog(t *testing.T) {
	root := newRoot(t, nil)
	dir := filepath.Join(root, "data")
	l := audit.Open(dir)
	if err := l.Append(audit.Event{Action: "detected"}, audit.Event{Action: "alerted"}); err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), root, Options{})
	if c := want(t, r, "audit", "log", OK); !strings.Contains(c.Detail, "2 records") {
		t.Errorf("detail = %q", c.Detail)
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	lines := strings.SplitAfter(string(raw), "\n")
	// Drop the first record: the second no longer links to it.
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	r = Run(context.Background(), root, Options{})
	if c := want(t, r, "audit", "log", Fail); !strings.Contains(c.Detail, "audit log damaged") {
		t.Errorf("detail = %q", c.Detail)
	}
	if !r.Failed() {
		t.Error("damaged audit log must fail the run")
	}
}

func TestOnlineCPE(t *testing.T) {
	root := newRoot(t, map[string]string{
		"config/techs.yaml":      "techs:\n  - {name: php, cpe: [\"php:php\"]}\n  - {name: bad, cpe: [\"nope:nothing\"]}\n",
		"sources/s.yaml":         "sources:\n  - {id: kev, type: kev, url: \"https://example.com/kev.json\", disabled: true}\n",
		"config/projects/a.yaml": "name: a\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: bad, version: \"1\"}\n",
	})
	g := &fakeGetter{cpe: `{"totalResults":3}`}
	r := Run(context.Background(), root, Options{Online: true, Getter: g})
	want(t, r, "techs", "php:php", OK)
	want(t, r, "techs", "nope:nothing", OK)
	cpeURLs := slices.DeleteFunc(slices.Clone(g.urls), func(u string) bool { return !strings.Contains(u, "cpeMatchString") })
	if len(cpeURLs) != 2 || !strings.Contains(g.urls[0], "cpeMatchString=cpe:2.3:a:php:php:*") || !strings.Contains(g.urls[0], "resultsPerPage=1") {
		t.Errorf("urls = %v", g.urls)
	}

	g = &fakeGetter{cpe: `{"totalResults":0}`}
	r = Run(context.Background(), root, Options{Online: true, Getter: g})
	if c := want(t, r, "techs", "php:php", Fail); !strings.Contains(c.Detail, "NVD has no product php:php") {
		t.Errorf("detail = %q", c.Detail)
	}
	if !r.Failed() {
		t.Error("unknown product must fail")
	}

	g = &fakeGetter{err: errors.New("connection refused")}
	r = Run(context.Background(), root, Options{Online: true, Getter: g})
	if c := want(t, r, "techs", "php:php", Warn); !strings.Contains(c.Detail, "could not check") {
		t.Errorf("detail = %q", c.Detail)
	}
	if r.Failed() {
		t.Errorf("network trouble must not fail: %+v", r.Checks)
	}

	g = &fakeGetter{cpe: `<html>`}
	r = Run(context.Background(), root, Options{Online: true, Getter: g})
	want(t, r, "techs", "php:php", Warn)
}

func TestOnlineSources(t *testing.T) {
	root := newRoot(t, map[string]string{
		"config/techs.yaml": "techs:\n  - {name: php}\n",
		"sources/s.yaml":    "sources:\n  - {id: kev, type: kev, url: \"https://example.com/kev.json\"}\n",
	})
	g := &fakeGetter{feed: `{"vulnerabilities":[]}`}
	r := Run(context.Background(), root, Options{Online: true, Getter: g})
	if c := want(t, r, "sources", "kev", OK); !strings.Contains(c.Detail, "0 items") {
		t.Errorf("detail = %q", c.Detail)
	}
	own := 0
	for _, u := range g.urls {
		if strings.Contains(u, "example.com") {
			own++
		}
	}
	if own != 1 {
		t.Errorf("urls = %v", g.urls)
	}

	g = &fakeGetter{err: errors.New("boom")}
	r = Run(context.Background(), root, Options{Online: true, Getter: g})
	if c := want(t, r, "sources", "kev", Warn); !strings.Contains(c.Detail, "boom") {
		t.Errorf("detail = %q", c.Detail)
	}
	if r.Failed() {
		t.Error("a failing feed must only warn")
	}

	// Offline runs never touch the getter.
	g = &fakeGetter{}
	Run(context.Background(), root, Options{Getter: g})
	if len(g.urls) != 0 {
		t.Errorf("offline run made requests: %v", g.urls)
	}
}

func TestNotifyChannels(t *testing.T) {
	cfg := "notify:\n  webhook: {url_env: CW_HOOK, secret_env: CW_HOOK_SECRET}\n  email: {host: smtp.example.com, from: a@example.com, to: [b@example.com], password_env: CW_MAIL_PASS}\n  digest: {daily_at: \"08:00\"}\n"
	root := newRoot(t, map[string]string{"config/config.yaml": cfg})

	r := Run(context.Background(), root, Options{})
	want(t, r, "notify", "slack", Skip)
	want(t, r, "notify", "webhook", Skip)
	want(t, r, "notify", "email", OK) // email needs no secret to be valid
	for _, c := range r.Checks {
		if c.Group == "notify" && c.Name == "channels" {
			t.Errorf("email is active, no warning expected: %+v", c)
		}
	}

	t.Setenv("SLACK_WEBHOOK_URL", "http://insecure.example.com/secret-token")
	t.Setenv("CW_HOOK", "https://hooks.example.com/abc123")
	t.Setenv("CW_MAIL_PASS", "hunter2")
	r = Run(context.Background(), root, Options{})
	c := want(t, r, "notify", "slack", Fail)
	if strings.Contains(c.Detail, "secret-token") {
		t.Errorf("secret leaked: %q", c.Detail)
	}
	want(t, r, "notify", "webhook", OK)
	var buf bytes.Buffer
	r.WriteText(&buf)
	_ = r.WriteJSON(&buf)
	for _, secret := range []string{"secret-token", "abc123", "hunter2"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("report leaks %q", secret)
		}
	}
	if !r.Failed() {
		t.Error("an invalid channel must fail")
	}
}

func TestNoChannelWarns(t *testing.T) {
	root := newRoot(t, map[string]string{"config/config.yaml": "notify:\n  digest: {daily_at: \"08:00\"}\n"})
	r := Run(context.Background(), root, Options{})
	if c := want(t, r, "notify", "channels", Warn); !strings.Contains(c.Detail, "nobody is alerted") {
		t.Errorf("detail = %q", c.Detail)
	}
	want(t, r, "notify", "digest", Warn)
	if r.Failed() {
		t.Error("no channel is a warning, not a failure")
	}

	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.example.com/x")
	r = Run(context.Background(), root, Options{})
	want(t, r, "notify", "slack", OK)
	for _, c := range r.Checks {
		if c.Name == "channels" || c.Name == "digest" {
			t.Errorf("unexpected %+v", c)
		}
	}
}

func TestPolicyRules(t *testing.T) {
	root := newRoot(t, map[string]string{"config/config.yaml": "policy:\n  rules:\n    - {name: kev-prod, env: prod, kev: true, owner_within: 24h, fix_within: 168h}\n"})
	r := Run(context.Background(), root, Options{})
	c := want(t, r, "policy", "kev-prod", OK)
	for _, s := range []string{"prod", "KEV", "24h", "168h"} {
		if !strings.Contains(c.Detail, s) {
			t.Errorf("detail %q lacks %q", c.Detail, s)
		}
	}
}

func TestWriteTextAndJSON(t *testing.T) {
	r := Report{Root: "/r", Checks: []Check{
		{Group: "config", Name: "loads", Status: OK, Detail: "fine"},
		{Group: "notify", Name: "slack", Status: Skip},
		{Group: "config", Name: "warning", Status: Warn, Detail: "hmm"},
	}}
	var b bytes.Buffer
	r.WriteText(&b)
	out := b.String()
	for _, s := range []string{"[ok]", "[warn]", "[skip]", "1 ok, 1 warnings, 0 failures", "loads: fine"} {
		if !strings.Contains(out, s) {
			t.Errorf("text lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "Fix the failures") {
		t.Errorf("no failures, no fix sentence:\n%s", out)
	}
	if strings.Index(out, "warning") > strings.Index(out, "notify") {
		t.Errorf("checks must be grouped:\n%s", out)
	}

	r.Checks = append(r.Checks, Check{Group: "audit", Name: "log", Status: Fail, Detail: "bad"})
	b.Reset()
	r.WriteText(&b)
	if !strings.Contains(b.String(), "[FAIL]") || !strings.Contains(b.String(), "Fix the failures above before relying on alerts.") {
		t.Errorf("text:\n%s", b.String())
	}

	b.Reset()
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Root     string
		Failed   bool
		Failures int
		Checks   []Check
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Root != "/r" || !got.Failed || got.Failures != 1 || len(got.Checks) != 4 || got.Checks[3].Status != Fail {
		t.Errorf("json = %+v", got)
	}
}

func TestUpdatesCheckSaysHowProjectsAreKeptUpToDate(t *testing.T) {
	root := newRoot(t, nil)
	put(t, root, "config/projects/shop.yaml", "name: shop\nenvs: [prod]\n")
	put(t, root, "config/projects/blog.yaml", "name: blog\nenvs: [prod]\nupdate: {every: 1h}\n")
	if c := want(t, Run(context.Background(), root, Options{}), "config", "updates", OK); !strings.Contains(c.Detail, "2 projects") {
		t.Errorf("detail = %q", c.Detail)
	}

	put(t, root, "config/projects/blog.yaml", "name: blog\nenvs: [prod]\nupdate: {auto: false}\n")
	if c := want(t, Run(context.Background(), root, Options{}), "config", "updates", Warn); !strings.Contains(c.Detail, "skip blog") || !strings.Contains(c.Detail, "cvewatch update") {
		t.Errorf("detail = %q", c.Detail)
	}

	off := newRoot(t, map[string]string{"config/config.yaml": "update:\n  auto: false\n", "config/projects/shop.yaml": "name: shop\nenvs: [prod]\n"})
	if c := want(t, Run(context.Background(), off, Options{}), "config", "updates", Warn); !strings.Contains(c.Detail, "update.auto is off") {
		t.Errorf("detail = %q", c.Detail)
	}

	none := newRoot(t, nil)
	for _, c := range Run(context.Background(), none, Options{}).Checks {
		if c.Name == "updates" {
			t.Errorf("no projects, nothing to say: %+v", c)
		}
	}
}

func TestAPeriodUnderTheMinimumFailsAndOverThirtyDaysWarns(t *testing.T) {
	root := newRoot(t, nil)
	put(t, root, "config/projects/shop.yaml", "name: shop\nenvs: [prod]\nupdate: {every: 1m}\n")
	r := Run(context.Background(), root, Options{})
	if c := want(t, r, "config", "loads", Fail); !strings.Contains(c.Detail, "shop") || !strings.Contains(c.Detail, "minimum of 5m") {
		t.Errorf("detail = %q", c.Detail)
	}

	root = newRoot(t, nil)
	put(t, root, "config/projects/blog.yaml", "name: blog\nenvs: [prod]\nupdate: {every: 800h}\n")
	r = Run(context.Background(), root, Options{})
	if c := want(t, r, "config", "warning", Warn); !strings.Contains(c.Detail, "blog") || !strings.Contains(c.Detail, "longer than 30 days") {
		t.Errorf("detail = %q", c.Detail)
	}
	if r.Failed() {
		t.Errorf("a long period is no failure: %+v", r.Checks)
	}
}

func TestSourcesCheckSaysWhetherTheTokenVariableIsSetNeverItsValue(t *testing.T) {
	root := newRoot(t, map[string]string{
		"sources/s.yaml": "sources:\n  - {id: ghsa, type: ghsa, url: \"https://example.com/advisories\", auth_env: CVEWATCH_TEST_TOKEN}\n  - {id: other, type: kev, url: \"https://example.com/kev.json\", auth_env: CVEWATCH_TEST_TOKEN, disabled: true}\n",
	})
	t.Setenv("CVEWATCH_TEST_TOKEN", "")
	c := want(t, Run(context.Background(), root, Options{}), "sources", "ghsa", OK)
	if !strings.Contains(c.Detail, "CVEWATCH_TEST_TOKEN not set") {
		t.Errorf("detail = %q", c.Detail)
	}
	t.Setenv("CVEWATCH_TEST_TOKEN", "s3cret-token")
	r := Run(context.Background(), root, Options{})
	c = want(t, r, "sources", "ghsa", OK)
	if !strings.Contains(c.Detail, "CVEWATCH_TEST_TOKEN set") || strings.Contains(c.Detail, "s3cret") {
		t.Errorf("detail = %q", c.Detail)
	}
	if c := want(t, r, "sources", "other", Skip); strings.Contains(c.Detail, "TOKEN") {
		t.Errorf("a disabled source says nothing about its token: %q", c.Detail)
	}
}
