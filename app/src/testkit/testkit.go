// Package testkit is the shared test rig: a fake feed Getter, a recording
// notification channel, and a Rig that runs real pipeline cycles over a
// temporary configuration folder. Pipeline, ops and the golden harness all
// use it, so there is one fake instead of one per package. Production code
// never imports it.
package testkit

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// Getter serves a body per URL and records what was asked.
type Getter struct {
	mu     sync.Mutex
	Bodies map[string]string
	Errs   map[string]error // a URL listed here fails with this error
	Asked  []string
}

func (g *Getter) Get(_ context.Context, u string, _ model.Validators, _ map[string]string) (*httpx.Response, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Asked = append(g.Asked, u)
	if err, ok := g.Errs[u]; ok {
		return nil, err
	}
	if body, ok := g.Bodies[u]; ok {
		return &httpx.Response{Body: []byte(body)}, nil
	}
	best := ""
	for key := range g.Bodies { // configured URLs may hold {since} style placeholders
		prefix, _, _ := strings.Cut(key, "{")
		if strings.HasPrefix(u, prefix) && len(prefix) > len(best) {
			best = key
		}
	}
	if best != "" {
		return &httpx.Response{Body: []byte(g.Bodies[best])}, nil
	}
	return &httpx.Response{Body: []byte(`{"status":"OK","data":[]}`)}, nil // unknown URLs (EPSS and friends) are empty
}

// Channel records what it is sent, and can be told to fail.
type Channel struct {
	Label   string // channel name; "slack" when empty
	Batches [][]notify.Alert
	Digests []notify.Digest
	Err     error
}

func (c *Channel) Name() string {
	if c.Label == "" {
		return "slack"
	}
	return c.Label
}

func (c *Channel) Send(_ context.Context, b []notify.Alert, _ time.Time) error {
	if c.Err != nil {
		return c.Err
	}
	c.Batches = append(c.Batches, b)
	return nil
}

func (c *Channel) SendDigest(_ context.Context, d notify.Digest, _ time.Time) error {
	if c.Err != nil {
		return c.Err
	}
	c.Digests = append(c.Digests, d)
	return nil
}

// Alerts counts the vulnerabilities delivered so far.
func (c *Channel) Alerts() int {
	n := 0
	for _, b := range c.Batches {
		n += len(b)
	}
	return n
}

// Rig runs real cycles over a temporary root folder.
type Rig struct {
	T       *testing.T
	Root    string
	Ledger  *ledger.Ledger
	Getter  *Getter
	Channel *Channel
	Runner  *pipeline.Runner
	Now     time.Time
}

// NewRig writes files (path relative to the root) and builds a runner on the
// config they form. Missing techs.yaml and sources use the shipped defaults.
// Feeds without a body get an empty valid document of their type.
func NewRig(t *testing.T, files, bodies map[string]string) *Rig {
	t.Helper()
	r := &Rig{T: t, Root: t.TempDir(), Ledger: ledger.New(ledger.State{}), Channel: &Channel{},
		Getter: &Getter{Bodies: map[string]string{}}, Now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	for rel, body := range files {
		r.Write(rel, body)
	}
	for u, b := range bodies {
		r.Getter.Bodies[u] = r.Sub(b)
	}
	r.Reload()
	return r
}

// Write puts a file under the root.
func (r *Rig) Write(rel, body string) {
	r.T.Helper()
	p := filepath.Join(r.Root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.T.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		r.T.Fatal(err)
	}
}

// Reload re-reads the configuration, as every real cycle does, and fills in
// empty feeds for sources that have no body yet.
func (r *Rig) Reload() {
	r.T.Helper()
	cfg, err := config.Load(r.Root)
	if err != nil {
		r.T.Fatal(err)
	}
	for _, src := range cfg.Sources {
		if _, ok := r.Getter.Bodies[src.URL]; !ok {
			r.Getter.Bodies[src.URL] = emptyFeed[src.Type]
		}
	}
	r.Runner = &pipeline.Runner{Cfg: cfg, Ledger: r.Ledger, Save: func() error { return nil }, Getter: r.Getter,
		Channels: []pipeline.Delivery{{Channel: r.Channel}}, Audit: audit.Open(cfg.DataDir),
		Now: func() time.Time { return r.Now }, Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
}

var emptyFeed = map[string]string{
	"rss":  `<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>`,
	"hn":   `{"hits":[]}`,
	"nvd":  `{"vulnerabilities":[]}`,
	"ghsa": `[]`,
	"kev":  `{"vulnerabilities":[]}`,
}

// Run executes one cycle and moves the clock an hour ahead.
func (r *Rig) Run() pipeline.Result {
	r.T.Helper()
	res, err := r.Runner.Run(context.Background())
	if err != nil {
		r.T.Fatal(err)
	}
	r.Now = r.Now.Add(time.Hour)
	return res
}

// Serve replaces what a URL answers, for the next cycle.
func (r *Rig) Serve(url, body string) { r.Getter.Bodies[url] = r.Sub(body) }

// Sub fills dates into a fixture so it stays inside the polling window:
// {{TODAY}} 2026-10-27, {{NVD_NOW}} 2026-10-27T00:00:00.000, {{RFC_NOW}} RFC 3339,
// {{RSS_NOW}} RFC 1123, {{DAYS_AGO:n}} a date n days before today.
func (r *Rig) Sub(s string) string {
	day := time.Date(r.Now.Year(), r.Now.Month(), r.Now.Day(), 0, 0, 0, 0, time.UTC)
	for strings.Contains(s, "{{DAYS_AGO:") {
		i := strings.Index(s, "{{DAYS_AGO:")
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			break
		}
		n := 0
		for _, c := range s[i+len("{{DAYS_AGO:") : i+j] {
			n = n*10 + int(c-'0')
		}
		s = s[:i] + day.AddDate(0, 0, -n).Format("2006-01-02") + s[i+j+2:]
	}
	return strings.NewReplacer(
		"{{TODAY}}", day.Format("2006-01-02"),
		"{{NVD_NOW}}", day.Format("2006-01-02T15:04:05.000"),
		"{{RFC_NOW}}", r.Now.Format(time.RFC3339),
		"{{RSS_NOW}}", r.Now.Format(time.RFC1123Z),
	).Replace(s)
}

// Findings returns the findings of one vulnerability.
func (r *Rig) Findings(id string) []model.Finding { return r.Ledger.FindingsOf(id) }
