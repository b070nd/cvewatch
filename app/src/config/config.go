// Package config loads and validates everything under app/config and app/sources.
// It is read again on every run, so edits apply from the next run on.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"cvewatch/src/model"
)

type Settings struct {
	Interval  time.Duration `yaml:"interval"`   // daemon period
	Lookback  time.Duration `yaml:"lookback"`   // how far back a source's first run reaches
	Retention time.Duration `yaml:"retention"`  // forget irrelevant items after this; 0 keeps them
	DataDir   string        `yaml:"data_dir"`   // state lives here
	AlertsDir string        `yaml:"alerts_dir"` // markdown reports land here
	HTTP      HTTP          `yaml:"http"`
	Slack     Slack         `yaml:"slack"`
}

type HTTP struct {
	UserAgent    string             `yaml:"user_agent"`
	Timeout      time.Duration      `yaml:"timeout"`
	Retries      int                `yaml:"retries"`
	RetryDelay   time.Duration      `yaml:"retry_delay"`
	Rate         float64            `yaml:"rate"`       // requests/second per host
	HostRates    map[string]float64 `yaml:"host_rates"` // per-host override
	MaxBody      int64              `yaml:"max_body"`
	Threshold429 int                `yaml:"threshold_429"`
	Cooldown429  time.Duration      `yaml:"cooldown_429"`
	AllowPrivate bool               `yaml:"allow_private"` // permit http and internal addresses (self-hosted feeds, internal proxy)
}

type Slack struct {
	WebhookEnv  string         `yaml:"webhook_env"` // name of the env var holding the webhook URL
	MinSeverity model.Severity `yaml:"min_severity"`
}

// Bundle is the complete, validated configuration.
type Bundle struct {
	Settings
	Root     string
	Techs    []model.Tech
	Sources  []model.Source
	Projects []model.Project
	Warnings []string // non-fatal problems worth logging
}

func defaults() Settings {
	return Settings{
		Interval:  4 * time.Hour,
		Lookback:  7 * 24 * time.Hour,
		Retention: 180 * 24 * time.Hour,
		DataDir:   "../data",
		AlertsDir: "../alerts",
		HTTP: HTTP{
			UserAgent:    "cvewatch/1.0 (internal vulnerability monitor)",
			Timeout:      30 * time.Second,
			Retries:      3,
			RetryDelay:   2 * time.Second,
			Rate:         1,
			MaxBody:      16 << 20,
			Threshold429: 3,
			Cooldown429:  2 * time.Minute,
		},
		Slack: Slack{WebhookEnv: "SLACK_WEBHOOK_URL", MinSeverity: model.SevUnknown},
	}
}

// Load reads root/config/{config,techs}.yaml, root/config/projects/*.yaml and
// root/sources/*.yaml. Unknown keys are errors, so typos never pass silently.
func Load(root string) (*Bundle, error) {
	b := &Bundle{Root: root, Settings: defaults()}

	if err := decode(filepath.Join(root, "config", "config.yaml"), &b.Settings, true); err != nil {
		return nil, err
	}
	b.DataDir = resolve(root, b.DataDir)
	b.AlertsDir = resolve(root, b.AlertsDir)

	var techs struct {
		Techs []model.Tech `yaml:"techs"`
	}
	if err := decode(filepath.Join(root, "config", "techs.yaml"), &techs, false); err != nil {
		return nil, err
	}
	b.Techs = techs.Techs

	err := each(filepath.Join(root, "config", "projects"), func(path string) error {
		var p model.Project
		if err := decode(path, &p, false); err != nil {
			return err
		}
		b.Projects = append(b.Projects, p)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = each(filepath.Join(root, "sources"), func(path string) error {
		var s struct {
			Sources []model.Source `yaml:"sources"`
		}
		if err := decode(path, &s, false); err != nil {
			return err
		}
		b.Sources = append(b.Sources, s.Sources...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return b, b.validate()
}

func (b *Bundle) validate() error {
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	known := map[string]bool{}
	for _, t := range b.Techs {
		key := strings.ToLower(t.Name)
		switch {
		case t.Name == "":
			fail("tech without a name")
		case known[key]:
			fail("duplicate tech %q", t.Name)
		}
		known[key] = true
	}

	names := map[string]bool{}
	for _, p := range b.Projects {
		if p.Name == "" || names[p.Name] {
			fail("project name %q is empty or duplicated", p.Name)
		}
		names[p.Name] = true
		for _, e := range p.Envs {
			if !e.Valid() {
				fail("project %s: unknown env %q (use dev, int, staging, prod)", p.Name, e)
			}
		}
		for _, t := range p.Techs {
			if !known[strings.ToLower(t.Name)] {
				b.Warnings = append(b.Warnings,
					fmt.Sprintf("project %s: tech %q is not in techs.yaml and will never match", p.Name, t.Name))
			}
		}
	}

	ids := map[string]bool{}
	for _, s := range b.Sources {
		if s.ID == "" || s.Type == "" || s.URL == "" || ids[s.ID] {
			fail("source %q needs a unique id, a type and a url", s.ID)
		}
		ids[s.ID] = true
		if err := b.checkURL(s.URL); err != nil {
			fail("source %q: %v", s.ID, err) // never echo the URL: it may hold a token
		}
	}
	if b.Interval <= 0 {
		fail("interval must be positive")
	}
	if b.Retention > 0 && b.Retention < 2*b.Lookback {
		fail("retention must be at least twice the lookback, or old items could be judged again")
	}
	return errors.Join(errs...)
}

var placeholders = strings.NewReplacer("{since}", "x", "{since_unix}", "0", "{since_date}", "x", "{now}", "x")

// checkURL rejects source URLs the HTTP client would refuse anyway, so the
// mistake shows up in `check` rather than on every run.
func (b *Bundle) checkURL(raw string) error {
	u, err := url.Parse(placeholders.Replace(raw))
	switch {
	case err != nil || u.Host == "":
		return errors.New("url is not valid")
	case u.User != nil:
		return errors.New("url must not contain credentials; use headers")
	case u.Scheme != "https" && !(b.HTTP.AllowPrivate && u.Scheme == "http"):
		return errors.New("url must use https (set http.allow_private for internal feeds)")
	}
	return nil
}

// TechNames lists configured tech names, sorted, for display.
func (b *Bundle) TechNames() []string {
	out := make([]string, 0, len(b.Techs))
	for _, t := range b.Techs {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}

func resolve(root, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(root, p))
}

// decode parses strict YAML. A missing file is fine when optional.
func decode(path string, out any, optional bool) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && optional {
		return nil
	}
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// each runs fn for every *.yaml file in dir, in name order. A missing dir is empty.
func each(dir string, fn func(path string) error) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}
