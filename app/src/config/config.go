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
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/catalog"
	shipped "github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
)

type Settings struct {
	Interval  time.Duration `yaml:"interval"`   // daemon period
	Lookback  time.Duration `yaml:"lookback"`   // how far back a source's first run reaches
	Retention time.Duration `yaml:"retention"`  // forget irrelevant items after this; 0 keeps them
	DataDir   string        `yaml:"data_dir"`   // state lives here
	AlertsDir string        `yaml:"alerts_dir"` // markdown reports land here
	HTTP      HTTP          `yaml:"http"`
	Slack     Slack         `yaml:"slack"`
	Notify    Notify        `yaml:"notify"`    // channels besides Slack, and the digest
	Policy    Policy        `yaml:"policy"`    // deadlines the report command checks
	Enrich    Enrich        `yaml:"enrich"`    // optional outside lookups
	Storage   Storage       `yaml:"storage"`   // where state lives
	Dashboard Dashboard     `yaml:"dashboard"` // a static status page, refreshed by the daemon
	// Access optionally limits who may see and change which projects, by the
	// actor name (CVEWATCH_ACTOR or the OS user). Empty means everyone may do
	// everything, which is right for a single operator. This is authorization
	// on top of a local identity, not authentication: do not expose the
	// tool to people you cannot identify by other means.
	Access map[string]Grant `yaml:"access"`
}

// Notify configures channels besides Slack. A channel is active when its
// secret environment variable is set, so a config file can be shared safely.
type Notify struct {
	Webhook Webhook `yaml:"webhook"`
	Email   Email   `yaml:"email"`
	Digest  Digest  `yaml:"digest"`
}

type Webhook struct {
	URLEnv       string         `yaml:"url_env"`    // env var holding the https URL
	SecretEnv    string         `yaml:"secret_env"` // env var holding the HMAC secret; optional
	MinSeverity  model.Severity `yaml:"min_severity"`
	AllowPrivate bool           `yaml:"allow_private"` // internal receivers over http
}

type Email struct {
	Host        string         `yaml:"host"` // empty disables email
	Port        int            `yaml:"port"` // default 587
	From        string         `yaml:"from"`
	To          []string       `yaml:"to"`
	UsernameEnv string         `yaml:"username_env"`
	PasswordEnv string         `yaml:"password_env"`
	MinSeverity model.Severity `yaml:"min_severity"`
}

// Digest is a periodic "still open" summary, sent in the first cycle after DailyAt.
type Digest struct {
	DailyAt  string    `yaml:"daily_at"` // local time "08:00"; empty disables
	Env      model.Env `yaml:"env"`      // only findings in this environment; empty means all
	Channels []string  `yaml:"channels"` // slack, webhook, email; empty means all that are active
	Max      int       `yaml:"max"`      // items listed, default 20
}

// Policy lists rules; `cvewatch policy` reports the findings that break them.
type Policy struct {
	Rules []PolicyRule `yaml:"rules"`
}

// PolicyRule says which findings it covers and what must be true within what time.
type PolicyRule struct {
	Name        string         `yaml:"name"`
	Env         model.Env      `yaml:"env"`          // empty means every environment
	KEV         bool           `yaml:"kev"`          // only issues on the CISA KEV list
	MinSeverity model.Severity `yaml:"min_severity"` // only this severe or worse
	OwnerWithin time.Duration  `yaml:"owner_within"` // an owner must be set this long after detection
	FixWithin   time.Duration  `yaml:"fix_within"`   // the finding must be closed this long after detection
}

// Enrich switches on lookups that contact outside services. They are off by
// default because they reveal which CVEs you track.
type Enrich struct {
	EPSS bool `yaml:"epss"` // FIRST EPSS exploit probability for tracked CVEs
}

// Dashboard switches on the static HTML status page. The page lists findings
// and feed errors, so it is written owner-only like every other output.
type Dashboard struct {
	Enabled bool   `yaml:"enabled"` // rewrite the page after every daemon cycle
	File    string `yaml:"file"`    // default: dashboard.html inside alerts_dir
}

// Storage selects the state backend.
type Storage struct {
	Backend string `yaml:"backend"` // file (default) or sqlite
}

// Grant is what one actor may do. "*" in Projects means every project.
type Grant struct {
	Projects []string `yaml:"projects"`
	Write    bool     `yaml:"write"`
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
	Broken   []BrokenProject

	Catalog        *catalog.Catalog // shipped technologies layered with config/techs.yaml
	DefaultTechs   bool             // no config/techs.yaml: only the shipped catalog
	DefaultSources bool             // no sources/*.yaml: only the shipped feeds
}

type BrokenProject struct {
	Name string
	File string
	Err  string
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
			HostRates:    map[string]float64{"raw.githubusercontent.com": 5}, // cve-records fetches one small file per new CVE
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
	return load(root, false)
}

func LoadLenient(root string) (*Bundle, error) {
	return load(root, true)
}

func load(root string, lenient bool) (*Bundle, error) {
	b := &Bundle{Root: root, Settings: defaults()}

	if err := decode(filepath.Join(root, "config", "config.yaml"), &b.Settings, true); err != nil {
		return nil, err
	}
	b.DataDir = resolve(root, b.DataDir)
	b.AlertsDir = resolve(root, b.AlertsDir)

	// The technology catalog and the feed list ship inside the binary. Files
	// in the folder layer on top by name (technologies) or id (feeds): an entry
	// replaces the shipped one, a new one is added, and `disabled: true` removes
	// a shipped one.
	var shippedTechs, userTechs struct {
		Techs []model.Tech `yaml:"techs"`
	}
	if err := decodeBytes("shipped techs.yaml", shipped.Techs(), &shippedTechs); err != nil {
		return nil, err
	}
	techsPath := filepath.Join(root, "config", "techs.yaml")
	if _, err := os.Stat(techsPath); errors.Is(err, os.ErrNotExist) {
		b.DefaultTechs = true
	} else if err := decode(techsPath, &userTechs, false); err != nil {
		return nil, err
	}
	b.Techs = catalog.Merge(shippedTechs.Techs, userTechs.Techs)
	b.Catalog = catalog.New(b.Techs)

	decoded := map[string]bool{}
	err := each(filepath.Join(root, "config", "projects"), func(path string) error {
		var p model.Project
		if err := decode(path, &p, false); err != nil {
			if !lenient {
				return err
			}
			b.Broken = append(b.Broken, brokenProject(path, err))
			return nil
		}
		for i, lf := range p.Lockfiles {
			p.Lockfiles[i].Path = resolve(root, lf.Path) // relative paths follow the app root, not the working directory
		}
		if lenient {
			if errs := projectErrors(p, decoded); len(errs) > 0 {
				b.Broken = append(b.Broken, brokenProject(path, errors.Join(errs...)))
				return nil
			}
		}
		decoded[p.Name] = true
		b.Projects = append(b.Projects, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, br := range b.Broken {
		decoded[br.Name] = true
	}

	var shippedSrc, userSrc struct {
		Sources []model.Source `yaml:"sources"`
	}
	if err := decodeBytes("shipped sources", shipped.Sources(), &shippedSrc); err != nil {
		return nil, err
	}
	err = each(filepath.Join(root, "sources"), func(path string) error {
		var s struct {
			Sources []model.Source `yaml:"sources"`
		}
		if err := decode(path, &s, false); err != nil {
			return err
		}
		userSrc.Sources = append(userSrc.Sources, s.Sources...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	b.DefaultSources = len(userSrc.Sources) == 0
	b.Sources = mergeSources(shippedSrc.Sources, userSrc.Sources)
	b.Sources = b.withTechFeeds(b.Sources)

	return b, b.validate(decoded)
}

func (b *Bundle) validate(decoded map[string]bool) error {
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	for _, err := range b.Catalog.Validate() {
		errs = append(errs, err)
	}
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

	seen := map[string]bool{}
	for _, p := range b.Projects {
		errs = append(errs, projectErrors(p, seen)...)
		b.Warnings = append(b.Warnings, projectWarnings(p, known)...)
	}

	for actor, g := range b.Access {
		for _, name := range g.Projects {
			if name != "*" && !decoded[name] {
				fail("access for %q names unknown project %q", actor, name)
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
	if d := b.Notify.Digest; d.DailyAt != "" {
		if _, err := time.Parse("15:04", d.DailyAt); err != nil {
			fail("notify.digest.daily_at must look like 08:00")
		}
		if d.Env != "" && !d.Env.Valid() {
			fail("notify.digest.env %q is unknown", d.Env)
		}
		for _, c := range d.Channels {
			if !slices.Contains([]string{"slack", "webhook", "email"}, c) {
				fail("notify.digest.channels: unknown channel %q", c)
			}
		}
	}
	for i, r := range b.Policy.Rules {
		switch {
		case r.Name == "":
			fail("policy rule %d needs a name", i+1)
		case r.OwnerWithin <= 0 && r.FixWithin <= 0:
			fail("policy rule %q needs owner_within or fix_within", r.Name)
		case r.Env != "" && !r.Env.Valid():
			fail("policy rule %q: unknown env %q", r.Name, r.Env)
		}
	}
	if !slices.Contains([]string{"", "file", "sqlite"}, b.Storage.Backend) {
		fail("storage.backend must be file or sqlite")
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

func projectErrors(p model.Project, seen map[string]bool) []error {
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if p.Name == "" || seen[p.Name] {
		fail("project name %q is empty or duplicated", p.Name)
	}
	seen[p.Name] = true
	for _, e := range p.Envs {
		if !e.Valid() {
			fail("project %s: unknown env %q (use dev, int, staging, prod)", p.Name, e)
		}
	}
	for _, lf := range p.Lockfiles {
		if !slices.Contains(matrix.Types(), lf.Type) {
			fail("project %s: lockfile type %q is unknown (use %s)", p.Name, lf.Type, strings.Join(matrix.Types(), ", "))
		}
		if lf.Env != "" && !lf.Env.Valid() {
			fail("project %s: lockfile env %q is unknown", p.Name, lf.Env)
		}
	}
	for env := range p.Environments {
		if !env.Valid() {
			fail("project %s: environments: unknown env %q", p.Name, env)
		}
	}
	return errs
}

func projectWarnings(p model.Project, known map[string]bool) []string {
	var warns []string
	if !p.Since.IsZero() && p.Since.After(time.Now()) {
		warns = append(warns, fmt.Sprintf("project %s: since %s is in the future, so every dated vulnerability is skipped for now", p.Name, p.Since.Format("2006-01-02")))
	}
	for env, ec := range p.Environments {
		for tn := range ec.Techs {
			if !known[strings.ToLower(tn)] {
				warns = append(warns, fmt.Sprintf("project %s: environments.%s: tech %q is not in techs.yaml", p.Name, env, tn))
			}
		}
	}
	for _, t := range p.Techs {
		if !known[strings.ToLower(t.Name)] {
			warns = append(warns, fmt.Sprintf("project %s: tech %q is not in techs.yaml and will never match", p.Name, t.Name))
		}
	}
	return warns
}

func brokenProject(path string, err error) BrokenProject {
	file := path
	if abs, aerr := filepath.Abs(path); aerr == nil {
		file = abs
	}
	var lines []string
	for _, l := range strings.Split(err.Error(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return BrokenProject{Name: strings.TrimSuffix(filepath.Base(path), ".yaml"), File: file, Err: strings.Join(lines, "; ")}
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
	return decodeBytes(path, raw, out)
}

func decodeBytes(name string, raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w", name, err)
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

// Allowed lists the projects an actor may see, and whether it may write.
// open is true when no access rules exist, so everything is allowed. A nil
// projects slice with open false means the actor has no access at all.
func (b *Bundle) Allowed(actor string) (projects []string, write, open bool) {
	if len(b.Access) == 0 {
		return nil, true, true
	}
	g, ok := b.Access[actor]
	if !ok {
		return nil, false, false
	}
	if slices.Contains(g.Projects, "*") {
		return nil, g.Write, true
	}
	return g.Projects, g.Write, false
}

// mergeSources layers user feeds over shipped ones by id, in shipped order.
func mergeSources(shipped, user []model.Source) []model.Source {
	out := slices.Clone(shipped)
	for _, u := range user {
		if i := slices.IndexFunc(out, func(s model.Source) bool { return s.ID == u.ID }); i >= 0 {
			out[i] = u
		} else {
			out = append(out, u)
		}
	}
	return out
}

// withTechFeeds adds the vendor feeds of every technology a project runs, so
// enabling a technology enables its advisories. A feed whose id already exists
// (a user override, or a feed shared by several technologies) is left alone.
func (b *Bundle) withTechFeeds(srcs []model.Source) []model.Source {
	used := map[string]bool{}
	for _, p := range b.Projects {
		for _, t := range p.Techs {
			used[strings.ToLower(t.Name)] = true
		}
		for _, ec := range p.Environments {
			for name := range ec.Techs {
				used[strings.ToLower(name)] = true
			}
		}
	}
	for _, t := range b.Techs {
		if !used[strings.ToLower(t.Name)] {
			continue
		}
		for _, f := range t.Feeds {
			if !slices.ContainsFunc(srcs, func(s model.Source) bool { return s.ID == f.ID }) {
				srcs = append(srcs, f)
			}
		}
	}
	return srcs
}

// Client builds the polite HTTP client the settings describe.
func (h HTTP) Client() *httpx.Client {
	return httpx.New(httpx.Options{
		UserAgent: h.UserAgent, Timeout: h.Timeout, Retries: h.Retries, RetryDelay: h.RetryDelay,
		Rate: h.Rate, HostRates: h.HostRates, MaxBody: h.MaxBody,
		Threshold429: h.Threshold429, Cooldown429: h.Cooldown429, AllowPrivate: h.AllowPrivate,
	})
}

// DashboardPath is where the dashboard page is written.
func (b *Bundle) DashboardPath() string {
	if b.Dashboard.File != "" {
		return resolve(b.Root, b.Dashboard.File)
	}
	return filepath.Join(b.AlertsDir, "dashboard.html")
}
