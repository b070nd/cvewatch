// Package config loads and validates everything under app/config and app/sources.
// It is read again on every run, so edits apply from the next run on.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
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
	TUI       TUI           `yaml:"tui"`       // the full-screen interface
	Horizon   Horizon       `yaml:"horizon"`   // which publication dates are judged, alerted and digested
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

// TUI sets the rhythm of the full-screen interface.
type TUI struct {
	Refresh time.Duration `yaml:"refresh"` // how often it re-reads the state; at least 1s
	Fetch   time.Duration `yaml:"fetch"`   // how often it fetches the feeds itself; 0 only on request
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

	projectFiles map[string]string // project name -> the file it was read from

	Catalog        *catalog.Catalog // shipped technologies layered with config/techs.yaml
	DefaultTechs   bool             // no config/techs.yaml: only the shipped catalog
	DefaultSources bool             // no sources/*.yaml: only the shipped feeds
}

type BrokenProject struct {
	Name string
	File string
	Err  string
}

// Defaults are the settings in force when config.yaml says nothing.
func Defaults() Settings {
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
		Slack:   Slack{WebhookEnv: "SLACK_WEBHOOK_URL", MinSeverity: model.SevUnknown},
		TUI:     TUI{Refresh: 30 * time.Second},
		Horizon: Horizon{Window: WindowUnlimited},
	}
}

// LoadTUI reads only the tui section of config.yaml. The interface must start
// when the rest of the configuration is broken, so any problem, or a value
// validation would reject, falls back to the default for that value.
func LoadTUI(root string) TUI {
	t := Defaults().TUI
	raw, err := os.ReadFile(SettingsPath(root))
	if err != nil {
		return t
	}
	var doc struct {
		TUI TUI `yaml:"tui"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return t
	}
	if doc.TUI.Refresh >= time.Second {
		t.Refresh = doc.TUI.Refresh
	}
	if doc.TUI.Fetch > 0 {
		t.Fetch = doc.TUI.Fetch
	}
	return t
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
	b, issues := assemble(root, lenient, nil)
	if b == nil { // a document could not be read or parsed
		return nil, issues[0].err
	}
	return b, joinIssues(issues)
}

func joinIssues(issues []Issue) error {
	errs := make([]error, len(issues))
	for i, is := range issues {
		errs[i] = is.err
	}
	return errors.Join(errs...)
}

// Issue is one thing wrong with the configuration, tied to the document and
// the field when that is known. Field uses dotted yaml keys, with list items by
// position (policy.rules.0.fix_within) or by their key (techs.[name=php].cpe).
type Issue struct {
	File  string // path of the document; empty when the problem spans documents
	Field string // path inside the document; empty when unknown
	Line  int    // 1-based line for syntax and unknown-key errors; 0 when unknown
	Msg   string
	err   error
}

func newIssue(file, field string, err error) Issue {
	return Issue{File: file, Field: field, Msg: err.Error(), err: err}
}

// Overlay replaces files for Check: keys are paths as Load sees them
// (filepath.Join(root, "config", "config.yaml")); a nil value hides the file.
type Overlay map[string][]byte

// Check assembles and validates the configuration with the overlay applied
// instead of the files on disk, collecting every problem it can attribute.
// Broken project files are listed in the bundle, as LoadLenient does. The
// bundle is nil when a document cannot be parsed at all, and then the one
// issue says which.
func Check(root string, over Overlay) (*Bundle, []Issue) {
	clean := Overlay{}
	for p, data := range over {
		clean[filepath.Clean(p)] = data
	}
	b, issues := assemble(root, true, clean)
	if b != nil {
		return b, issues
	}
	return nil, splitDecodeIssue(issues[0])
}

// splitDecodeIssue turns a yaml type error with several lines into one issue
// per line, each with its line number.
func splitDecodeIssue(is Issue) []Issue {
	var de *decodeError
	if !errors.As(is.err, &de) {
		return []Issue{is}
	}
	var te *yaml.TypeError
	if errors.As(de.err, &te) {
		var out []Issue
		for _, m := range te.Errors {
			out = append(out, Issue{File: de.name, Line: lineOf(m), Msg: m, err: de})
		}
		return out
	}
	return []Issue{{File: de.name, Line: lineOf(de.err.Error()), Msg: strings.TrimPrefix(de.err.Error(), "yaml: "), err: de}}
}

var lineRE = regexp.MustCompile(`line (\d+)`)

func lineOf(msg string) int {
	if m := lineRE.FindStringSubmatch(msg); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// Paths of the documents under a root.
func SettingsPath(root string) string { return filepath.Join(root, "config", "config.yaml") }
func TechsPath(root string) string    { return filepath.Join(root, "config", "techs.yaml") }
func SourcesDir(root string) string   { return filepath.Join(root, "sources") }
func ProjectsDir(root string) string  { return filepath.Join(root, "config", "projects") }

// origins remembers which file each merged entry came from, for issues.
type origins struct {
	settings string
	techs    string
	userTech map[string]bool // lowercase names defined in the user's techs.yaml
	projects map[string]string
	sources  map[string]sourceAt
}

type sourceAt struct {
	file  string
	index int
}

func assemble(root string, lenient bool, over Overlay) (*Bundle, []Issue) {
	b := &Bundle{Root: root, Settings: Defaults()}
	fail := func(err error) (*Bundle, []Issue) { return nil, []Issue{newIssue("", "", err)} }
	rd := reader{over}
	og := origins{settings: SettingsPath(root), techs: TechsPath(root), userTech: map[string]bool{},
		projects: map[string]string{}, sources: map[string]sourceAt{}}

	if err := rd.decode(og.settings, &b.Settings, true); err != nil {
		return fail(err)
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
		return fail(err)
	}
	if _, err := rd.read(og.techs); errors.Is(err, os.ErrNotExist) {
		b.DefaultTechs = true
	} else if err := rd.decode(og.techs, &userTechs, false); err != nil {
		return fail(err)
	}
	for _, t := range userTechs.Techs {
		og.userTech[strings.ToLower(t.Name)] = true
	}
	b.Techs = catalog.Merge(shippedTechs.Techs, userTechs.Techs)
	b.Catalog = catalog.New(b.Techs)

	decoded := map[string]bool{}
	err := rd.each(ProjectsDir(root), func(path string) error {
		var p model.Project
		if err := rd.decode(path, &p, false); err != nil {
			if !lenient {
				return err
			}
			b.Broken = append(b.Broken, brokenProject(path, err))
			b.addProjectFile(b.Broken[len(b.Broken)-1].Name, path)
			return nil
		}
		og.projects[p.Name] = path
		for i, lf := range p.Lockfiles {
			p.Lockfiles[i].Path = resolve(root, lf.Path) // relative paths follow the app root, not the working directory
		}
		if lenient {
			if errs := projectErrors(p, decoded); len(errs) > 0 {
				b.Broken = append(b.Broken, brokenProject(path, joinFieldErrs(errs)))
				b.addProjectFile(b.Broken[len(b.Broken)-1].Name, path)
				return nil
			}
		}
		decoded[p.Name] = true
		b.addProjectFile(p.Name, path)
		b.Projects = append(b.Projects, p)
		return nil
	})
	if err != nil {
		return fail(err)
	}
	for _, br := range b.Broken {
		decoded[br.Name] = true
	}

	var shippedSrc, userSrc struct {
		Sources []model.Source `yaml:"sources"`
	}
	if err := decodeBytes("shipped sources", shipped.Sources(), &shippedSrc); err != nil {
		return fail(err)
	}
	err = rd.each(SourcesDir(root), func(path string) error {
		var s struct {
			Sources []model.Source `yaml:"sources"`
		}
		if err := rd.decode(path, &s, false); err != nil {
			return err
		}
		for i, src := range s.Sources {
			og.sources[src.ID] = sourceAt{file: path, index: i}
		}
		userSrc.Sources = append(userSrc.Sources, s.Sources...)
		return nil
	})
	if err != nil {
		return fail(err)
	}
	b.DefaultSources = len(userSrc.Sources) == 0
	b.Sources = mergeSources(shippedSrc.Sources, userSrc.Sources)
	b.Sources = b.withTechFeeds(b.Sources)

	return b, b.validate(decoded, og)
}

func (b *Bundle) validate(decoded map[string]bool, og origins) []Issue {
	var out []Issue
	fail := func(file, field, f string, a ...any) { out = append(out, newIssue(file, field, fmt.Errorf(f, a...))) }

	for _, err := range b.Catalog.Validate() {
		is := newIssue("", "", err)
		var p *catalog.Problem
		if errors.As(err, &p) {
			if p.Tech == "" {
				is.File, is.Field = og.techs, "techs"
			} else if og.userTech[strings.ToLower(p.Tech)] {
				is.File, is.Field = og.techs, "techs.[name="+p.Tech+"]"
				if p.Field != "" {
					is.Field += "." + p.Field
				}
			}
		}
		out = append(out, is)
	}
	known := map[string]bool{}
	for _, t := range b.Techs {
		key := strings.ToLower(t.Name)
		switch {
		case t.Name == "":
			fail(og.techs, "techs", "tech without a name")
		case known[key]:
			fail(og.techs, "techs.[name="+t.Name+"].name", "duplicate tech %q", t.Name)
		}
		known[key] = true
	}

	seen := map[string]bool{}
	for _, p := range b.Projects {
		for _, fe := range projectErrors(p, seen) {
			out = append(out, newIssue(og.projects[p.Name], fe.field, fe.err))
		}
		b.Warnings = append(b.Warnings, projectWarnings(p, known)...)
	}

	for _, actor := range slices.Sorted(maps.Keys(b.Access)) {
		g := b.Access[actor]
		for _, name := range g.Projects {
			if name != "*" && !decoded[name] {
				fail(og.settings, "access."+actor+".projects", "access for %q names unknown project %q", actor, name)
			}
		}
	}

	ids := map[string]bool{}
	for _, s := range b.Sources {
		at, mine := og.sources[s.ID]
		file, base := "", ""
		if mine {
			file, base = at.file, "sources.[id="+s.ID+"]"
			if s.ID == "" {
				base = "sources." + strconv.Itoa(at.index)
			}
		}
		if s.ID == "" || s.Type == "" || s.URL == "" || ids[s.ID] {
			field := ""
			if mine {
				switch {
				case s.ID == "" || ids[s.ID]:
					field = base + ".id"
				case s.Type == "":
					field = base + ".type"
				default:
					field = base + ".url"
				}
			}
			fail(file, field, "source %q needs a unique id, a type and a url", s.ID)
		}
		ids[s.ID] = true
		if err := b.checkURL(s.URL); err != nil {
			field := ""
			if mine {
				field = base + ".url"
			}
			fail(file, field, "source %q: %v", s.ID, err) // never echo the URL: it may hold a token
		}
	}
	if b.Interval <= 0 {
		fail(og.settings, "interval", "interval must be positive")
	}
	if d := b.Notify.Digest; d.DailyAt != "" {
		if _, err := time.Parse("15:04", d.DailyAt); err != nil {
			fail(og.settings, "notify.digest.daily_at", "notify.digest.daily_at must look like 08:00")
		}
		if d.Env != "" && !d.Env.Valid() {
			fail(og.settings, "notify.digest.env", "notify.digest.env %q is not a valid environment name (lowercase letters, digits, - and _)", d.Env)
		}
		for _, c := range d.Channels {
			if !slices.Contains([]string{"slack", "webhook", "email"}, c) {
				fail(og.settings, "notify.digest.channels", "notify.digest.channels: unknown channel %q", c)
			}
		}
	}
	for i, r := range b.Policy.Rules {
		at := "policy.rules." + strconv.Itoa(i)
		switch {
		case r.Name == "":
			fail(og.settings, at+".name", "policy rule %d needs a name", i+1)
		case r.OwnerWithin <= 0 && r.FixWithin <= 0:
			fail(og.settings, at+".fix_within", "policy rule %q needs owner_within or fix_within", r.Name)
		case r.Env != "" && !r.Env.Valid():
			fail(og.settings, at+".env", "policy rule %q: %q is not a valid environment name", r.Name, r.Env)
		}
	}
	if b.TUI.Refresh < time.Second {
		fail(og.settings, "tui.refresh", "tui.refresh must be at least 1s")
	}
	if b.TUI.Fetch < 0 {
		fail(og.settings, "tui.fetch", "tui.fetch must not be negative (0 fetches only on request)")
	}
	for _, hp := range b.Horizon.Problems() {
		fail(og.settings, "horizon."+hp.Field, "%s", hp.Msg)
	}
	if reach := b.Horizon.Reach(time.Now()); reach > b.Lookback && b.Lookback > 0 {
		b.Warnings = append(b.Warnings, fmt.Sprintf("horizon reaches back %s but lookback is %s: sources are only fetched back to the lookback on their first run, so older items are not seen; raise lookback",
			formatSpan(reach), formatSpan(b.Lookback)))
	}
	if !slices.Contains([]string{"", "file", "sqlite"}, b.Storage.Backend) {
		fail(og.settings, "storage.backend", "storage.backend must be file or sqlite")
	}
	if b.Retention > 0 && b.Retention < 2*b.Lookback {
		fail(og.settings, "retention", "retention must be at least twice the lookback, or old items could be judged again")
	}
	return out
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

type fieldErr struct {
	field string
	err   error
}

func joinFieldErrs(fes []fieldErr) error {
	errs := make([]error, len(fes))
	for i, fe := range fes {
		errs[i] = fe.err
	}
	return errors.Join(errs...)
}

func projectErrors(p model.Project, seen map[string]bool) []fieldErr {
	var errs []fieldErr
	fail := func(field, f string, a ...any) { errs = append(errs, fieldErr{field, fmt.Errorf(f, a...)}) }

	if p.Name == "" || seen[p.Name] {
		fail("name", "project name %q is empty or duplicated", p.Name)
	}
	seen[p.Name] = true
	for _, e := range p.Envs {
		if !e.Valid() {
			fail("envs", "project %s: %q is not a valid environment name (lowercase letters, digits, - and _)", p.Name, e)
		}
	}
	for i, lf := range p.Lockfiles {
		at := "lockfiles." + strconv.Itoa(i)
		if !slices.Contains(matrix.Types(), lf.Type) {
			fail(at+".type", "project %s: lockfile type %q is unknown (use %s)", p.Name, lf.Type, strings.Join(matrix.Types(), ", "))
		}
		if lf.Env != "" && !lf.Env.Valid() {
			fail(at+".env", "project %s: lockfile env %q is not a valid environment name", p.Name, lf.Env)
		}
	}
	for _, env := range slices.SortedFunc(maps.Keys(p.Environments), model.EnvCompare) {
		field, where := model.WhenPrefix+string(env), model.WhenPrefix+string(env)
		if p.Environments[env].Old {
			field, where = "environments."+string(env), "environments: "+string(env)
		}
		switch {
		case !env.Valid():
			fail(field, "project %s: %s is not a valid environment name", p.Name, where)
		case !p.Environments[env].Old && !slices.Contains(p.EffectiveEnvs(), env):
			fail(field, "project %s: %s describes an environment that is not in envs; add %s to envs or remove the block", p.Name, field, env)
		}
	}
	for i, t := range p.Techs {
		for _, e := range t.Envs {
			if !e.Valid() {
				fail("techs."+strconv.Itoa(i)+".envs", "project %s: tech %s: %q is not a valid environment name", p.Name, t.Name, e)
			}
		}
	}
	return errs
}

func projectWarnings(p model.Project, known map[string]bool) []string {
	var warns []string
	if !p.Since.IsZero() && p.Since.After(time.Now()) {
		warns = append(warns, fmt.Sprintf("project %s: since %s is in the future, so every dated vulnerability is skipped for now", p.Name, p.Since.Format("2006-01-02")))
	}
	for _, env := range slices.SortedFunc(maps.Keys(p.Environments), model.EnvCompare) {
		where := model.WhenPrefix + string(env)
		if p.Environments[env].Old {
			where = "environments." + string(env)
		}
		for tn := range p.Environments[env].Techs {
			if !known[strings.ToLower(tn)] {
				warns = append(warns, fmt.Sprintf("project %s: %s: tech %q is not in techs.yaml", p.Name, where, tn))
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

func (b *Bundle) addProjectFile(name, path string) {
	if b.projectFiles == nil {
		b.projectFiles = map[string]string{}
	}
	if _, dup := b.projectFiles[name]; !dup { // the first file to claim a name keeps it
		b.projectFiles[name] = path
	}
}

// ProjectFiles maps each project to the file it was read from. A project is
// named by the `name:` its file declares, which need not be the file's name; a
// file that did not load is listed under its file name without .yaml.
func (b *Bundle) ProjectFiles() map[string]string {
	return maps.Clone(b.projectFiles)
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

// reader reads documents from disk, or from an overlay that replaces them.
type reader struct{ over Overlay }

func (r reader) read(path string) ([]byte, error) {
	if data, ok := r.over[filepath.Clean(path)]; ok {
		if data == nil {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}
		return data, nil
	}
	return os.ReadFile(path)
}

// decode parses strict YAML. A missing file is fine when optional.
func (r reader) decode(path string, out any, optional bool) error {
	raw, err := r.read(path)
	if errors.Is(err, os.ErrNotExist) && optional {
		return nil
	}
	if err != nil {
		return err
	}
	return decodeBytes(path, raw, out)
}

// decodeError keeps the document name apart from yaml's own message.
type decodeError struct {
	name string
	err  error
}

func (e *decodeError) Error() string { return e.name + ": " + e.err.Error() }
func (e *decodeError) Unwrap() error { return e.err }

func decodeBytes(name string, raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return &decodeError{name, err}
	}
	return nil
}

// each runs fn for every *.yaml file in dir, in name order. A missing dir is empty.
func (r reader) each(dir string, fn func(path string) error) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	for p, data := range r.over {
		if filepath.Dir(p) == filepath.Clean(dir) && filepath.Ext(p) == ".yaml" && data != nil && !slices.Contains(files, p) {
			files = append(files, p)
		}
	}
	files = slices.DeleteFunc(files, func(f string) bool { data, ok := r.over[filepath.Clean(f)]; return ok && data == nil })
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
	return AllowedBy(b.Access, actor)
}

// AllowedBy is Allowed for a bare list of access rules.
func AllowedBy(access map[string]Grant, actor string) (projects []string, write, open bool) {
	if len(access) == 0 {
		return nil, true, true
	}
	g, ok := access[actor]
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
