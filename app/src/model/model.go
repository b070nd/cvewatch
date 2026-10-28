// Package model holds the types shared by every other package.
// Configuration types carry yaml tags so one struct serves file and runtime.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Env is a deployment environment. AllEnvs is also the promotion order.
type Env string

const (
	EnvDev     Env = "dev"
	EnvInt     Env = "int"
	EnvStaging Env = "staging"
	EnvProd    Env = "prod"
)

var AllEnvs = []Env{EnvDev, EnvInt, EnvStaging, EnvProd}

func (e Env) Valid() bool {
	for _, v := range AllEnvs {
		if e == v {
			return true
		}
	}
	return false
}

// Status tracks whether the fix for one finding has been dealt with.
type Status string

const (
	StatusOpen    Status = "open"
	StatusFixed   Status = "fixed"
	StatusIgnored Status = "ignored"
	// StatusNotAffected is a human assertion (VEX-style) that the issue does not
	// apply here. It needs a reason. It is separate from the derived
	// Applicability, which comes from version ranges.
	StatusNotAffected Status = "not_affected"
)

// Severity is ordered. Unknown ranks lowest, so once a minimum severity is
// set, unrated items fall below it.
type Severity string

const (
	SevUnknown  Severity = "unknown"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case SevLow:
		return 1
	case SevMedium:
		return 2
	case SevHigh:
		return 3
	case SevCritical:
		return 4
	}
	return 0
}

// AtLeast reports whether s meets a minimum; the zero minimum accepts everything.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

func ParseSeverity(v string) Severity {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "low":
		return SevLow
	case "medium", "moderate":
		return SevMedium
	case "high", "important":
		return SevHigh
	case "critical":
		return SevCritical
	}
	return SevUnknown
}

// SeverityFromCVSS maps a CVSS v3 base score to a severity band.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9:
		return SevCritical
	case score >= 7:
		return SevHigh
	case score >= 4:
		return SevMedium
	case score > 0:
		return SevLow
	}
	return SevUnknown
}

// ---- configuration ----

// Source is one feed to poll (app/sources/*.yaml).
type Source struct {
	ID       string            `yaml:"id"`
	Type     string            `yaml:"type"` // rss | hn | nvd | kev | ghsa
	URL      string            `yaml:"url"`  // may contain {since} (RFC3339) and {since_unix}
	Headers  map[string]string `yaml:"headers"`
	Disabled bool              `yaml:"disabled"`
	// MatchTitleOnly limits tech matching to the title. Use it for firehoses
	// like NVD, whose descriptions mention platforms ("... written in PHP").
	MatchTitleOnly bool `yaml:"match_title_only"`
	// MatchStructured makes a tech that has CPE names match only on the
	// feed's product data. Freshly published NVD entries have none until
	// NVD analyses them; with this set they wait instead of matching on
	// words like "PHP" in the description.
	MatchStructured bool `yaml:"match_structured"`
}

// Tech is a supported technology. Items are matched on its aliases
// (whole words, case-insensitive); Name is used when no aliases are given.
// An item containing any exclude term is not about this tech, which filters
// advisories that only name it as a platform ("plugin for WordPress ... PHP").
//
// CPE lists "vendor:product" names (as in NVD's CPE data, e.g. php:php). When
// an item carries structured CPE data, those names decide the match instead
// of free text, which removes most "mentioned in passing" noise.
type Tech struct {
	Name     string   `yaml:"name"` // short key used in project files: php, fortios
	Aliases  []string `yaml:"aliases"`
	Excludes []string `yaml:"excludes"`
	CPE      []string `yaml:"cpe"`

	// Catalog metadata. Only Name is needed for matching; the rest lets
	// setup offer the technology, recognise it in a repository and attach
	// its vendor's advisory feed.
	Title    string   `yaml:"title"`    // display name: "Fortinet FortiOS"
	Category string   `yaml:"category"` // see package catalog for the values
	Vendor   string   `yaml:"vendor"`
	Source   string   `yaml:"source"`   // open, closed or mixed
	Scheme   string   `yaml:"scheme"`   // version ordering: empty (dotted numbers, semver-like), pypi, maven or go
	Detect   Detect   `yaml:"detect"`   // how to recognise it in a repository
	Feeds    []Source `yaml:"feeds"`    // vendor advisory feeds that switch on with the technology
	Disabled bool     `yaml:"disabled"` // in a user catalog: drop the shipped entry of this name
}

// Detect says how a technology shows up in a repository.
type Detect struct {
	Files    []string      `yaml:"files"`    // marker file names, e.g. wp-config.php
	Images   []string      `yaml:"images"`   // container image names without registry or tag, e.g. postgres
	Packages []PackageHint `yaml:"packages"` // lockfile packages that imply it, e.g. composer magento/product-community-edition
	Versions []VersionHint `yaml:"versions"` // where its version can be read
}

type PackageHint struct {
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
}

type VersionHint struct {
	File    string `yaml:"file"`    // base name, e.g. .nvmrc
	Pattern string `yaml:"pattern"` // regular expression with one capture group holding the version
}

func (t Tech) Terms() []string {
	if len(t.Aliases) > 0 {
		return t.Aliases
	}
	return []string{t.Name}
}

// Project is one monitored system (app/config/projects/*.yaml).
type Project struct {
	Name      string        `yaml:"name"`
	Envs      []Env         `yaml:"envs"` // defaults to AllEnvs
	Techs     []ProjectTech `yaml:"techs"`
	Lockfiles []Lockfile    `yaml:"lockfiles"`
	Since     time.Time     `yaml:"since"` // vulnerabilities published before this day are not checked
	// Environments holds what differs per environment: the runtime versions
	// actually deployed and the image reference. Anything not listed falls
	// back to the project-level techs.
	Environments map[Env]EnvConfig `yaml:"environments"`
}

// EnvConfig is what one environment runs.
type EnvConfig struct {
	Techs map[string]string `yaml:"techs"` // tech name -> deployed version, e.g. php: "8.2.30"
	Image string            `yaml:"image"` // image tag or digest, recorded only; no registry is queried
}

type ProjectTech struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// Lockfile is read on every run, so the tech matrix follows the repository.
type Lockfile struct {
	Type string `yaml:"type"` // see matrix.Types(): composer, npm, go, pip, ...
	Path string `yaml:"path"`
	Env  Env    `yaml:"env"` // applies to this environment only; empty means all
	// Dev includes development-only packages (composer require-dev and the
	// like) in every environment. By default they count only in dev and int.
	Dev bool `yaml:"dev"`
}

func (p Project) EffectiveEnvs() []Env {
	if len(p.Envs) == 0 {
		return AllEnvs
	}
	return p.Envs
}

// Ecosystem names. Feeds, lockfiles and SBOMs all map onto these; see package ecosystem.
const (
	EcoComposer = "composer"
	EcoNPM      = "npm"
	EcoGo       = "go"
	EcoPyPI     = "pypi"
	EcoMaven    = "maven"
	EcoCPE      = "cpe" // product names from NVD, not a package manager
)

// Package is one dependency read from a lockfile or SBOM.
type Package struct {
	Name, Version, Ecosystem string
	Dev                      bool // development-only dependency
}

// ---- affected versions and fixes ----

// Applicability says whether what a project runs falls in the affected range.
type Applicability string

const (
	AppUnknown     Applicability = "unknown" // no usable range or version
	AppAffected    Applicability = "affected"
	AppNotAffected Applicability = "not_affected"
)

// Rank orders urgency: affected, then unknown, then not affected. An empty
// value (older data) counts as unknown.
func (a Applicability) Rank() int {
	switch a {
	case AppAffected:
		return 2
	case AppNotAffected:
		return 0
	}
	return 1
}

// Worse returns the more urgent of two applicabilities.
func (a Applicability) Worse(b Applicability) Applicability {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Range is one span of affected versions. An empty Min or Max means unbounded,
// so the zero Range covers every version. Bounds are inclusive unless flagged.
type Range struct {
	Min     string `json:"min,omitempty"`
	Max     string `json:"max,omitempty"`
	MinExcl bool   `json:"min_excl,omitempty"`
	MaxExcl bool   `json:"max_excl,omitempty"`
}

// Affected is what a feed says is vulnerable: a package (Ecosystem composer,
// npm, ...) or a product (Ecosystem "cpe", Name "vendor:product"), lowercase.
// No Ranges means the feed gave none; the zero Range means all versions.
type Affected struct {
	Ecosystem string  `json:"ecosystem"`
	Name      string  `json:"name"`
	Ranges    []Range `json:"ranges,omitempty"`
	Fixed     string  `json:"fixed,omitempty"` // first patched version, when given
}

// FixKind says what a fix reference is.
type FixKind string

const (
	FixVersion    FixKind = "version"    // a patched version exists
	FixPatch      FixKind = "patch"      // a patch or commit is linked
	FixAdvisory   FixKind = "advisory"   // vendor advisory or release notes
	FixMitigation FixKind = "mitigation" // workaround
	FixAction     FixKind = "action"     // required action (CISA KEV)
)

// Fix is evidence that a remedy exists. Official marks vendor or authority
// sources (reviewed advisories, KEV, NVD "Vendor Advisory"), not news.
type Fix struct {
	Kind     FixKind `json:"kind"`
	Detail   string  `json:"detail,omitempty"` // version number or action text
	URL      string  `json:"url,omitempty"`
	Source   string  `json:"source"` // id of the feed that said so
	Official bool    `json:"official,omitempty"`
}

// Installed is what a project runs that an item matched: a configured
// technology (Via "tech") or a lockfile package (Via "package").
type Installed struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Via       string `json:"via"`
}

func (i Installed) Label() string {
	if i.Version == "" {
		return i.Name
	}
	return i.Name + "@" + i.Version
}

// KEV is CISA's Known Exploited Vulnerabilities catalog entry.
type KEV struct {
	DateAdded  time.Time `json:"date_added,omitempty"`
	DueDate    time.Time `json:"due_date,omitempty"` // CISA's remediation deadline for federal agencies
	Action     string    `json:"action,omitempty"`   // required action, plain text
	Ransomware bool      `json:"ransomware,omitempty"`
}

// EPSS is FIRST's probability that a vulnerability is exploited in the next 30 days.
type EPSS struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	Date       time.Time `json:"date,omitempty"`
}

// ---- runtime data ----

// Item is a normalized feed entry before deduplication.
type Item struct {
	SourceID   string
	SourceType string // the Source.Type that produced it; decides article or advisory
	URL        string
	Title      string
	Summary    string     // plain text, no markup
	IDs        []string   // CVE / GHSA ids found; first one is the primary
	Affected   []Affected // structured affected products and packages, if the feed has them
	Fixes      []Fix      // remedies the feed names
	Published  time.Time
	Severity   Severity
	CVSS       float64
	KEV        *KEV // set by the CISA KEV feed
	TitleOnly  bool // tech matching ignores the summary (set from Source.MatchTitleOnly)
	// StructuredOnly: techs with CPE names ignore text and need product data (Source.MatchStructured).
	StructuredOnly bool
}

// Keys are the identities used for deduplication. Items without any
// advisory id fall back to a hash of their URL.
func (i Item) Keys() []string {
	if len(i.IDs) > 0 {
		return i.IDs
	}
	sum := sha256.Sum256([]byte(canonicalURL(i.URL)))
	return []string{"WEB-" + strings.ToUpper(hex.EncodeToString(sum[:5]))}
}

// Text is what package matching runs against.
func (i Item) Text() string { return i.Title + "\n" + i.Summary }

// TechText is what supported-tech matching runs against.
func (i Item) TechText() string {
	if i.TitleOnly {
		return i.Title
	}
	return i.Text()
}

func canonicalURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawQuery = ""
	u.Host = strings.TrimPrefix(strings.ToLower(u.Host), "www.")
	return strings.TrimRight(u.String(), "/")
}

var idPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b|\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b`)

// ExtractIDs returns advisory ids in text, upper-cased, CVEs first, no duplicates.
func ExtractIDs(text string) []string {
	var cves, others []string
	seen := map[string]bool{}
	for _, m := range idPattern.FindAllString(text, -1) {
		m = strings.ToUpper(m)
		if seen[m] {
			continue
		}
		seen[m] = true
		if strings.HasPrefix(m, "CVE-") {
			cves = append(cves, m)
		} else {
			others = append(others, m)
		}
	}
	return append(cves, others...)
}

// StripIDs removes advisory ids from text, for comparing titles by content.
func StripIDs(s string) string { return idPattern.ReplaceAllString(s, " ") }

// Validators are the HTTP cache validators for conditional GETs.
type Validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// FeedState is what we remember about a source between runs.
type FeedState struct {
	Validators Validators `json:"validators"`
	LastRun    time.Time  `json:"last_run"` // last successful fetch
}

// Ref kinds: news-style reports versus authoritative advisory databases.
const (
	RefArticle  = "article"
	RefAdvisory = "advisory"
)

// RefKind maps a source type to the kind of reference it produces.
func RefKind(sourceType string) string {
	switch sourceType {
	case "rss", "hn":
		return RefArticle
	}
	return RefAdvisory
}

// Ref links a vulnerability back to one report about it.
type Ref struct {
	Source    string    `json:"source"`
	Kind      string    `json:"kind,omitempty"` // RefArticle or RefAdvisory; empty in older data
	URL       string    `json:"url"`
	Title     string    `json:"title,omitempty"`
	Published time.Time `json:"published,omitempty"`
}

// Vulnerability is the deduplicated record. Techs is frozen at first
// evaluation: later config changes never rewrite history.
type Vulnerability struct {
	ID         string     `json:"id"`
	Aliases    []string   `json:"aliases,omitempty"`
	Title      string     `json:"title"`
	Summary    string     `json:"summary"`
	Severity   Severity   `json:"severity"`
	CVSS       float64    `json:"cvss,omitempty"`
	Published  time.Time  `json:"published"`
	FirstSeen  time.Time  `json:"first_seen"`
	Refs       []Ref      `json:"refs"`
	Affected   []Affected `json:"affected,omitempty"`
	Fixes      []Fix      `json:"fixes,omitempty"`
	KEV        *KEV       `json:"kev,omitempty"`
	EPSS       *EPSS      `json:"epss,omitempty"`
	Techs      []string   `json:"techs,omitempty"` // matched at evaluation time
	ReportPath string     `json:"report_path,omitempty"`
}

func (v *Vulnerability) Keys() []string { return append([]string{v.ID}, v.Aliases...) }

// Finding is one vulnerability affecting one project in one environment.
type Finding struct {
	VulnID    string        `json:"vuln_id"`
	Project   string        `json:"project"`
	Env       Env           `json:"env"`
	Status    Status        `json:"status"`
	Note      string        `json:"note,omitempty"`
	Matched   []string      `json:"matched"` // "php@8.2", "symfony/http-kernel@6.4.1"
	Installed []Installed   `json:"installed,omitempty"`
	Applies   Applicability `json:"applies,omitempty"` // whether the installed version is in the affected range
	Reasons   []string      `json:"reasons,omitempty"` // why this finding exists, in plain words
	Updated   time.Time     `json:"updated"`
	AlertedAt time.Time     `json:"alerted_at,omitempty"` // legacy: first delivery; see Alerted

	// Workflow. Owner, Due and Ticket say who handles it and by when; Note is
	// the current reason or remark; Evidence and History keep the trail.
	Owner    string        `json:"owner,omitempty"`
	Due      time.Time     `json:"due,omitempty"`
	Ticket   string        `json:"ticket,omitempty"` // change ticket, merge request or similar link
	Evidence []Evidence    `json:"evidence,omitempty"`
	History  []Disposition `json:"history,omitempty"`
	// Alerted records the delivery per channel ("slack", "webhook", "email"),
	// so one failing channel does not repeat alerts on the others.
	Alerted map[string]time.Time `json:"alerted,omitempty"`
}

// Evidence is a note and link attached to a finding: an advisory, a merge
// request, a change ticket, a deployment record.
type Evidence struct {
	Time  time.Time `json:"time"`
	Actor string    `json:"actor"`
	Note  string    `json:"note,omitempty"`
	URL   string    `json:"url,omitempty"`
}

// Disposition is one entry in a finding's history: what changed, by whom, when.
type Disposition struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"` // status | assign | evidence | inventory
	Status Status    `json:"status,omitempty"`
	Note   string    `json:"note,omitempty"`
	Owner  string    `json:"owner,omitempty"`
	Due    time.Time `json:"due,omitempty"`
	Ticket string    `json:"ticket,omitempty"`
	URL    string    `json:"url,omitempty"`
}

// Delivered reports whether the channel already got this finding. Findings
// delivered before channels existed count as delivered on Slack.
func (f Finding) Delivered(channel string) bool {
	if !f.Alerted[channel].IsZero() {
		return true
	}
	return channel == "slack" && !f.AlertedAt.IsZero()
}

func (f Finding) Key() string { return f.VulnID + "|" + f.Project + "|" + string(f.Env) }

// ---- health of the tool itself ----

// CycleRecord is what one refresh cycle did.
type CycleRecord struct {
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	Items      int       `json:"items"`
	New        int       `json:"new"`
	Merged     int       `json:"merged"`
	Findings   int       `json:"findings"`
	Reconciled int       `json:"reconciled"`
	Alerted    int       `json:"alerted"`
	Digests    int       `json:"digests"`
	Failed     int       `json:"failed_sources"`
	Err        string    `json:"err,omitempty"`
}

// SourceHealth is what we know about one feed's recent attempts.
type SourceHealth struct {
	Type        string    `json:"type,omitempty"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	Failures    int       `json:"failures"` // consecutive failed attempts
	LastError   string    `json:"last_error,omitempty"`
	Items       int       `json:"items"`
}

// ChannelHealth is the same for a notification channel.
type ChannelHealth struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	Failures    int       `json:"failures"`
	LastError   string    `json:"last_error,omitempty"`
}

// Heartbeat is written by the daemon after every cycle, so any other process
// can tell whether it is still alive and when it should run next.
type Heartbeat struct {
	Mode      string        `json:"mode"` // daemon
	Started   time.Time     `json:"started"`
	LastCycle time.Time     `json:"last_cycle"`
	NextRun   time.Time     `json:"next_run"`
	Interval  time.Duration `json:"interval"`
	PID       int           `json:"pid"`
}
