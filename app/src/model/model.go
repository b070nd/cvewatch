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
)

// Severity is ordered; unknown ranks lowest but is never filtered out.
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
}

// Tech is a supported technology. Items are matched on its aliases
// (whole words, case-insensitive); Name is used when no aliases are given.
// An item containing any exclude term is not about this tech, which filters
// advisories that only name it as a platform ("plugin for WordPress ... PHP").
type Tech struct {
	Name     string   `yaml:"name"`
	Aliases  []string `yaml:"aliases"`
	Excludes []string `yaml:"excludes"`
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
}

type ProjectTech struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// Lockfile is read on every run, so the tech matrix follows the repository.
type Lockfile struct {
	Type string `yaml:"type"` // composer | npm
	Path string `yaml:"path"`
}

func (p Project) EffectiveEnvs() []Env {
	if len(p.Envs) == 0 {
		return AllEnvs
	}
	return p.Envs
}

// Package is one dependency read from a lockfile.
type Package struct {
	Name, Version, Ecosystem string
}

// ---- runtime data ----

// Item is a normalized feed entry before deduplication.
type Item struct {
	SourceID  string
	URL       string
	Title     string
	Summary   string   // plain text, no markup
	IDs       []string // CVE / GHSA ids found; first one is the primary
	Packages  []string // structured "name" values from the feed (e.g. GHSA), lowercase
	Published time.Time
	Severity  Severity
	CVSS      float64
	TitleOnly bool // tech matching ignores the summary (set from Source.MatchTitleOnly)
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

// Ref links a vulnerability back to a report.
type Ref struct {
	Source string `json:"source"`
	URL    string `json:"url"`
}

// Vulnerability is the deduplicated record. Techs is frozen at first
// evaluation: later config changes never rewrite history.
type Vulnerability struct {
	ID         string    `json:"id"`
	Aliases    []string  `json:"aliases,omitempty"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	Severity   Severity  `json:"severity"`
	CVSS       float64   `json:"cvss,omitempty"`
	Published  time.Time `json:"published"`
	FirstSeen  time.Time `json:"first_seen"`
	Refs       []Ref     `json:"refs"`
	Techs      []string  `json:"techs,omitempty"` // matched at evaluation time
	ReportPath string    `json:"report_path,omitempty"`
}

func (v *Vulnerability) Keys() []string { return append([]string{v.ID}, v.Aliases...) }

// Finding is one vulnerability affecting one project in one environment.
type Finding struct {
	VulnID    string    `json:"vuln_id"`
	Project   string    `json:"project"`
	Env       Env       `json:"env"`
	Status    Status    `json:"status"`
	Note      string    `json:"note,omitempty"`
	Matched   []string  `json:"matched"` // "php@8.2", "symfony/http-kernel@6.4.1"
	Updated   time.Time `json:"updated"`
	AlertedAt time.Time `json:"alerted_at,omitempty"` // zero until Slack accepted it
}

func (f Finding) Key() string { return f.VulnID + "|" + f.Project + "|" + string(f.Env) }
