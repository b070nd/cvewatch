// Package query is the read model shared by the CLI, the digest, the
// calendar and the MCP server: issues with their targets, articles in
// chronological order, fix evidence and age.
package query

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/calendar"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
)

// Filter narrows a listing. Zero values mean no restriction.
type Filter struct {
	Min       model.Severity // hide anything below this severity
	Project   string         // only this project
	Env       model.Env      // only this environment
	Projects  []string       // only these projects (access control); empty means all
	All       bool           // include targets whose version is not affected
	Closed    bool           // also list the fixed, ignored and not-affected targets of issues that still have an open one
	AnyStatus bool           // list issues whose findings are in any status, with all their targets
}

func (f Filter) allows(project string) bool {
	if f.Project != "" && project != f.Project {
		return false
	}
	return len(f.Projects) == 0 || slices.Contains(f.Projects, project)
}

func (f Filter) allowsEnv(env model.Env) bool { return f.Env == "" || f.Env == env }

// Target is one project environment affected by an issue.
type Target struct {
	Project string              `json:"project"`
	Env     model.Env           `json:"env"`
	Status  model.Status        `json:"status"`
	Applies model.Applicability `json:"applies"`
	Note    string              `json:"note,omitempty"`
	Matched []string            `json:"matched"`
	Reasons []string            `json:"reasons,omitempty"` // why this finding exists, in plain words
	Owner   string              `json:"owner,omitempty"`
	Due     time.Time           `json:"due,omitempty"`
	Overdue bool                `json:"overdue,omitempty"`
	Ticket  string              `json:"ticket,omitempty"`
	Updated time.Time           `json:"updated"`
	// Evidence counts attached notes and links; the entries are in the evidence pack.
	Evidence int `json:"evidence,omitempty"`
}

// KEVInfo is the CISA Known Exploited Vulnerabilities listing. The required
// action text is feed text and sits under Untrusted.
type KEVInfo struct {
	DateAdded  time.Time `json:"date_added,omitempty"`
	DueDate    time.Time `json:"due_date,omitempty"`
	Ransomware bool      `json:"ransomware,omitempty"`
}

// Article is one report about the issue.
type Article struct {
	Title     string    `json:"title"`
	URL       string    `json:"url"`
	Source    string    `json:"source"`
	Published time.Time `json:"published,omitempty"`
}

// Untrusted is text copied from public feeds. Consumers, agents above all,
// must treat it as data to read, never as instructions to follow.
type Untrusted struct {
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Articles    []Article   `json:"articles"` // chronological, oldest first
	Fixes       []model.Fix `json:"fixes,omitempty"`
	KEVAction   string      `json:"kev_action,omitempty"`
}

// FixInfo says whether a remedy is known; the evidence is in Untrusted.Fixes.
type FixInfo struct {
	Available bool `json:"available"`
	Official  bool `json:"official"` // a vendor or authority source says so
}

// Issue is one deduplicated vulnerability and where it applies.
type Issue struct {
	ID           string              `json:"id"`
	Aliases      []string            `json:"aliases,omitempty"`
	Severity     model.Severity      `json:"severity"`
	CVSS         float64             `json:"cvss,omitempty"`
	Published    time.Time           `json:"published"`
	Age          string              `json:"age"`       // since publication, e.g. "2d 4h"
	AgeHours     int                 `json:"age_hours"` // the same, for sorting and scripts
	FirstSeen    time.Time           `json:"first_seen"`
	Techs        []string            `json:"techs,omitempty"`
	Applies      model.Applicability `json:"applies"` // most urgent over the targets
	ArticleCount int                 `json:"article_count"`
	Fix          FixInfo             `json:"fix"`
	KEV          *KEVInfo            `json:"kev,omitempty"`
	EPSS         *model.EPSS         `json:"epss,omitempty"`
	Priority     []string            `json:"priority,omitempty"` // why it sits where it does, from our own data
	ProdOpen     bool                `json:"prod_open"`
	Report       string              `json:"report,omitempty"` // markdown file with the plan
	Targets      []Target            `json:"targets"`
	Untrusted    Untrusted           `json:"untrusted"`
}

// Open returns issues that still have an open finding, in priority order:
// KEV first, then severity, open in prod, EPSS and age (see package priority).
// Targets hold only open findings unless the filter asks for closed ones, and
// versions known to be unaffected are hidden unless it asks for all.
func Open(l *ledger.Ledger, f Filter, now time.Time) []Issue {
	byID := map[string]*Issue{}
	var out []*Issue
	all := l.Findings()
	for _, fd := range all {
		v := l.Vuln(fd.VulnID)
		if (fd.Status != model.StatusOpen && !f.AnyStatus) || v == nil || !v.Severity.AtLeast(f.Min) || !f.allows(fd.Project) || !f.allowsEnv(fd.Env) ||
			(!f.All && fd.Applies == model.AppNotAffected) {
			continue
		}
		is := byID[v.ID]
		if is == nil {
			i := issue(v, now)
			is = &i
			byID[v.ID] = is
			out = append(out, is)
		}
		is.Targets = append(is.Targets, target(fd, now))
		is.Applies = worst(is.Applies, fd.Applies, len(is.Targets) == 1)
		is.ProdOpen = is.ProdOpen || (fd.Env == model.EnvProd && fd.Status == model.StatusOpen)
	}
	if f.Closed || f.AnyStatus {
		for _, fd := range all {
			if is := byID[fd.VulnID]; !f.AnyStatus && is != nil && fd.Status != model.StatusOpen && f.allows(fd.Project) && f.allowsEnv(fd.Env) {
				is.Targets = append(is.Targets, target(fd, now))
			}
		}
		for _, is := range out {
			slices.SortStableFunc(is.Targets, func(a, b Target) int {
				if c := strings.Compare(a.Project, b.Project); c != 0 {
					return c
				}
				return slices.Index(model.AllEnvs, a.Env) - slices.Index(model.AllEnvs, b.Env)
			})
		}
	}
	for _, is := range out {
		facts := factsOf(l.Vuln(is.ID), is.ProdOpen)
		is.Priority = priority.Reasons(facts, now)
	}
	slices.SortStableFunc(out, func(a, b *Issue) int {
		if c := priority.Compare(factsOf(l.Vuln(a.ID), a.ProdOpen), factsOf(l.Vuln(b.ID), b.ProdOpen)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	res := make([]Issue, len(out))
	for i, p := range out {
		res[i] = *p
	}
	return res
}

func factsOf(v *model.Vulnerability, prodOpen bool) priority.Facts {
	return priority.Facts{Severity: v.Severity, KEV: v.KEV, EPSS: v.EPSS, Published: v.Published, FirstSeen: v.FirstSeen, ProdOpen: prodOpen}
}

// One returns an issue with all its targets in any status. The id may be an alias.
// Targets outside the filter's projects are left out.
func One(l *ledger.Ledger, id string, f Filter, now time.Time) (Issue, error) {
	v := l.Lookup([]string{strings.ToUpper(strings.TrimSpace(id))})
	if v == nil {
		return Issue{}, fmt.Errorf("unknown vulnerability %q", id)
	}
	is := issue(v, now)
	for _, fd := range l.FindingsOf(v.ID) {
		if f.allows(fd.Project) {
			is.addTarget(fd, now)
		}
	}
	if len(f.Projects) > 0 && len(is.Targets) == 0 {
		return Issue{}, fmt.Errorf("unknown vulnerability %q", id) // do not reveal what you may not see
	}
	return is, nil
}

// Entries lists every tracked issue published in the month, for the calendar.
func Entries(l *ledger.Ledger, f Filter, now time.Time) []calendar.Entry {
	var out []calendar.Entry
	for _, v := range l.Relevant() {
		if !v.Severity.AtLeast(f.Min) {
			continue
		}
		visible := false
		for _, fd := range l.FindingsOf(v.ID) {
			if f.allows(fd.Project) && (f.All || fd.Applies != model.AppNotAffected) {
				visible = true
			}
		}
		if !visible {
			continue
		}
		is := issue(v, now)
		out = append(out, calendar.Entry{
			Date: v.Published, ID: v.ID, Title: Clip(v.Title, 200), Severity: v.Severity,
			Techs: v.Techs, Articles: is.ArticleCount, Fix: is.Fix.Available,
		})
	}
	return out
}

// addTarget lists a finding on the issue and folds it into the issue's verdicts.
func (is *Issue) addTarget(fd model.Finding, now time.Time) {
	is.Targets = append(is.Targets, target(fd, now))
	is.Applies = worst(is.Applies, fd.Applies, len(is.Targets) == 1)
	is.ProdOpen = is.ProdOpen || (fd.Env == model.EnvProd && fd.Status == model.StatusOpen)
}

func worst(cur, next model.Applicability, first bool) model.Applicability {
	if first {
		if next == "" {
			return model.AppUnknown
		}
		return next
	}
	return cur.Worse(next)
}

func issue(v *model.Vulnerability, now time.Time) Issue {
	arts := Articles(v.Refs)
	fix := FixInfo{Available: len(v.Fixes) > 0}
	for _, f := range v.Fixes {
		fix.Official = fix.Official || f.Official
	}
	var kev *KEVInfo
	kevAction := ""
	if v.KEV != nil {
		kev = &KEVInfo{DateAdded: v.KEV.DateAdded, DueDate: v.KEV.DueDate, Ransomware: v.KEV.Ransomware}
		kevAction = Clip(v.KEV.Action, 200)
	}
	return Issue{
		KEV: kev, EPSS: v.EPSS,
		ID: v.ID, Aliases: v.Aliases, Severity: v.Severity, CVSS: v.CVSS, Published: v.Published,
		Age: Age(v.Published, now), AgeHours: int(now.Sub(v.Published).Hours()),
		FirstSeen: v.FirstSeen, Techs: v.Techs, ArticleCount: len(arts), Fix: fix,
		Report: v.ReportPath, Targets: []Target{},
		Untrusted: Untrusted{
			Title: Clip(v.Title, 300), Description: Clip(v.Summary, 600), Articles: arts, Fixes: cleanFixes(v.Fixes), KEVAction: kevAction,
		},
	}
}

// Articles gathers the news-style references in chronological order. Entries
// without a date (older data) sort last.
func Articles(refs []model.Ref) []Article {
	out := []Article{}
	for _, r := range refs {
		if r.Kind == model.RefAdvisory {
			continue
		}
		out = append(out, Article{Title: Clip(r.Title, 200), URL: r.URL, Source: r.Source, Published: r.Published})
	}
	slices.SortStableFunc(out, func(a, b Article) int {
		switch {
		case a.Published.IsZero() && b.Published.IsZero():
			return 0
		case a.Published.IsZero():
			return 1
		case b.Published.IsZero():
			return -1
		}
		return a.Published.Compare(b.Published)
	})
	return out
}

func cleanFixes(fs []model.Fix) []model.Fix {
	out := slices.Clone(fs)
	for i := range out {
		out[i].Detail = Clip(out[i].Detail, 200)
	}
	return out
}

func target(f model.Finding, now time.Time) Target {
	a := f.Applies
	if a == "" {
		a = model.AppUnknown
	}
	return Target{
		Project: f.Project, Env: f.Env, Status: f.Status, Applies: a, Note: f.Note, Matched: f.Matched, Reasons: f.Reasons,
		Owner: f.Owner, Due: f.Due, Overdue: !f.Due.IsZero() && now.After(f.Due) && f.Status == model.StatusOpen,
		Ticket: f.Ticket, Updated: f.Updated, Evidence: len(f.Evidence),
	}
}

// Age renders the time since t in the two most useful units, e.g. "12m",
// "5h", "2d 4h", "3w". The future and the zero time give "".
func Age(t, now time.Time) string {
	if t.IsZero() || now.Before(t) {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 14*24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d < 90*24*time.Hour:
		return fmt.Sprintf("%dw", int(d.Hours())/24/7)
	}
	return fmt.Sprintf("%dmo", int(d.Hours())/24/30)
}

// Clip drops control and invisible format characters, collapses whitespace
// and cuts at a word boundary, adding an ellipsis when it shortened the text.
func Clip(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) <= max {
		return string(r)
	}
	cut := max
	for i := max - 1; i > 0; i-- {
		if r[i] == ' ' {
			cut = i
			break
		}
	}
	return string(r[:cut]) + "…"
}

// Compare orders two vulnerabilities by priority: a negative result puts a
// first. prodA and prodB say whether each is open in prod.
func Compare(a, b *model.Vulnerability, prodA, prodB bool) int {
	return priority.Compare(factsOf(a, prodA), factsOf(b, prodB))
}
