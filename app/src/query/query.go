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
)

// Filter narrows a listing. Zero values mean no restriction.
type Filter struct {
	Min      model.Severity // hide anything below this severity
	Project  string         // only this project
	Projects []string       // only these projects (access control); empty means all
	All      bool           // include targets whose version is not affected
}

func (f Filter) allows(project string) bool {
	if f.Project != "" && project != f.Project {
		return false
	}
	return len(f.Projects) == 0 || slices.Contains(f.Projects, project)
}

// Target is one project environment affected by an issue.
type Target struct {
	Project string              `json:"project"`
	Env     model.Env           `json:"env"`
	Status  model.Status        `json:"status"`
	Applies model.Applicability `json:"applies"`
	Note    string              `json:"note,omitempty"`
	Matched []string            `json:"matched"`
	Reasons []string            `json:"reasons,omitempty"`
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
	Report       string              `json:"report,omitempty"` // markdown file with the plan
	Targets      []Target            `json:"targets"`
	Untrusted    Untrusted           `json:"untrusted"`
}

// Open returns issues that still have an open finding, most severe first and
// newest last within a severity. Targets hold only open findings, and
// versions known to be unaffected are hidden unless the filter asks for all.
func Open(l *ledger.Ledger, f Filter, now time.Time) []Issue {
	byID := map[string]*Issue{}
	var out []*Issue
	for _, fd := range l.Findings() {
		v := l.Vuln(fd.VulnID)
		if fd.Status != model.StatusOpen || v == nil || !v.Severity.AtLeast(f.Min) || !f.allows(fd.Project) ||
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
		is.Targets = append(is.Targets, target(fd))
		is.Applies = worst(is.Applies, fd.Applies, len(is.Targets) == 1)
	}
	slices.SortStableFunc(out, func(a, b *Issue) int {
		if d := b.Severity.Rank() - a.Severity.Rank(); d != 0 {
			return d
		}
		if c := a.FirstSeen.Compare(b.FirstSeen); c != 0 {
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
			is.Targets = append(is.Targets, target(fd))
			is.Applies = worst(is.Applies, fd.Applies, len(is.Targets) == 1)
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
	return Issue{
		ID: v.ID, Aliases: v.Aliases, Severity: v.Severity, CVSS: v.CVSS, Published: v.Published,
		Age: Age(v.Published, now), AgeHours: int(now.Sub(v.Published).Hours()),
		FirstSeen: v.FirstSeen, Techs: v.Techs, ArticleCount: len(arts), Fix: fix,
		Report: v.ReportPath, Targets: []Target{},
		Untrusted: Untrusted{
			Title: Clip(v.Title, 300), Description: Clip(v.Summary, 600), Articles: arts, Fixes: cleanFixes(v.Fixes),
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

func target(f model.Finding) Target {
	a := f.Applies
	if a == "" {
		a = model.AppUnknown
	}
	return Target{Project: f.Project, Env: f.Env, Status: f.Status, Applies: a, Note: f.Note, Matched: f.Matched, Reasons: f.Reasons}
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
