package query

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
)

// Link kinds, in the order Detail.Links lists them.
const (
	LinkAdvisory = "advisory"
	LinkFix      = "fix"
	LinkArticle  = "article"
	LinkEvidence = "evidence"
	LinkTicket   = "ticket"
)

// Link is a web address the issue points to. Only plain http(s) addresses
// are listed (see SafeLink), so a link can be opened or copied as it is.
type Link struct {
	Kind   string    `json:"kind"`
	Source string    `json:"source,omitempty"` // the feed, or the project/env that attached it
	Title  string    `json:"title,omitempty"`
	URL    string    `json:"url"`
	Time   time.Time `json:"time,omitzero"`
}

// CVSSText words the score with its version, e.g. "9.8 (v3.1)"; empty without a score.
func (i Issue) CVSSText() string {
	if i.CVSS <= 0 {
		return ""
	}
	s := strconv.FormatFloat(i.CVSS, 'f', 1, 64)
	if i.CVSSVersion != "" {
		s += " (v" + i.CVSSVersion + ")"
	}
	return s
}

// CVSSOrigin words the vector and who scored, e.g. "CVSS:3.1/AV:N/... from nvd"; empty when neither is known.
func (i Issue) CVSSOrigin() string {
	switch {
	case i.CVSSVector != "" && i.CVSSSource != "":
		return i.CVSSVector + " from " + i.CVSSSource
	case i.CVSSVector != "":
		return i.CVSSVector
	case i.CVSSSource != "":
		return "from " + i.CVSSSource
	}
	return ""
}

// SafeLink reports whether raw is a plain http(s) URL with a host and no
// whitespace, control or markup characters: what may be handed to a browser.
func SafeLink(raw string) bool {
	if raw == "" || len(raw) > 2000 || strings.ContainsAny(raw, " \t\r\n<>|\"`\\") || strings.ContainsFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// TargetDetail is what one environment of the issue adds to the Target.
type TargetDetail struct {
	Project   string            `json:"project"`
	Env       model.Env         `json:"env"`
	Installed []model.Installed `json:"installed,omitempty"`
	Evidence  []model.Evidence  `json:"evidence,omitempty"` // in the order attached
}

// HistoryEntry is one thing that happened to the findings of the issue.
type HistoryEntry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Actor   string    `json:"actor,omitempty"`
	Project string    `json:"project,omitempty"`
	Env     string    `json:"env,omitempty"`
	Detail  string    `json:"detail"`
	URL     string    `json:"url,omitempty"`
	Source  string    `json:"source"` // ledger or audit
}

// ActorLabel is how an actor is shown to people: the monitor's own changes,
// made without a person, are marked as automatic.
func ActorLabel(actor string) string {
	if actor == "cvewatch" {
		return "cvewatch (automatic)"
	}
	return actor
}

// Detail is everything shown about one issue: the Issue, which the JSON
// exports carry, and the facts only a full page needs. The markdown report
// and the terminal page both draw from it.
type Detail struct {
	Issue    Issue
	Why      []string       // why it ranks where it does, from our own data
	Targets  []TargetDetail // parallel to Issue.Targets
	Links    []Link         // advisories, fixes, articles, evidence and tickets, without duplicates
	Affected []model.Affected
	History  []HistoryEntry // oldest first; the caller fills it (see package evidence)
}

// DetailOf builds the detail of one vulnerability and the findings to show.
func DetailOf(v *model.Vulnerability, fs []model.Finding, now time.Time) Detail {
	return DetailIn(v, fs, nil, now)
}

// DetailIn is DetailOf with the vendor of each project (see Filter.Vendors).
func DetailIn(v *model.Vulnerability, fs []model.Finding, vendors map[string]string, now time.Time) Detail {
	d := Detail{Issue: issue(v, now), Affected: slices.Clone(v.Affected)}
	for _, fd := range fs {
		d.Issue.addTarget(fd, now, vendors[fd.Project])
		d.Targets = append(d.Targets, TargetDetail{Project: fd.Project, Env: fd.Env, Installed: slices.Clone(fd.Installed), Evidence: slices.Clone(fd.Evidence)})
	}
	d.Why = prodWhere(priority.Reasons(factsOf(v, d.Issue.ProdOpen), now), d.Issue.Targets)
	d.Links = linksOf(v, fs)
	return d
}

// TargetOf is the extra detail of the environment, the zero value for none.
func (d Detail) TargetOf(project string, env model.Env) TargetDetail {
	for _, t := range d.Targets {
		if t.Project == project && t.Env == env {
			return t
		}
	}
	return TargetDetail{Project: project, Env: env}
}

func linksOf(v *model.Vulnerability, fs []model.Finding) []Link {
	var out []Link
	seen := map[string]bool{}
	add := func(l Link) {
		l.URL = strings.TrimSpace(l.URL)
		if !SafeLink(l.URL) || seen[l.URL] {
			return
		}
		seen[l.URL] = true
		out = append(out, l)
	}
	for _, r := range v.Refs {
		if r.Kind == model.RefAdvisory {
			add(Link{Kind: LinkAdvisory, Source: r.Source, Title: Clip(r.Title, 200), URL: r.URL, Time: r.Published})
		}
	}
	for _, f := range v.Fixes {
		add(Link{Kind: LinkFix, Source: f.Source, Title: Clip(string(f.Kind)+" "+f.Detail, 200), URL: f.URL})
	}
	for _, a := range Articles(v.Refs) {
		add(Link{Kind: LinkArticle, Source: a.Source, Title: a.Title, URL: a.URL, Time: a.Published})
	}
	for _, f := range fs {
		where := f.Project + "/" + string(f.Env)
		for _, e := range f.Evidence {
			add(Link{Kind: LinkEvidence, Source: where, Title: Clip(e.Note, 200), URL: e.URL, Time: e.Time})
		}
		add(Link{Kind: LinkTicket, Source: where, Title: "ticket", URL: f.Ticket})
	}
	return out
}

// RangeText words affected version ranges, e.g. ">=6.0, <6.4.5"; a range
// without bounds is every version.
func RangeText(rs []model.Range) string {
	if len(rs) == 0 {
		return "no range given"
	}
	var out []string
	for _, r := range rs {
		var parts []string
		if r.Min != "" {
			op := ">="
			if r.MinExcl {
				op = ">"
			}
			parts = append(parts, op+r.Min)
		}
		if r.Max != "" {
			op := "<="
			if r.MaxExcl {
				op = "<"
			}
			parts = append(parts, op+r.Max)
		}
		if len(parts) == 0 {
			parts = append(parts, "all versions")
		}
		out = append(out, strings.Join(parts, ", "))
	}
	return strings.Join(out, "; ")
}
