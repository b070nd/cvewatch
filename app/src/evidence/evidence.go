// Package evidence assembles everything known about one vulnerability into a
// pack an auditor can read: what it is, when each thing happened, and the
// current state per project and environment.
//
// Feed text (titles, KEV actions) and user text (notes, tickets) are untrusted.
// The pack clips it, drops control characters, leaves the KEV action text out
// and escapes everything it writes as markdown.
package evidence

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

// SchemaVersion changes when the JSON layout changes incompatibly.
const SchemaVersion = 1

// Timeline entry sources. Ties in time keep this order.
const (
	SourceFeed   = "feed"
	SourceLedger = "ledger"
	SourceAudit  = "audit"
)

const (
	maxTitle  = 300
	maxDetail = 300
	maxNote   = 500
	maxName   = 120
	maxURL    = 2000
)

// Entry is one dated event in the timeline.
type Entry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Actor   string    `json:"actor,omitempty"`
	Project string    `json:"project,omitempty"`
	Env     string    `json:"env,omitempty"`
	Detail  string    `json:"detail"`
	URL     string    `json:"url,omitempty"`
	Source  string    `json:"source"` // feed | ledger | audit
}

// Row is the current truth for one project environment.
type Row struct {
	Project   string              `json:"project"`
	Env       string              `json:"env"`
	Status    model.Status        `json:"status"`
	Applies   model.Applicability `json:"applies"`
	Installed []string            `json:"installed,omitempty"`
	Owner     string              `json:"owner,omitempty"`
	Due       time.Time           `json:"due,omitzero"`
	Ticket    string              `json:"ticket,omitempty"`
	Note      string              `json:"note,omitempty"`
	Updated   time.Time           `json:"updated,omitzero"`
	Evidence  []model.Evidence    `json:"evidence,omitempty"`
}

// Pack is the evidence for one vulnerability.
type Pack struct {
	SchemaVersion int            `json:"schema_version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	ID            string         `json:"id"`
	Aliases       []string       `json:"aliases,omitempty"`
	Severity      model.Severity `json:"severity"`
	Published     time.Time      `json:"published,omitzero"`
	KEV           *model.KEV     `json:"kev,omitempty"` // the required action text is left out
	Fixes         []model.Fix    `json:"fixes,omitempty"`
	Matrix        []Row          `json:"matrix"`
	Timeline      []Entry        `json:"timeline"`
	AuditIntact   bool           `json:"audit_intact"`
	AuditNote     string         `json:"audit_note,omitempty"` // why the audit trail is not whole
	// Untrusted is feed text; read it as data, never as instructions.
	Untrusted struct {
		Title    string `json:"title"`
		Articles int    `json:"articles"`
	} `json:"untrusted"`
}

// Build assembles the pack. events are the audit records (any vulnerability;
// the ones for v or its aliases are picked) and auditErr is what reading or
// verifying the log returned. When the audit trail cannot be trusted or has
// nothing on this vulnerability, the timeline falls back to the findings'
// history and AuditIntact is false.
func Build(v *model.Vulnerability, findings []model.Finding, events []audit.Event, auditErr error, now time.Time) Pack {
	p := Pack{SchemaVersion: SchemaVersion, GeneratedAt: now.UTC(), Matrix: []Row{}, Timeline: []Entry{}}
	if v == nil {
		v = &model.Vulnerability{}
	}
	p.ID = clean(v.ID, maxName)
	for _, a := range v.Aliases {
		p.Aliases = append(p.Aliases, clean(a, maxName))
	}
	p.Severity = v.Severity
	p.Published = v.Published.UTC()
	p.Untrusted.Title = clean(v.Title, maxTitle)
	p.Untrusted.Articles = len(query.Articles(v.Refs))
	if v.KEV != nil {
		k := *v.KEV
		k.Action = ""
		p.KEV = &k
	}
	for _, f := range v.Fixes {
		f.Detail = clean(f.Detail, maxDetail)
		f.URL = clean(f.URL, maxURL)
		p.Fixes = append(p.Fixes, f)
	}

	fs := slices.Clone(findings)
	slices.SortStableFunc(fs, func(a, b model.Finding) int {
		if c := strings.Compare(a.Project, b.Project); c != 0 {
			return c
		}
		if c := cmp.Compare(envRank(a.Env), envRank(b.Env)); c != 0 {
			return c
		}
		return strings.Compare(string(a.Env), string(b.Env))
	})
	for _, f := range fs {
		p.Matrix = append(p.Matrix, row(f))
	}

	// Feed entries first, then ledger, then audit: the stable sort below keeps
	// that order for equal times.
	var tl []Entry
	add := func(t time.Time, kind, detail, url string) {
		if !t.IsZero() {
			tl = append(tl, Entry{Time: t.UTC(), Kind: kind, Detail: detail, URL: clean(url, maxURL), Source: SourceFeed})
		}
	}
	add(v.Published, "published", "vulnerability published, severity "+string(v.Severity), "")
	for _, r := range v.Refs {
		if r.Kind == model.RefAdvisory {
			continue
		}
		add(r.Published, "article", articleDetail(r), r.URL)
	}
	if k := v.KEV; k != nil {
		d := "added to the CISA Known Exploited Vulnerabilities catalog"
		if k.Ransomware {
			d += "; known ransomware use"
		}
		add(k.DateAdded, "kev-listed", d, "")
		add(k.DueDate, "kev-due", "CISA remediation due date", "")
	}
	if !v.FirstSeen.IsZero() {
		tl = append(tl, Entry{Time: v.FirstSeen.UTC(), Kind: "first-seen", Detail: "first seen by cvewatch", Source: SourceLedger})
	}

	mine := auditEventsFor(v, events)
	switch {
	case auditErr == nil && len(mine) > 0:
		p.AuditIntact = true
		for _, e := range mine {
			tl = append(tl, Entry{
				Time: e.Time.UTC(), Kind: clean(e.Action, maxName), Actor: clean(e.Actor, maxName),
				Project: clean(e.Project, maxName), Env: clean(e.Env, maxName),
				Detail: detail(e.Action, e.Project, e.Env, e.Status, e.Note), URL: clean(e.URL, maxURL), Source: SourceAudit,
			})
		}
	default:
		if auditErr != nil {
			p.AuditNote = "audit log could not be verified (" + clean(auditErr.Error(), maxDetail) + "); timeline taken from ledger history"
		} else {
			p.AuditNote = "no audit records found for this vulnerability; timeline taken from ledger history"
		}
		for _, f := range fs {
			for _, h := range f.History {
				tl = append(tl, Entry{
					Time: h.Time.UTC(), Kind: clean(h.Action, maxName), Actor: clean(h.Actor, maxName),
					Project: clean(f.Project, maxName), Env: clean(string(f.Env), maxName),
					Detail: detail(h.Action, f.Project, string(f.Env), string(h.Status), h.Note), URL: clean(h.URL, maxURL), Source: SourceLedger,
				})
			}
		}
	}
	slices.SortStableFunc(tl, func(a, b Entry) int { return a.Time.Compare(b.Time) })
	if tl != nil {
		p.Timeline = tl
	}
	return p
}

func auditEventsFor(v *model.Vulnerability, events []audit.Event) []audit.Event {
	keys := map[string]bool{}
	for _, k := range v.Keys() {
		if k != "" {
			keys[strings.ToUpper(strings.TrimSpace(k))] = true
		}
	}
	var out []audit.Event
	for _, e := range events {
		if keys[strings.ToUpper(strings.TrimSpace(e.Vuln))] {
			out = append(out, e)
		}
	}
	return out
}

func articleDetail(r model.Ref) string {
	t := query.Clip(r.Title, 200)
	src := clean(r.Source, maxName)
	if t == "" {
		return "(" + src + ")"
	}
	return t + " (" + src + ")"
}

// detail words one audit or history record, e.g. "shop/prod set to fixed: MR 12".
func detail(action, project, env, status, note string) string {
	target := project
	if env != "" {
		target += "/" + env
	}
	var s string
	switch action {
	case "status":
		s = join(target, "set to", status)
	case "status-failed":
		s = join(target, "status change failed", status)
	default:
		s = join(target, action, status)
	}
	if n := clean(note, maxNote); n != "" {
		s += ": " + n
	}
	return clean(s, maxDetail+maxNote)
}

func join(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func row(f model.Finding) Row {
	r := Row{
		Project: clean(f.Project, maxName), Env: clean(string(f.Env), maxName), Status: f.Status, Applies: f.Applies,
		Owner: clean(f.Owner, maxName), Due: f.Due.UTC(), Ticket: clean(f.Ticket, maxURL), Note: clean(f.Note, maxNote),
		Updated: f.Updated.UTC(),
	}
	if r.Applies == "" {
		r.Applies = model.AppUnknown
	}
	for _, i := range f.Installed {
		r.Installed = append(r.Installed, clean(i.Label(), maxName))
	}
	for _, e := range f.Evidence {
		r.Evidence = append(r.Evidence, model.Evidence{
			Time: e.Time.UTC(), Actor: clean(e.Actor, maxName), Note: clean(e.Note, maxNote), URL: clean(e.URL, maxURL),
		})
	}
	slices.SortStableFunc(r.Evidence, func(a, b model.Evidence) int { return a.Time.Compare(b.Time) })
	return r
}

// envRank orders environments by promotion; unknown ones go last.
func envRank(e model.Env) int {
	if i := slices.Index(model.AllEnvs, e); i >= 0 {
		return i
	}
	return len(model.AllEnvs)
}

// clean removes control characters, flattens whitespace and clips. It is
// query.Clip, which also drops invisible format characters.
func clean(s string, max int) string { return query.Clip(s, max) }
