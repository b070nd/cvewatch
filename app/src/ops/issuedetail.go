package ops

import (
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/evidence"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/report"
)

// IssueDetail is the one view of an issue that `cvewatch show`, the MCP
// server and the terminal page draw from. Detail.History comes from the audit
// trail when it can be trusted, else from the ledger.
type IssueDetail struct {
	query.Detail
	Markdown string // the report, as `cvewatch show` prints it
}

// IssueDetail reads everything known about one issue, for the projects the
// session may see. The id may be an alias.
func (s *Session) IssueDetail(id string) (IssueDetail, error) {
	return s.IssueDetailIn(id, query.Filter{})
}

// IssueDetailIn is IssueDetail for the projects the filter names (project,
// vendor): targets, evidence and history of the others are left out.
func (s *Session) IssueDetailIn(id string, f query.Filter) (IssueDetail, error) {
	p, err := s.issueParts(id, f)
	if err != nil {
		return IssueDetail{}, err
	}
	now := s.Now()
	d := query.DetailIn(p.v, p.fs, p.vendors, now)
	d.History = p.pack(now).History()
	return IssueDetail{Detail: d, Markdown: report.RenderDetail(d)}, nil
}

// issueParts is what one issue is made of, narrowed to the projects the
// session may see.
type issueParts struct {
	v      *model.Vulnerability
	fs     []model.Finding
	events []audit.Event
	aerr   error
	// restricted is set when the session sees only some projects, so the
	// events were narrowed to theirs.
	restricted bool
	vendors    map[string]string
}

func (s *Session) issueParts(id string, f query.Filter) (issueParts, error) {
	f, err := s.scope(f)
	if err != nil {
		return issueParts{}, err
	}
	is, err := query.One(s.Ledger, id, f, s.Now())
	if err != nil {
		return issueParts{}, err
	}
	p := issueParts{v: s.Ledger.Vuln(is.ID), vendors: f.Vendors}
	for _, fd := range s.Ledger.FindingsOf(is.ID) {
		if f.Allows(fd.Project) {
			p.fs = append(p.fs, fd)
		}
	}
	p.events, p.aerr = s.Audit.Events()
	if len(f.Projects) > 0 || f.Project != "" || f.Vendor != "" {
		p.restricted = true
		p.events = narrowEvents(p.events, f)
	}
	return p, nil
}

func (p issueParts) pack(now time.Time) evidence.Pack {
	pk := evidence.Build(p.v, p.fs, p.events, p.aerr, p.restricted, now)
	for i := range pk.Matrix {
		pk.Matrix[i].Vendor = p.vendors[pk.Matrix[i].Project]
	}
	return pk
}

// narrowEvents keeps the records that concern no project or one the filter
// allows, and cuts a record of several projects down to those in view. A record
// made under a name the project had before a rename counts for the project it
// is now, so a reader of the new name sees what was detected under the old one.
func narrowEvents(events []audit.Event, f query.Filter) []audit.Event {
	renames := audit.Renames(events)
	var out []audit.Event
	for i, e := range events {
		if e.Project == "" {
			out = append(out, e)
			continue
		}
		var keep []string
		for _, name := range strings.Split(e.Project, ",") {
			if f.Allows(name) || f.Allows(audit.CurrentName(renames, name, i)) {
				keep = append(keep, name)
			}
		}
		if len(keep) > 0 {
			e.Project = strings.Join(keep, ",")
			out = append(out, e)
		}
	}
	return out
}
