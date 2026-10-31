package ops

import (
	"slices"
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
		p.events = slices.DeleteFunc(p.events, func(e audit.Event) bool { return !visibleIn(f, &e) })
		for i := range p.events { // a record of several projects names only those in view
			p.events[i].Project = visibleProjects(f, p.events[i].Project)
		}
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

// visibleIn reports whether an audit record concerns no project or one the filter allows.
func visibleIn(f query.Filter, e *audit.Event) bool {
	return e.Project == "" || slices.ContainsFunc(strings.Split(e.Project, ","), f.Allows)
}

// visibleProjects keeps the allowed projects of a record's comma-separated project field.
func visibleProjects(f query.Filter, project string) string {
	var keep []string
	for _, p := range strings.Split(project, ",") {
		if project == "" || f.Allows(p) {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ",")
}
