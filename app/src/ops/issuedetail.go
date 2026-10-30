package ops

import (
	"slices"
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
	p, err := s.issueParts(id)
	if err != nil {
		return IssueDetail{}, err
	}
	now := s.Now()
	d := query.DetailOf(p.v, p.fs, now)
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
}

func (s *Session) issueParts(id string) (issueParts, error) {
	f, err := s.scope(query.Filter{})
	if err != nil {
		return issueParts{}, err
	}
	is, err := query.One(s.Ledger, id, f, s.Now())
	if err != nil {
		return issueParts{}, err
	}
	p := issueParts{v: s.Ledger.Vuln(is.ID)}
	for _, fd := range s.Ledger.FindingsOf(is.ID) {
		if len(f.Projects) == 0 || slices.Contains(f.Projects, fd.Project) {
			p.fs = append(p.fs, fd)
		}
	}
	p.events, p.aerr = s.Audit.Events()
	if len(f.Projects) > 0 {
		p.events = slices.DeleteFunc(p.events, func(e audit.Event) bool { return !visibleTo(f.Projects, e.Project) })
	}
	return p, nil
}

func (p issueParts) pack(now time.Time) evidence.Pack {
	return evidence.Build(p.v, p.fs, p.events, p.aerr, now)
}
