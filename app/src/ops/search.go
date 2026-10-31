package ops

import "github.com/b070nd/cvewatch/app/src/query"

func (s *Session) Search(text string, f query.Filter, openOnly bool) ([]query.Issue, error) {
	q, err := query.ParseSearchAt(text, s.Now())
	if err != nil {
		return nil, err
	}
	f, err = s.scope(f)
	if err != nil {
		return nil, err
	}
	f.All = true
	f.AnyStatus = !openOnly
	var exact, rest []query.Issue
	for _, is := range query.Open(s.Ledger, f, s.Now()) {
		switch {
		case !q.Match(is):
		case q.Exact(is):
			exact = append(exact, is)
		default:
			rest = append(rest, is)
		}
	}
	return append(exact, rest...), nil
}
