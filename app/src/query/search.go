package query

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/model"
)

type Search struct {
	clauses []clause
}

type clause []term

// A term is tested on an issue and one of its targets, so the terms that
// name a project, vendor, environment, status, owner or ticket all hold on the
// same row.
type term struct {
	exclude bool
	plain   string // lower-case text of a plain term, empty for a field term
	test    func(Issue, Target) bool
}

type token struct {
	exclude bool
	field   string
	value   string
	isOr    bool
}

var fieldNames = []string{"id", "severity", "vendor", "project", "env", "owner", "ticket", "tech", "status", "applies", "kev", "fix", "overdue", "after", "before", "published"}

var fieldAliases = map[string]string{"cve": "id", "sev": "severity"}

func ParseSearch(text string) (Search, error) { return ParseSearchAt(text, time.Now()) }

// ParseSearchAt is ParseSearch with the clock a relative published: filter counts back from.
func ParseSearchAt(text string, now time.Time) (Search, error) {
	var s Search
	joined := false
	for _, t := range operators(tokenize(text)) {
		tm, err := compile(t.token, now)
		if err != nil {
			return Search{}, err
		}
		if joined {
			last := len(s.clauses) - 1
			s.clauses[last] = append(s.clauses[last], tm)
		} else {
			s.clauses = append(s.clauses, clause{tm})
		}
		joined = t.orNext
	}
	return s, nil
}

func (s Search) Empty() bool { return len(s.clauses) == 0 }

// Match says whether the issue has a target the query holds on.
func (s Search) Match(is Issue) bool {
	if len(is.Targets) == 0 {
		return s.Row(is, Target{})
	}
	return slices.ContainsFunc(is.Targets, func(t Target) bool { return s.Row(is, t) })
}

// Row says whether the whole query holds on one target of the issue. Pass it
// as Filter.Row to list only the targets the query names.
func (s Search) Row(is Issue, t Target) bool {
	for _, c := range s.clauses {
		if !c.match(is, t) {
			return false
		}
	}
	return true
}

func (s Search) Exact(is Issue) bool {
	for _, c := range s.clauses {
		for _, t := range c {
			if t.plain != "" && !t.exclude && hasID(is, t.plain) {
				return true
			}
		}
	}
	return false
}

func (c clause) match(is Issue, t Target) bool {
	return slices.ContainsFunc(c, func(tm term) bool { return tm.test(is, t) != tm.exclude })
}

type operand struct {
	token
	orNext bool
}

// An OR without a term on both sides stays in the list as an ordinary word.
func operators(toks []token) []operand {
	var out []operand
	for i, t := range toks {
		if t.isOr && i > 0 && i < len(toks)-1 && !toks[i-1].isOr && !toks[i+1].isOr {
			out[len(out)-1].orNext = true
			continue
		}
		out = append(out, operand{token: t})
	}
	return out
}

func tokenize(text string) []token {
	var out []token
	runes := []rune(text)
	for i := 0; i < len(runes); {
		if unicode.IsSpace(runes[i]) {
			i++
			continue
		}
		var t token
		if runes[i] == '-' && i+1 < len(runes) && !unicode.IsSpace(runes[i+1]) {
			t.exclude = true
			i++
		}
		t, i = readWord(runes, i, t)
		if t.field != "" || t.value != "" || t.isOr {
			out = append(out, t)
		}
	}
	return out
}

func readWord(runes []rune, i int, t token) (token, int) {
	var word strings.Builder
	inQuote, quoted := false, false
	for ; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '"':
			inQuote, quoted = !inQuote, true
		case unicode.IsSpace(r) && !inQuote:
			return finishWord(t, word.String(), quoted), i
		case r == ':' && !inQuote && !quoted && t.field == "" && isLetters(word.String()):
			t.field = strings.ToLower(word.String())
			word.Reset()
		default:
			word.WriteRune(r)
		}
	}
	return finishWord(t, word.String(), quoted), i
}

func finishWord(t token, word string, quoted bool) token {
	t.value = word
	t.isOr = word == "OR" && !quoted && !t.exclude && t.field == ""
	return t
}

func isLetters(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsLetter(r) }) < 0
}

func compile(t token, now time.Time) (term, error) {
	if t.field == "" {
		return term{exclude: t.exclude, plain: strings.ToLower(t.value), test: containing(strings.ToLower(t.value))}, nil
	}
	test, err := fieldTest(t.field, t.value, now)
	return term{exclude: t.exclude, test: test}, err
}

func containing(text string) func(Issue, Target) bool {
	return func(is Issue, t Target) bool { return strings.Contains(haystack(is, t), text) }
}

func haystack(is Issue, t Target) string {
	parts := []string{is.ID, is.Untrusted.Title, is.Untrusted.Description}
	parts = append(parts, is.Aliases...)
	parts = append(parts, is.Techs...)
	parts = append(parts, t.Vendor, t.Project, string(t.Env), t.Owner, t.Ticket)
	parts = append(parts, t.Matched...)
	return strings.ToLower(strings.Join(parts, "\n"))
}

func fieldTest(field, value string, now time.Time) (func(Issue, Target) bool, error) {
	if canonical, ok := fieldAliases[field]; ok {
		field = canonical
	}
	if !slices.Contains(fieldNames, field) {
		return nil, fmt.Errorf("unknown field %q; use one of: %s", field, strings.Join(fieldNames, ", "))
	}
	var alternatives []func(Issue, Target) bool
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("missing value after %s:", field)
		}
		test, err := valueTest(field, v, now)
		if err != nil {
			return nil, err
		}
		alternatives = append(alternatives, test)
	}
	return func(is Issue, t Target) bool {
		for _, test := range alternatives {
			if test(is, t) {
				return true
			}
		}
		return false
	}, nil
}

func valueTest(field, v string, now time.Time) (func(Issue, Target) bool, error) {
	switch field {
	case "id":
		return ofIssue(idTest(v)), nil
	case "severity":
		test, err := severityTest(v)
		return ofIssue(test), err
	case "vendor":
		if v != model.NoVendor && !model.ValidVendor(strings.ToLower(v)) {
			return nil, fmt.Errorf("unknown vendor %q; use a lowercase name such as acme, or %s for projects without one", v, model.NoVendor)
		}
		return targetTest(func(t Target) bool { return strings.EqualFold(model.VendorLabel(t.Vendor), v) }), nil
	case "project":
		return targetTest(func(t Target) bool { return strings.EqualFold(t.Project, v) }), nil
	case "owner":
		return targetTest(func(t Target) bool { return strings.EqualFold(t.Owner, v) }), nil
	case "ticket":
		return targetTest(func(t Target) bool { return strings.EqualFold(t.Ticket, v) }), nil
	case "tech":
		return ofIssue(func(is Issue) bool {
			return slices.ContainsFunc(is.Techs, func(tech string) bool { return strings.EqualFold(tech, v) })
		}), nil
	case "env":
		env := model.Env(strings.ToLower(v))
		if !env.Valid() {
			return nil, fmt.Errorf("unknown environment %q; use a lowercase name such as local, dev or prod", v)
		}
		return targetTest(func(t Target) bool { return t.Env == env }), nil
	case "status":
		status, err := parseEnum("status", v, []model.Status{model.StatusOpen, model.StatusFixed, model.StatusIgnored, model.StatusNotAffected})
		return targetTest(func(t Target) bool { return t.Status == status }), err
	case "applies":
		applies, err := parseEnum("applicability", v, []model.Applicability{model.AppAffected, model.AppUnknown, model.AppNotAffected})
		return targetTest(func(t Target) bool { return t.Applies == applies }), err
	case "kev":
		return yesNoTest(field, v, func(is Issue, _ Target) bool { return is.KEV != nil })
	case "overdue":
		return yesNoTest(field, v, func(_ Issue, t Target) bool { return t.Overdue })
	case "fix":
		test, err := fixTest(v)
		return ofIssue(test), err
	case "published":
		test, err := publishedTest(v, now)
		return ofIssue(test), err
	}
	test, err := dateTest(field, v)
	return ofIssue(test), err
}

// ofIssue is a test of the issue alone, the same on every target.
func ofIssue(test func(Issue) bool) func(Issue, Target) bool {
	if test == nil {
		return nil
	}
	return func(is Issue, _ Target) bool { return test(is) }
}

func keys(is Issue) []string { return append([]string{is.ID}, is.Aliases...) }

func hasID(is Issue, id string) bool {
	return slices.ContainsFunc(keys(is), func(k string) bool { return strings.EqualFold(k, id) })
}

func idTest(v string) func(Issue) bool {
	prefix, isPrefix := strings.CutSuffix(strings.ToLower(v), "*")
	if !isPrefix {
		return func(is Issue) bool { return hasID(is, v) }
	}
	return func(is Issue) bool {
		return slices.ContainsFunc(keys(is), func(k string) bool { return strings.HasPrefix(strings.ToLower(k), prefix) })
	}
}

func severityTest(v string) (func(Issue) bool, error) {
	word, orWorse := strings.CutSuffix(v, "+")
	want := model.ParseSeverity(word)
	if want == model.SevUnknown && !strings.EqualFold(word, "unknown") {
		return nil, fmt.Errorf("unknown severity %q; use low, medium, high, critical or unknown, and add + for that or worse", v)
	}
	if orWorse {
		return func(is Issue) bool { return is.Severity.AtLeast(want) }, nil
	}
	return func(is Issue) bool { return is.Severity.Rank() == want.Rank() }, nil
}

func targetTest(match func(Target) bool) func(Issue, Target) bool {
	return func(_ Issue, t Target) bool { return match(t) }
}

func parseEnum[T ~string](kind, v string, allowed []T) (T, error) {
	for _, a := range allowed {
		if strings.EqualFold(string(a), v) {
			return a, nil
		}
	}
	names := make([]string, len(allowed))
	for i, a := range allowed {
		names[i] = string(a)
	}
	var none T
	return none, fmt.Errorf("unknown %s %q; use one of: %s", kind, v, strings.Join(names, ", "))
}

func parseYesNo(v string) (yes, ok bool) {
	switch strings.ToLower(v) {
	case "yes", "true":
		return true, true
	case "no", "false":
		return false, true
	}
	return false, false
}

func yesNoTest(field, v string, has func(Issue, Target) bool) (func(Issue, Target) bool, error) {
	want, ok := parseYesNo(v)
	if !ok {
		return nil, fmt.Errorf("%s needs yes or no, not %q", field, v)
	}
	return func(is Issue, t Target) bool { return has(is, t) == want }, nil
}

func fixTest(v string) (func(Issue) bool, error) {
	if strings.EqualFold(v, "official") {
		return func(is Issue) bool { return is.Fix.Official }, nil
	}
	want, ok := parseYesNo(v)
	if !ok {
		return nil, fmt.Errorf("fix needs yes, no or official, not %q", v)
	}
	return func(is Issue) bool { return is.Fix.Available == want }, nil
}

func dateTest(field, v string) (func(Issue) bool, error) {
	day, err := time.Parse("2006-01-02", v)
	if err != nil {
		return nil, fmt.Errorf("bad date %q for %s; use YYYY-MM-DD", v, field)
	}
	if field == "after" {
		return func(is Issue) bool { return !is.Published.IsZero() && !is.Published.Before(day) }, nil
	}
	return func(is Issue) bool { return !is.Published.IsZero() && is.Published.Before(day) }, nil
}

func publishedTest(v string, now time.Time) (func(Issue) bool, error) {
	r, err := ParseTimeRange(v)
	if err != nil {
		return nil, err
	}
	return func(is Issue) bool { return r.Contains(is.Published, now) }, nil
}
