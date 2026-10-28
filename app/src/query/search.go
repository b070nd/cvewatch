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

type term struct {
	exclude bool
	plain   string // lower-case text of a plain term, empty for a field term
	test    func(Issue) bool
}

type token struct {
	exclude bool
	field   string
	value   string
	isOr    bool
}

var fieldNames = []string{"id", "severity", "project", "env", "owner", "ticket", "tech", "status", "applies", "kev", "fix", "overdue", "after", "before"}

var fieldAliases = map[string]string{"cve": "id", "sev": "severity"}

func ParseSearch(text string) (Search, error) {
	var s Search
	joined := false
	for _, t := range operators(tokenize(text)) {
		tm, err := compile(t.token)
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

func (s Search) Match(is Issue) bool {
	for _, c := range s.clauses {
		if !c.match(is) {
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

func (c clause) match(is Issue) bool {
	return slices.ContainsFunc(c, func(t term) bool { return t.test(is) != t.exclude })
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

func compile(t token) (term, error) {
	if t.field == "" {
		return term{exclude: t.exclude, plain: strings.ToLower(t.value), test: containing(strings.ToLower(t.value))}, nil
	}
	test, err := fieldTest(t.field, t.value)
	return term{exclude: t.exclude, test: test}, err
}

func containing(text string) func(Issue) bool {
	return func(is Issue) bool { return strings.Contains(haystack(is), text) }
}

func haystack(is Issue) string {
	parts := []string{is.ID, is.Untrusted.Title, is.Untrusted.Description}
	parts = append(parts, is.Aliases...)
	parts = append(parts, is.Techs...)
	for _, t := range is.Targets {
		parts = append(parts, t.Project, string(t.Env), t.Owner, t.Ticket)
		parts = append(parts, t.Matched...)
	}
	return strings.ToLower(strings.Join(parts, "\n"))
}

func fieldTest(field, value string) (func(Issue) bool, error) {
	if canonical, ok := fieldAliases[field]; ok {
		field = canonical
	}
	if !slices.Contains(fieldNames, field) {
		return nil, fmt.Errorf("unknown field %q; use one of: %s", field, strings.Join(fieldNames, ", "))
	}
	var alternatives []func(Issue) bool
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("missing value after %s:", field)
		}
		test, err := valueTest(field, v)
		if err != nil {
			return nil, err
		}
		alternatives = append(alternatives, test)
	}
	return func(is Issue) bool {
		for _, test := range alternatives {
			if test(is) {
				return true
			}
		}
		return false
	}, nil
}

func valueTest(field, v string) (func(Issue) bool, error) {
	switch field {
	case "id":
		return idTest(v), nil
	case "severity":
		return severityTest(v)
	case "project":
		return targetTest(func(t Target) bool { return strings.EqualFold(t.Project, v) }), nil
	case "owner":
		return targetTest(func(t Target) bool { return strings.EqualFold(t.Owner, v) }), nil
	case "ticket":
		return targetTest(func(t Target) bool { return strings.EqualFold(t.Ticket, v) }), nil
	case "tech":
		return func(is Issue) bool {
			return slices.ContainsFunc(is.Techs, func(tech string) bool { return strings.EqualFold(tech, v) })
		}, nil
	case "env":
		env, err := parseEnum("environment", v, model.AllEnvs)
		return targetTest(func(t Target) bool { return t.Env == env }), err
	case "status":
		status, err := parseEnum("status", v, []model.Status{model.StatusOpen, model.StatusFixed, model.StatusIgnored, model.StatusNotAffected})
		return targetTest(func(t Target) bool { return t.Status == status }), err
	case "applies":
		applies, err := parseEnum("applicability", v, []model.Applicability{model.AppAffected, model.AppUnknown, model.AppNotAffected})
		return func(is Issue) bool { return is.Applies == applies }, err
	case "kev":
		return yesNoTest(field, v, func(is Issue) bool { return is.KEV != nil })
	case "overdue":
		return yesNoTest(field, v, func(is Issue) bool { return slices.ContainsFunc(is.Targets, func(t Target) bool { return t.Overdue }) })
	case "fix":
		return fixTest(v)
	}
	return dateTest(field, v)
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

func targetTest(match func(Target) bool) func(Issue) bool {
	return func(is Issue) bool { return slices.ContainsFunc(is.Targets, match) }
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

func yesNoTest(field, v string, has func(Issue) bool) (func(Issue) bool, error) {
	want, ok := parseYesNo(v)
	if !ok {
		return nil, fmt.Errorf("%s needs yes or no, not %q", field, v)
	}
	return func(is Issue) bool { return has(is) == want }, nil
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
