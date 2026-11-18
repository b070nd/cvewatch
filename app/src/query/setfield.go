package query

import (
	"regexp"
	"strings"
)

var (
	orRun     = regexp.MustCompile(`(?i)(^|\s)OR(\s+OR)+(\s|$)`)
	orEdge    = regexp.MustCompile(`(?i)^OR\s+|\s+OR$`)
	manySpace = regexp.MustCompile(`\s+`)
)

// SetField rewrites the field's terms in a search text: the terms that
// include by the field (or its alias) go, and one term with the values as
// alternatives takes their place at the end. Excluded terms (-field:v) and
// the rest of the text stay. No values removes the field.
func SetField(text, field string, values []string) string {
	names := []string{regexp.QuoteMeta(field)}
	for alias, to := range fieldAliases {
		if to == field {
			names = append(names, regexp.QuoteMeta(alias))
		}
	}
	re := regexp.MustCompile(`(?i)(^|\s)(` + strings.Join(names, "|") + `):("[^"]*"|\S*)`)
	out := re.ReplaceAllString(text, " ")
	out = orRun.ReplaceAllString(out, " OR ")
	out = strings.TrimSpace(manySpace.ReplaceAllString(out, " "))
	out = strings.TrimSpace(orEdge.ReplaceAllString(out, ""))
	if len(values) == 0 {
		return out
	}
	vs := make([]string, len(values))
	for i, v := range values {
		if strings.ContainsAny(v, " \t\"") {
			v = `"` + strings.ReplaceAll(v, `"`, "") + `"`
		}
		vs[i] = v
	}
	return strings.TrimSpace(out + " " + field + ":" + strings.Join(vs, ","))
}

// FieldValues is the values the text includes by the field, in order.
func FieldValues(text, field string) []string {
	var out []string
	for _, t := range tokenize(text) {
		f := t.field
		if to, ok := fieldAliases[f]; ok {
			f = to
		}
		if f != field || t.exclude {
			continue
		}
		for _, v := range strings.Split(t.value, ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}
