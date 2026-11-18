package query

import (
	"slices"
	"testing"
)

func TestSetFieldReplacesTheIncludedTermsOfAField(t *testing.T) {
	cases := []struct {
		text, field string
		values      []string
		want        string
	}{
		{"", "severity", []string{"high", "critical"}, "severity:high,critical"},
		{"redis sev:low -severity:medium", "severity", []string{"high"}, "redis -severity:medium severity:high"},
		{"env:prod OR env:dev kev:yes", "env", nil, "kev:yes"},
		{"tech:php OR redis", "tech", nil, "redis"},
		{"owner:\"Ann B\" x", "owner", []string{"Ann B", "bob"}, "x owner:\"Ann B\",bob"},
		{"Severity:HIGH", "severity", nil, ""},
	}
	for _, c := range cases {
		if got := SetField(c.text, c.field, c.values); got != c.want {
			t.Errorf("SetField(%q, %s, %v) = %q, want %q", c.text, c.field, c.values, got, c.want)
		}
		if _, err := ParseSearch(SetField(c.text, c.field, c.values)); err != nil {
			t.Errorf("%q does not parse: %v", SetField(c.text, c.field, c.values), err)
		}
	}
}

func TestFieldValuesReadsTheIncludedValues(t *testing.T) {
	got := FieldValues(`sev:high,critical -severity:low project:"my shop" redis`, "severity")
	if !slices.Equal(got, []string{"high", "critical"}) {
		t.Errorf("severity = %v", got)
	}
	if got := FieldValues(`project:"my shop"`, "project"); !slices.Equal(got, []string{"my shop"}) {
		t.Errorf("project = %v", got)
	}
}
