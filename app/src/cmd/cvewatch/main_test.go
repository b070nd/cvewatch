package main

import (
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

func TestFailGateOnlyActsWhenAskedFor(t *testing.T) {
	issues := []query.Issue{{ID: "CVE-2026-1", Severity: model.SevHigh}, {ID: "CVE-2026-2", Severity: model.SevLow}}
	if err := failGate(issues, ""); err != nil {
		t.Errorf("no -fail-on must never fail the command: %v", err)
	}
	if err := failGate(issues, model.SevCritical); err != nil {
		t.Errorf("nothing is critical: %v", err)
	}
	if err := failGate(issues, model.SevHigh); err == nil {
		t.Error("a high finding must trip -fail-on high")
	}
	if err := failGate(nil, model.SevLow); err != nil {
		t.Errorf("no findings: %v", err)
	}
}

func TestParseListFailOn(t *testing.T) {
	o, err := parseList("list", nil)
	if err != nil || o.FailOn != "" {
		t.Fatalf("default: %+v %v", o, err)
	}
	if o, err = parseList("list", []string{"-fail-on", "high"}); err != nil || o.FailOn != model.SevHigh {
		t.Fatalf("high: %+v %v", o, err)
	}
	if _, err = parseList("list", []string{"-fail-on", "bogus"}); err == nil {
		t.Fatal("an unknown level must be rejected")
	}
}

func TestParseListPublished(t *testing.T) {
	o, err := parseList("list", nil)
	if err != nil || !o.Published.Any() {
		t.Fatalf("default is any time: %+v %v", o.Published, err)
	}
	for value, label := range map[string]string{"week": "past week", "24h": "past 24 hours", "2026-01-01..2026-03-01": "2026-01-01 to 2026-03-01", "..2026-03-01": "until 2026-03-01"} {
		if o, err = parseList("list", []string{"-published", value}); err != nil || o.Published.Label() != label {
			t.Errorf("%s: %q %v", value, o.Published.Label(), err)
		}
	}
	if _, err = parseList("list", []string{"-published", "soon"}); err == nil {
		t.Fatal("a bad time filter must be rejected")
	}
	var f query.Filter
	if err := setPublished(&f, "month"); err != nil || f.Published.Label() != "past month" {
		t.Fatalf("setPublished: %+v %v", f.Published, err)
	}
}
