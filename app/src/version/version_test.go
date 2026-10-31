package version

import (
	"reflect"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.2.3", "1.2.4", -1, true},
		{"1.10", "1.9", 1, true},
		{"1.2.3", "1.2.3", 0, true},
		{" v1.2.3 ", "1.2.3", 0, true},
		{"V2", "=2.0.0", 0, true},
		{"=1.0", "v1.0.0", 0, true},
		{"1.2", "1.2.0", 0, true},
		{"1.2", "1.2.0.0.0.0", 0, true},
		{"1.2", "1.2.0.1", -1, true},
		{"2.4.7-p1", "2.4.7", 1, true},
		{"2.4.7-p1", "2.4.7-p2", -1, true},
		{"2.4.7p1", "2.4.7-p1", 0, true},
		{"2.4-p1", "2.4.0-p1", 0, true},
		{"2.4.7-p10", "2.4.7-p9", 1, true},
		{"2.4.7-p1", "2.4.8-beta", -1, true},
		{"1.0.0-beta.1", "1.0.0", -1, true},
		{"1.0.0-rc1", "1.0.0-beta.2", 1, true},
		{"1.0.0-rc2", "1.0.0-rc10", -1, true},
		{"1.0.0-beta", "1.0.0-beta.1", -1, true},
		{"1.0.0-RC1", "1.0.0-rc1", 0, true},
		{"1.0.0rc1", "1.0.0", -1, true},
		{"1.2.3+build5", "1.2.3", 0, true},
		{"1.2.3+a", "1.2.3+b", 0, true},
		// kernel and distribution suffixes are builds, not pre-releases
		{"6.12.85+", "6.12.85", 0, true},
		{"6.12.85+", "6.12.86", -1, true},
		{"6.8.0-45-generic", "6.8.0", 0, true},
		{"6.8.0-45-generic", "6.8.1", -1, true},
		{"6.12.86-generic", "6.12.86", 0, true},
		{"6.12.85-1ubuntu1", "6.12.85", 0, true},
		{"6.12.85+deb12u1", "6.12.85", 0, true},
		{"6.12.85-ubuntu1", "6.12.85", 0, true},
		{"5.14.0-362.el9", "5.14.0", 0, true},
		{"6.1.0-18-amd64", "6.1.0", 0, true},
		{"6.12.0-rc3", "6.12.0", -1, true},
		{"6.12.85-custom", "6.12.85", -1, true},
		{"", "1.0", 0, false},
		{"1.0", "", 0, false},
		{"abc", "1.0", 0, false},
		{"v", "1.0", 0, false},
		{"1.2.3.4.5.6.7", "1", 0, false},
		{"1.2.3.4.5.6", "1.2.3.4.5.7", -1, true},
	}
	for _, tt := range tests {
		got, ok := Compare(tt.a, tt.b)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseRange(t *testing.T) {
	tests := []struct {
		expr string
		want []model.Range
	}{
		{"", nil},
		{"   ", nil},
		{">= 1.0.0, < 1.2.3", []model.Range{{Min: "1.0.0", Max: "1.2.3", MaxExcl: true}}},
		{"< 6.4.2", []model.Range{{Max: "6.4.2", MaxExcl: true}}},
		{"<=6.4.2", []model.Range{{Max: "6.4.2"}}},
		{"> 1.0", []model.Range{{Min: "1.0", MinExcl: true}}},
		{"= 1.2.3", []model.Range{{Min: "1.2.3", Max: "1.2.3"}}},
		{"==1.2.3", []model.Range{{Min: "1.2.3", Max: "1.2.3"}}},
		{"1.2.3", []model.Range{{Min: "1.2.3", Max: "1.2.3"}}},
		{">=2.0 <2.5", []model.Range{{Min: "2.0", Max: "2.5", MaxExcl: true}}},
		{"> 1.0, <= 2.0", []model.Range{{Min: "1.0", MinExcl: true, Max: "2.0"}}},
		{">= v1.0 , < 2.0-beta", []model.Range{{Min: "v1.0", Max: "2.0-beta", MaxExcl: true}}},
		{">= 1.0, < 2.0 || >= 3.0, < 3.5 || = 4.1", []model.Range{
			{Min: "1.0", Max: "2.0", MaxExcl: true},
			{Min: "3.0", Max: "3.5", MaxExcl: true},
			{Min: "4.1", Max: "4.1"},
		}},
		{">= 1.0, >= 1.5", []model.Range{{Min: "1.5"}}},
		{">= 1.5, >= 1.0", []model.Range{{Min: "1.5"}}},
		{">= 1.5, > 1.5", []model.Range{{Min: "1.5", MinExcl: true}}},
		{"> 1.5, >= 1.5", []model.Range{{Min: "1.5", MinExcl: true}}},
		{"< 2.0, < 1.5", []model.Range{{Max: "1.5", MaxExcl: true}}},
		{"< 1.5, <= 2.0", []model.Range{{Max: "1.5", MaxExcl: true}}},
		{"<= 1.5, < 1.5", []model.Range{{Max: "1.5", MaxExcl: true}}},
		{"< 1.5, <= 1.5", []model.Range{{Max: "1.5", MaxExcl: true}}},
		{">= 1.0, 1.5", []model.Range{{Min: "1.5", Max: "1.5"}}},
	}
	for _, tt := range tests {
		got, err := ParseRange(tt.expr)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseRange(%q) = %+v, %v; want %+v", tt.expr, got, err, tt.want)
		}
	}

	for _, expr := range []string{"garbage", ">=", ">= ", "!= 1.0", ">= 1.0 foo", "||", "< 1.0 ||", "|| < 1.0", "~> 1.2", "< ,"} {
		if got, err := ParseRange(expr); err == nil {
			t.Errorf("ParseRange(%q) = %+v; want error", expr, got)
		}
	}

	long := strings.Repeat("Q", 200)
	_, err := ParseRange(long)
	if err == nil {
		t.Fatal("long garbage: want error")
	}
	if n := strings.Count(err.Error(), "Q"); n > 80 {
		t.Errorf("error echoes %d chars of input; want at most 80", n)
	}
}

func TestEvaluate(t *testing.T) {
	rs := func(expr string) []model.Range {
		r, err := ParseRange(expr)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", expr, err)
		}
		return r
	}
	const (
		aff = model.AppAffected
		not = model.AppNotAffected
		unk = model.AppUnknown
	)
	tests := []struct {
		name      string
		installed string
		ranges    []model.Range
		want      model.Applicability
	}{
		// no data
		{"no ranges", "1.2.3", nil, unk},
		{"empty ranges", "1.2.3", []model.Range{}, unk},
		{"installed empty", "", rs("< 2.0"), unk},
		{"installed unparsable", "latest", rs("< 2.0"), unk},
		{"installed spaces", "  ", rs("< 2.0"), unk},

		// zero Range covers everything
		{"zero range exact", "1.2.3", []model.Range{{}}, aff},
		{"zero range series", "8.2", []model.Range{{}}, aff},
		{"zero range major", "20", []model.Range{{}}, aff},

		// exact versions
		{"exact inside", "8.2.5", rs("< 8.2.30"), aff},
		{"exact at excl max", "8.2.30", rs("< 8.2.30"), not},
		{"exact at incl max", "1.2.3", rs("<= 1.2.3"), aff},
		{"exact above incl max", "1.2.4", rs("<= 1.2.3"), not},
		{"exact at excl min", "1.2.3", rs("> 1.2.3"), not},
		{"exact at incl min", "1.2.3", rs(">= 1.2.3"), aff},
		{"exact equal", "1.2.3", rs("= 1.2.3"), aff},
		{"exact not equal", "1.2.4", rs("= 1.2.3"), not},
		{"exact v prefix", "v1.2.3", rs("< 2.0"), aff},
		{"exact bounded", "8.2.29", rs(">= 8.2.0, < 8.2.30"), aff},
		{"exact below bounded", "8.1.9", rs(">= 8.2.0, < 8.2.30"), not},
		{"exact second alternative", "8.5.0", rs("< 1.0 || >= 8.0, < 9.0"), aff},
		{"exact between alternatives", "7.0.1", rs("< 1.0 || >= 8.0, < 9.0"), not},
		{"exact padded bound", "2.0.0", rs("<= 2.0"), aff},
		{"exact three zeros", "1.0.0", rs("< 1"), not},
		{"exact prerelease below release", "1.0.0-rc1", rs("< 1.0.0"), aff},
		{"exact two parts with suffix", "1.2-beta", rs("< 1.2.0"), aff},
		{"patch vs higher patch", "2.4.7-p1", rs("< 2.4.7-p2"), aff},
		{"patch vs base release", "2.4.7-p1", rs("< 2.4.7"), not},
		{"base release vs patch", "2.4.7", rs("< 2.4.7-p1"), aff},
		{"patch at fixed patch", "2.4.7-p2", rs("< 2.4.7-p2"), not},

		// kernel-style versions: the numeric core decides, the suffix never errors
		{"kernel plus", "6.12.85+", rs(">= 6.12.0, <= 6.12.86"), aff},
		{"kernel plus below fix", "6.12.85+", rs("< 6.12.86"), aff},
		{"kernel flavour at fix", "6.12.86-generic", rs("< 6.12.86"), not},
		{"kernel flavour below fix", "6.8.0-45-generic", rs("< 6.8.1"), aff},
		{"kernel flavour past range", "6.8.0-45-generic", rs(">= 6.1.0, < 6.8.0"), not},
		{"kernel debian revision", "6.1.85-1+deb12u1", rs("< 6.1.90"), aff},
		{"kernel ubuntu revision at fix", "6.12.86-1ubuntu1", rs("< 6.12.86"), not},
		{"kernel suffix on two parts is a series", "6.12-generic", rs("< 6.12.86"), unk},

		// series
		{"series partly affected", "8.2", rs("< 8.2.30"), unk},
		{"series above range", "8.2", rs(">= 8.3.0"), not},
		{"series below range", "8.2", rs("< 8.2.0"), not},
		{"series below range, short bound", "8.2", rs("< 8.2"), not},
		{"series fully below excl max", "8.2", rs("< 8.3.0"), aff},
		{"series vs incl max just short", "8.2", rs("<= 8.2.99999"), unk},
		{"series vs incl max at start", "8.2", rs("<= 8.2.0"), unk},
		{"series vs incl max below start", "8.2", rs("<= 8.1.99"), not},
		{"series vs excl min at start", "8.2", rs("> 8.2.0"), unk},
		{"series vs incl min at start", "8.2", rs(">= 8.2.0"), aff},
		{"series vs incl min inside", "8.2", rs(">= 8.2.5"), unk},
		{"series vs exact point inside", "8.2", rs("= 8.2.5"), unk},
		{"series exact bounds", "8.2", rs(">= 8.2.0, < 8.3.0"), aff},
		{"series bigger span", "8.2", rs(">= 8.0, < 9.0"), aff},
		{"series other span", "8.2", rs(">= 9, < 10"), not},
		{"series union covers", "8.2", rs("< 8.2.30 || >= 8.2.30"), aff},
		{"series union with hole", "8.2", rs("< 8.2.30 || > 8.2.30"), unk},
		{"series union of three", "8.2", rs("< 8.2.10 || >= 8.2.10, < 8.2.50 || >= 8.2.50"), aff},
		{"series union out of order", "8.2", rs(">= 8.2.30 || < 8.2.30"), aff},
		{"series disjoint alternatives", "8.2", rs("< 7.0 || >= 9.0"), not},
		{"major series inside", "20", rs("< 21"), aff},
		{"major series above", "20", rs(">= 21"), not},
		{"major series partly", "20", rs("< 20.5"), unk},
		{"major series below", "20", rs("< 19"), not},
		{"major series vs 20.0", "20", rs("<= 20"), unk},

		// ranges the feed gave but we cannot read
		{"unreadable range only", "1.0.0", []model.Range{{Max: "abc"}}, unk},
		{"unreadable range, other hits", "1.0.0", []model.Range{{Max: "abc"}, {Min: "1.0.0"}}, aff},
		{"unreadable range, series", "8.2", []model.Range{{Min: "abc"}}, unk},
		{"unreadable range, other misses", "1.0.0", []model.Range{{Max: "abc"}, {Min: "2.0.0"}}, unk},
		{"empty span ignored", "1.5.0", []model.Range{{Min: "2.0", Max: "1.0"}}, not},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(tt.installed, tt.ranges); got != tt.want {
				t.Errorf("Evaluate(%q, %+v) = %s; want %s", tt.installed, tt.ranges, got, tt.want)
			}
		})
	}
}
