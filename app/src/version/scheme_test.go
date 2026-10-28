package version

import (
	"reflect"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

// checkChain asserts the versions are strictly increasing, both ways round.
func checkChain(t *testing.T, eco string, chain ...string) {
	t.Helper()
	for i := range chain {
		for j := range chain {
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			got, ok := CompareFor(eco, chain[i], chain[j])
			if !ok || got != want {
				t.Errorf("CompareFor(%q, %q, %q) = %d, %v; want %d", eco, chain[i], chain[j], got, ok, want)
			}
		}
	}
}

// checkEqual asserts every version in the group compares equal to the first.
func checkEqual(t *testing.T, eco string, group ...string) {
	t.Helper()
	for _, v := range group[1:] {
		if got, ok := CompareFor(eco, group[0], v); !ok || got != 0 {
			t.Errorf("CompareFor(%q, %q, %q) = %d, %v; want 0", eco, group[0], v, got, ok)
		}
	}
}

func checkUnparsable(t *testing.T, eco string, vs ...string) {
	t.Helper()
	for _, v := range vs {
		if _, ok := CompareFor(eco, v, "1.0"); ok {
			t.Errorf("CompareFor(%q, %q, 1.0) parsed; want unparsable", eco, v)
		}
	}
}

func TestCompareForPyPI(t *testing.T) {
	checkChain(t, "pypi",
		"1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
		"1.0.post1.dev1", "1.0.post1", "1.0.post2", "1.0.1.dev1", "1.0.1", "1.1.dev1", "1.1", "1.10", "2.0")
	checkChain(t, "pypi", "9.9", "1!0.5", "1!0.6", "2!0.1")
	checkChain(t, "pypi", "1.0.dev1", "1.0.dev2", "1.0.dev10", "1.0a1")
	checkEqual(t, "pypi", "1.0", "1.0.0", "1.0.0.0", "v1.0", "V1.0", " 1.0 ", "1.0+abc", "1.0+local.2", "0!1.0")
	checkEqual(t, "pypi", "1.0a1", "1.0-a1", "1.0.alpha1", "1.0.ALPHA.1", "1.0_a_1", "1.0-alpha-1", "1.0A1")
	checkEqual(t, "pypi", "1.0b2", "1.0beta2", "1.0.BETA-2")
	checkEqual(t, "pypi", "1.0rc1", "1.0c1", "1.0pre1", "1.0preview1", "1.0.RC.1", "1.0-rc1")
	checkEqual(t, "pypi", "1.0.post1", "1.0-1", "1.0.rev1", "1.0.r1", "1.0post1", "1.0_post_1", "1.0-POST1")
	checkEqual(t, "pypi", "1.0.post0", "1.0.post", "1.0-0")
	checkEqual(t, "pypi", "1.0a0", "1.0a")
	checkEqual(t, "pypi", "1.0.dev0", "1.0.dev", "1.0dev")
	checkEqual(t, "pypi", "1.0rc1.post2.dev3", "1.0-rc1-post2-dev3")
	checkUnparsable(t, "pypi", "", "v", "abc", "1.0.x", "1.0.*", "1..0", "1.0+", "1.0 a1", "latest", "1.0rc1rc2")
}

func TestCompareForMaven(t *testing.T) {
	checkChain(t, "maven",
		"1.0-alpha1", "1.0-beta1", "1.0-milestone1", "1.0-rc1", "1.0-SNAPSHOT",
		"1.0", "1.0-sp1", "1.0-sp2", "1.0.1-alpha1", "1.0.1", "1.1", "1.10", "2")
	checkChain(t, "maven", "1.0-alpha", "1.0-beta", "1.0-milestone", "1.0-rc", "1.0-snapshot", "1.0", "1.0-sp")
	checkChain(t, "maven", "1", "1-1", "1.1")
	checkChain(t, "maven", "1.0-sp1", "1.0-bar", "1.0-foo") // unknown qualifiers after known ones
	checkChain(t, "maven", "1.0-alpha1", "1.0-alpha2", "1.0-alpha10")
	checkEqual(t, "maven", "1.0", "1.0.0", "1.0.0.0", "1.0-ga", "1.0-final", "1.0-release", "1.0.GA", "1.0-FINAL", "1-0", "1.0-0")
	checkEqual(t, "maven", "1.0-alpha1", "1.0-a1", "1.0-ALPHA1", "1.0alpha1")
	checkEqual(t, "maven", "1.0-beta2", "1.0-b2", "1.0beta2")
	checkEqual(t, "maven", "1.0-milestone3", "1.0-m3")
	checkEqual(t, "maven", "1.0-rc1", "1.0-cr1", "1.0-RC1")
	checkEqual(t, "maven", "1.0-SNAPSHOT", "1.0-snapshot")
	checkEqual(t, "maven", "1.0-sp1", "1.0-SP1", "1.0sp1")
	checkEqual(t, "maven", "1.0-final-1", "1.0-ga-1")
	checkUnparsable(t, "maven", "", "  ", "latest", "RELEASE", "1.0 beta")
	if got, ok := CompareFor("maven", "Hoxton.SR3", "Hoxton.SR10"); !ok || got != -1 {
		t.Errorf("Hoxton.SR3 vs SR10 = %d, %v; want -1", got, ok)
	}
}

func TestCompareForGo(t *testing.T) {
	checkChain(t, "go",
		"v0.0.0-20200101120000-abcdef123456", "v0.0.0-20200202120000-000000000000",
		"v0.0.0", "v0.0.1-0.20200101120000-abcdef123456", "v0.0.1", "v0.1.0", "v1.0.0-alpha")
	checkChain(t, "go",
		"v1.2.3-alpha", "v1.2.3-alpha.1", "v1.2.3-alpha.beta", "v1.2.3-beta", "v1.2.3-beta.2",
		"v1.2.3-beta.11", "v1.2.3-rc.1", "v1.2.3", "v1.2.4-0.20200101120000-abcdef123456",
		"v1.2.4-0.20200101120001-0abcdef12345", "v1.2.4", "v1.10.0", "v2.0.0")
	checkChain(t, "go", "v1.2.3-1", "v1.2.3-2", "v1.2.3-10", "v1.2.3-a") // numeric before alphanumeric
	checkChain(t, "go", "v1.2.4-0.20200101120000-aaaaaaaaaaaa", "v1.2.4-0.20200101120000-bbbbbbbbbbbb")
	checkEqual(t, "go", "v1.2.3", "v1.2.3+incompatible", "v1.2.3+build.5", "1.2.3", "V1.2.3")
	checkEqual(t, "go", "v2.0.0", "v2.0.0+incompatible", "v2", "v2.0")
	checkEqual(t, "go", "v1.2.3-rc.1", "v1.2.3-rc.1+meta")
	checkUnparsable(t, "go", "", "v", "v1.2.3.4", "v1.x", "v1.2.3-", "v1.2.3-a..b", "v1.2.3-a_b", "go1.21", "latest", "v-1")
}

func TestCompareForFallsBackToDefault(t *testing.T) {
	pairs := [][2]string{
		{"1.2.3", "1.2.4"}, {"1.10", "1.9"}, {"v1.0", "1.0.0"}, {"2.4.7-p1", "2.4.7"}, {"2.4.7-p2", "2.4.7-p1"},
		{"1.0.0-rc1", "1.0.0"}, {"1.0.0-beta.2", "1.0.0-rc1"}, {"1.2.3+b", "1.2.3"}, {"abc", "1.0"}, {"", "1"},
	}
	for _, eco := range []string{"composer", "packagist", "npm", "cpe", "", "rpm", "Whatever"} {
		for _, p := range pairs {
			wantC, wantOK := Compare(p[0], p[1])
			if c, ok := CompareFor(eco, p[0], p[1]); c != wantC || ok != wantOK {
				t.Errorf("CompareFor(%q, %q, %q) = %d, %v; Compare gives %d, %v", eco, p[0], p[1], c, ok, wantC, wantOK)
			}
		}
	}
	// the point of the schemes: the same strings order differently per ecosystem
	if c, _ := CompareFor("composer", "1.0.post1", "1.0"); c != -1 {
		t.Errorf("default: 1.0.post1 vs 1.0 = %d; want -1 (suffix is a pre-release)", c)
	}
	if c, _ := CompareFor("pypi", "1.0.post1", "1.0"); c != 1 {
		t.Errorf("pypi: 1.0.post1 vs 1.0 = %d; want 1", c)
	}
	if c, _ := CompareFor("composer", "1.0-sp1", "1.0"); c != -1 {
		t.Errorf("default: 1.0-sp1 vs 1.0 = %d; want -1", c)
	}
	if c, _ := CompareFor("maven", "1.0-sp1", "1.0"); c != 1 {
		t.Errorf("maven: 1.0-sp1 vs 1.0 = %d; want 1", c)
	}
}

func TestCompareForAliases(t *testing.T) {
	for _, eco := range []string{"pypi", "PyPI", "pip", " python "} {
		if c, _ := CompareFor(eco, "1.0.post1", "1.0"); c != 1 {
			t.Errorf("CompareFor(%q): post-release not newer", eco)
		}
	}
	for _, eco := range []string{"maven", "Maven", "gradle"} {
		if c, _ := CompareFor(eco, "1.0-sp1", "1.0"); c != 1 {
			t.Errorf("CompareFor(%q): sp not newer", eco)
		}
	}
	for _, eco := range []string{"go", "golang", "Go"} {
		if c, _ := CompareFor(eco, "v1.2.3+incompatible", "v1.2.3"); c != 0 {
			t.Errorf("CompareFor(%q): build metadata not ignored", eco)
		}
	}
}

func TestParseRangeFor(t *testing.T) {
	r := func(min, max string, minExcl, maxExcl bool) model.Range {
		return model.Range{Min: min, Max: max, MinExcl: minExcl, MaxExcl: maxExcl}
	}
	tests := []struct {
		eco, expr string
		want      []model.Range
	}{
		// pypi: advisory notation
		{"pypi", "", nil},
		{"pypi", ">= 1.0, < 2.0", []model.Range{r("1.0", "2.0", false, true)}},
		{"pypi", ">= 1.0, < 2.0 || >= 3.0.post1, <= 3.5 || = 4.0rc1", []model.Range{
			r("1.0", "2.0", false, true), r("3.0.post1", "3.5", false, false), r("4.0rc1", "4.0rc1", false, false)}},
		{"pypi", "= 1.2.3", []model.Range{r("1.2.3", "1.2.3", false, false)}},
		{"pypi", "1.2.3", []model.Range{r("1.2.3", "1.2.3", false, false)}},
		{"pypi", "< 1.0.post1", []model.Range{r("", "1.0.post1", false, true)}},
		{"pypi", ">= 1.0, >= 1.0.post1", []model.Range{r("1.0.post1", "", false, false)}}, // tighter lower bound
		{"pypi", "< 1.0.post1, < 1.0", []model.Range{r("", "1.0", false, true)}},
		// pypi: PEP 440 specifiers
		{"pypi", ">=1.0,<2.0", []model.Range{r("1.0", "2.0", false, true)}},
		{"pypi", "==1.2.*", []model.Range{r("1.2", "1.3", false, true)}},
		{"pypi", "== 1.2.*", []model.Range{r("1.2", "1.3", false, true)}},
		{"pypi", "==1.2.3.*", []model.Range{r("1.2.3", "1.2.4", false, true)}},
		{"pypi", "==1.*", []model.Range{r("1", "2", false, true)}},
		{"pypi", "==9.*", []model.Range{r("9", "10", false, true)}},
		{"pypi", "==1!2.0.*", []model.Range{r("1!2.0", "1!2.1", false, true)}},
		{"pypi", "~=1.4.2", []model.Range{r("1.4.2", "1.5", false, true)}},
		{"pypi", "~= 1.4.2", []model.Range{r("1.4.2", "1.5", false, true)}},
		{"pypi", "~=2.2", []model.Range{r("2.2", "3", false, true)}},
		{"pypi", "~=1.4.2.1", []model.Range{r("1.4.2.1", "1.4.3", false, true)}},
		{"pypi", "~=1.0a1", []model.Range{r("1.0a1", "2", false, true)}},
		{"pypi", "~=1!1.4", []model.Range{r("1!1.4", "1!2", false, true)}},
		{"pypi", "===1.0", []model.Range{r("1.0", "1.0", false, false)}},
		{"pypi", "==1.0", []model.Range{r("1.0", "1.0", false, false)}},
		{"pypi", ">=1.0, ==1.*", []model.Range{r("1.0", "2", false, true)}},
		{"pypi", ">=1.5, ==1.*", []model.Range{r("1.5", "2", false, true)}},
		{"pypi", ">=1.0,<2.0 || ==3.*", []model.Range{r("1.0", "2.0", false, true), r("3", "4", false, true)}},
		// maven
		{"maven", ">= 1.0, < 1.0.1", []model.Range{r("1.0", "1.0.1", false, true)}},
		{"maven", "< 1.0-SP1 || = 2.0-Final", []model.Range{r("", "1.0-SP1", false, true), r("2.0-Final", "2.0-Final", false, false)}},
		{"maven", ">= 1.0-ga, < 1.0", []model.Range{r("1.0-ga", "1.0", false, true)}},
		{"maven", ">= 1.0, >= 1.0-sp1", []model.Range{r("1.0-sp1", "", false, false)}},
		// go
		{"go", ">= v1.0.0, < v1.2.3", []model.Range{r("v1.0.0", "v1.2.3", false, true)}},
		{"go", "< v0.0.0-20200101120000-abcdef123456", []model.Range{r("", "v0.0.0-20200101120000-abcdef123456", false, true)}},
		{"golang", "= v1.2.3+incompatible", []model.Range{r("v1.2.3+incompatible", "v1.2.3+incompatible", false, false)}},
		{"go", ">= v1.2.4-0.20200101120000-abcdef123456, < v1.2.4", []model.Range{r("v1.2.4-0.20200101120000-abcdef123456", "v1.2.4", false, true)}},
		// default
		{"composer", ">= 1.0, < 2.0 || = 3.1", []model.Range{r("1.0", "2.0", false, true), r("3.1", "3.1", false, false)}},
		{"npm", "< 6.4.2", []model.Range{r("", "6.4.2", false, true)}},
		{"cpe", "<= 2.4.7-p1", []model.Range{r("", "2.4.7-p1", false, false)}},
		{"", ">= 1.0, 1.5", []model.Range{r("1.5", "1.5", false, false)}},
		{"rpm", "2.4.7-p2", []model.Range{r("2.4.7-p2", "2.4.7-p2", false, false)}},
	}
	for _, tt := range tests {
		got, err := ParseRangeFor(tt.eco, tt.expr)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseRangeFor(%q, %q) = %+v, %v; want %+v", tt.eco, tt.expr, got, err, tt.want)
		}
	}

	errs := []struct{ eco, expr string }{
		{"pypi", "!=1.0"}, {"pypi", "!= 1.0"}, {"pypi", ">=1.0, !=1.5"}, {"pypi", "!=1.*"},
		{"pypi", "~=1"}, {"pypi", "~=1.*"}, {"pypi", "==1.2a.*"}, {"pypi", "==1.2.post1.*"}, {"pypi", "==1.*.*"},
		{"pypi", ">=1.0.*"}, {"pypi", "garbage"}, {"pypi", ">="}, {"pypi", ">= foo"}, {"pypi", "< 1.0 ||"},
		{"pypi", "~> 1.2"}, {"pypi", ">= 1.0rc1rc2"}, {"pypi", "==*"},
		{"maven", "garbage"}, {"maven", ">= "}, {"maven", "< latest"}, {"maven", ">= 1.0 || < foo"}, {"maven", "!= 1.0"},
		{"go", "garbage"}, {"go", ">= v1.2.3.4"}, {"go", "< v1.x"}, {"go", "< v1.2.3-"}, {"go", "!= v1.0.0"},
		{"composer", "~> 1.2"}, {"composer", "!= 1.0"}, {"npm", "garbage"},
	}
	for _, tt := range errs {
		if got, err := ParseRangeFor(tt.eco, tt.expr); err == nil {
			t.Errorf("ParseRangeFor(%q, %q) = %+v; want error", tt.eco, tt.expr, got)
		}
	}

	if _, err := ParseRangeFor("pypi", strings.Repeat("Q", 200)); err == nil || strings.Count(err.Error(), "Q") > 80 {
		t.Errorf("long garbage: err = %v; want an error echoing at most 80 chars", err)
	}
	if _, err := ParseRangeFor("pypi", "!=1.0"); err == nil || !strings.Contains(err.Error(), "!=") {
		t.Errorf("!= error = %v; want it to name the operator", err)
	}
}

func TestParseRangeForDefaultMatchesParseRange(t *testing.T) {
	for _, expr := range []string{"", ">= 1.0, < 2.0", "= 1.2.3", "< 2.4.7-p2 || >= 3.0-beta", "!= 1.0", "garbage", "~> 1.2"} {
		want, wantErr := ParseRange(expr)
		for _, eco := range []string{"composer", "npm", "cpe", "unknown"} {
			got, err := ParseRangeFor(eco, expr)
			if !reflect.DeepEqual(got, want) || (err == nil) != (wantErr == nil) {
				t.Errorf("ParseRangeFor(%q, %q) = %+v, %v; ParseRange gives %+v, %v", eco, expr, got, err, want, wantErr)
			}
		}
	}
}

func TestEvaluateFor(t *testing.T) {
	const (
		aff = model.AppAffected
		not = model.AppNotAffected
		unk = model.AppUnknown
	)
	tests := []struct {
		name, eco, installed, expr string
		want                       model.Applicability
	}{
		// pypi: exact versions
		{"pypi inside", "pypi", "1.5.0", ">=1.0,<2.0", aff},
		{"pypi at excl max", "pypi", "2.0.0", ">=1.0,<2.0", not},
		{"pypi post-release above incl max", "pypi", "1.0.post1", "<= 1.0", not},
		{"pypi post-release at incl max", "pypi", "1.0.post1", "<= 1.0.post1", aff},
		{"pypi post-release below excl max", "pypi", "1.0.post1", "< 1.0.post2", aff},
		{"pypi post-release at excl max", "pypi", "1.0.post1", "< 1.0.post1", not},
		{"pypi post-release below next patch", "pypi", "1.0.post1", "< 1.0.1", aff},
		{"pypi post-release above fixed 1.0", "pypi", "1.0.post1", ">= 0.5, < 1.0", not},
		{"pypi post-release at incl min", "pypi", "1.0.post1", ">= 1.0.post1, < 2", aff},
		{"pypi post-release above excl min", "pypi", "1.0.post1", "> 1.0", aff},
		{"pypi post-release at excl min", "pypi", "1.0.post1", "> 1.0.post1", not},
		{"pypi post-release in prefix", "pypi", "1.0.post1", "==1.0.*", aff},
		{"pypi dev below release", "pypi", "1.0.dev1", "< 1.0", aff},
		{"pypi rc below release", "pypi", "1.0rc1", "< 1.0", aff},
		{"pypi rc not in lower-bounded", "pypi", "1.0rc1", ">= 1.0", not},
		{"pypi alias spelling", "pip", "1.0-a1", "< 1.0b1", aff},
		{"pypi epoch beats range", "pypi", "1!0.5", "< 9.9", not},
		{"pypi epoch inside", "pypi", "1!0.5", ">= 1!0.1, < 1!1.0", aff},
		{"pypi local ignored", "pypi", "1.0+cu118", "<= 1.0", aff},
		{"pypi compatible release in", "pypi", "1.4.9", "~=1.4.2", aff},
		{"pypi compatible release below", "pypi", "1.4.1", "~=1.4.2", not},
		{"pypi compatible release above", "pypi", "1.5.0", "~=1.4.2", not},
		{"pypi prefix in", "pypi", "1.2.7", "==1.2.*", aff},
		{"pypi prefix out", "pypi", "1.3.0", "==1.2.*", not},
		{"pypi union second", "pypi", "3.1.0", "<1.0 || >=3.0,<3.2", aff},
		// pypi: series
		{"pypi series covered", "pypi", "1.2", "< 1.3", aff},
		{"pypi series covered by union", "pypi", "1.2", "< 1.2.5 || >= 1.2.5", aff},
		{"pypi series partly", "pypi", "1.2", "< 1.2.5", unk},
		{"pypi series above", "pypi", "1.2", ">= 1.3", not},
		{"pypi series below", "pypi", "1.2", "< 1.2", not},
		{"pypi series vs 1.3 pre-release start", "pypi", "1.2", ">= 1.3.dev1", not},
		{"pypi series prefix range", "pypi", "1.2", "==1.2.*", aff},
		{"pypi series major", "pypi", "2", ">=2, <3", aff},
		{"pypi series major partly", "pypi", "2", ">=2.5", unk},
		{"pypi series with epoch", "pypi", "1!2.0", ">=1!2.0, <1!2.1", aff},
		{"pypi three parts exact", "pypi", "1.2.0", "< 1.2.5", aff},
		{"pypi suffix is exact", "pypi", "1.2rc1", "< 1.2", aff},
		// pypi: unknown
		{"pypi no ranges", "pypi", "1.0", "", unk},
		{"pypi unparsable installed", "pypi", "latest", "< 2", unk},

		// maven
		{"maven sp1 below next patch", "maven", "1.0-SP1", "< 1.0.1", aff},
		{"maven sp1 above 1.0", "maven", "1.0-SP1", "<= 1.0", not},
		{"maven sp1 not below 1.0", "maven", "1.0-SP1", "< 1.0", not},
		{"maven sp1 inside", "maven", "1.0-SP1", ">= 1.0-ga, < 1.0.1", aff},
		{"maven snapshot below release", "maven", "1.0-SNAPSHOT", "< 1.0", aff},
		{"maven release above snapshot", "maven", "1.0.0", "<= 1.0-SNAPSHOT", not},
		{"maven final equals release", "maven", "1.0.Final", "<= 1.0", aff},
		{"maven final at excl max", "maven", "1.0-final", "< 1.0", not},
		{"maven rc below final", "maven", "2.0-rc1", ">= 1.0, < 2.0", aff},
		{"maven alpha shorthand", "maven", "2.0-a1", "< 2.0-beta1", aff},
		{"maven at fixed patch", "maven", "1.0.1", "< 1.0.1", not},
		{"maven equal", "maven", "1.0.0", "= 1.0", aff},
		{"maven unknown qualifier after sp", "maven", "1.0-foo", "<= 1.0-sp1", not},
		{"maven second alternative", "maven", "2.0-SP1", "< 1.0 || >= 2.0, < 2.0.1", aff},
		{"maven series covered", "maven", "1.2", "< 1.3", aff},
		{"maven series partly", "maven", "1.2", "< 1.2.5", unk},
		{"maven series incl max", "maven", "1.2", "<= 1.2", unk},
		{"maven series above", "maven", "1.2", ">= 1.3", not},
		{"maven series vs next snapshot", "maven", "1.2", ">= 1.3-SNAPSHOT", not},
		{"maven series below", "maven", "1.2", "< 1.2", not},
		{"maven series major", "maven", "3", "< 4", aff},
		{"maven three parts exact", "maven", "1.2.0", "<= 1.2", aff},
		{"maven no digits installed", "maven", "latest", "< 2", unk},

		// go
		{"go inside", "go", "v1.2.3", ">= v1.0.0, < v1.2.4", aff},
		{"go at excl max", "go", "v1.2.4", ">= v1.0.0, < v1.2.4", not},
		{"go incompatible ignored", "go", "v2.0.0+incompatible", "< v2.0.1", aff},
		{"go incompatible vs fixed", "go", "v2.0.0+incompatible", "< v2.0.0", not},
		{"go pseudo below fix", "go", "v0.0.0-20200101120000-abcdef123456", "< v0.0.0-20210101000000-000000000000", aff},
		{"go pseudo above fix", "go", "v0.0.0-20220101000000-abcdef123456", "< v0.0.0-20210101000000-000000000000", not},
		{"go pseudo at min", "go", "v0.0.0-20200101120000-abcdef123456", ">= v0.0.0-20200101120000-abcdef123456", aff},
		{"go pseudo below release", "go", "v1.2.4-0.20200101120000-abcdef123456", "< v1.2.4", aff},
		{"go pseudo above previous release", "go", "v1.2.4-0.20200101120000-abcdef123456", "<= v1.2.3", not},
		{"go prerelease below release", "go", "v1.2.3-rc.1", "< v1.2.3", aff},
		{"go pseudo in union", "go", "v0.0.0-20200101120000-abcdef123456", "< v0.0.0-20190101000000-000000000000 || >= v0.0.0-20200101000000-000000000000, < v0.0.1", aff},
		{"go series covered", "go", "v1.21", "< v1.22.0", aff},
		{"go series partly", "go", "v1.21", ">= v1.21.5", unk},
		{"go series above", "go", "v1.21", ">= v1.22.0", not},
		{"go series below", "go", "v1.21", "< v1.21.0", not},
		{"go series bare", "go", "1.21", "< 1.22", aff},
		{"go series major", "go", "v2", ">= v2.0.0, < v3.0.0", aff},
		{"go series vs next pre-release", "go", "v1.21", ">= v1.22.0-rc.1", not},
		{"go unparsable", "go", "latest", "< v1.0.0", unk},

		// default
		{"composer exact", "composer", "2.4.7-p1", "< 2.4.7-p2", aff},
		{"npm series", "npm", "8.2", "< 8.2.30", unk},
		{"cpe at max", "cpe", "1.2.3", "<= 1.2.3", aff},
		{"unknown eco", "rpm", "1.2.4", "<= 1.2.3", not},
		{"empty eco", "", "1.0.0-rc1", "< 1.0.0", aff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs, err := ParseRangeFor(tt.eco, tt.expr)
			if err != nil {
				t.Fatalf("ParseRangeFor(%q, %q): %v", tt.eco, tt.expr, err)
			}
			if got := EvaluateFor(tt.eco, tt.installed, rs); got != tt.want {
				t.Errorf("EvaluateFor(%q, %q, %+v) = %s; want %s", tt.eco, tt.installed, rs, got, tt.want)
			}
		})
	}
}

func TestEvaluateForUnreadableAndEmpty(t *testing.T) {
	for _, eco := range []string{"pypi", "maven", "go", "composer"} {
		v := "1.0.0"
		if eco == "go" {
			v = "v1.0.0"
		}
		if got := EvaluateFor(eco, v, []model.Range{{Max: "!!"}}); got != model.AppUnknown {
			t.Errorf("%s: unreadable only = %s; want unknown", eco, got)
		}
		if got := EvaluateFor(eco, v, []model.Range{{Max: "!!"}, {Min: v}}); got != model.AppAffected {
			t.Errorf("%s: unreadable plus hit = %s; want affected", eco, got)
		}
		if got := EvaluateFor(eco, v, []model.Range{{}}); got != model.AppAffected {
			t.Errorf("%s: zero range = %s; want affected", eco, got)
		}
		if got := EvaluateFor(eco, v, nil); got != model.AppUnknown {
			t.Errorf("%s: no ranges = %s; want unknown", eco, got)
		}
		if got := EvaluateFor(eco, "", []model.Range{{}}); got != model.AppUnknown {
			t.Errorf("%s: empty installed = %s; want unknown", eco, got)
		}
	}
}

func TestEvaluateForDefaultMatchesEvaluate(t *testing.T) {
	ranges := [][]model.Range{nil, {{}}, {{Max: "8.2.30", MaxExcl: true}}, {{Min: "2.4.7-p1", Max: "2.4.7-p2"}}, {{Max: "abc"}, {Min: "1.0.0"}}}
	for _, eco := range []string{"composer", "npm", "cpe", "unknown", ""} {
		for _, inst := range []string{"8.2", "8.2.5", "2.4.7-p1", "1.0.0", "latest", ""} {
			for _, rs := range ranges {
				if got, want := EvaluateFor(eco, inst, rs), Evaluate(inst, rs); got != want {
					t.Errorf("EvaluateFor(%q, %q, %+v) = %s; Evaluate gives %s", eco, inst, rs, got, want)
				}
			}
		}
	}
}
