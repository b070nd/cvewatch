package model

import (
	"slices"
	"strings"
	"testing"
)

func TestEnvValid(t *testing.T) {
	for _, ok := range []string{"local", "prod", "qa-2", "demo_eu", "a", "x" + strings.Repeat("y", 31)} {
		if !Env(ok).Valid() {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "Prod", "2fast", "-x", "_x", "a b", "a/b", "ä", "a.b", "x" + strings.Repeat("y", 32)} {
		if Env(bad).Valid() {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestSortEnvs(t *testing.T) {
	got := []Env{"zeta", "prod", "alpha", "local", "staging", "int", "dev", "beta"}
	SortEnvs(got)
	want := []Env{"local", "dev", "int", "staging", "prod", "alpha", "beta", "zeta"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !EnvLess("local", "dev") || EnvLess("dev", "local") || !EnvLess("prod", "aaa") || EnvLess("aaa", "prod") || EnvLess("a", "a") {
		t.Error("EnvLess order is wrong")
	}
	if EnvCompare("dev", "dev") != 0 || EnvCompare("dev", "prod") >= 0 || EnvCompare("qa", "prod") <= 0 {
		t.Error("EnvCompare disagrees with EnvLess")
	}
}

func TestEnvMeaning(t *testing.T) {
	for e, want := range map[Env]bool{"prod": true, "production": true, "staging": false, "prod-eu": false, "": false} {
		if IsProd(e) != want {
			t.Errorf("IsProd(%q) = %v", e, !want)
		}
	}
	for e, want := range map[Env]bool{"local": true, "dev": true, "int": true, "development": true, "test": true, "staging": false, "prod": false, "qa": false} {
		if IsDevLike(e) != want {
			t.Errorf("IsDevLike(%q) = %v", e, !want)
		}
	}
	if !slices.Equal(SuggestedEnvs, []Env{"local", "dev", "int", "staging", "prod"}) {
		t.Errorf("SuggestedEnvs = %v", SuggestedEnvs)
	}
}

func TestEffectiveEnvsKeepsTheOldDefault(t *testing.T) {
	got := Project{}.EffectiveEnvs()
	if !slices.Equal(got, []Env{"dev", "int", "staging", "prod"}) {
		t.Fatalf("no envs = %v", got)
	}
	got[0] = "changed" // a caller's edit must not reach the shared default
	if LegacyEnvs[0] != "dev" {
		t.Error("EffectiveEnvs handed out the shared slice")
	}
	if got := (Project{Envs: []Env{"local"}}).EffectiveEnvs(); !slices.Equal(got, []Env{"local"}) {
		t.Errorf("explicit envs = %v", got)
	}
}
