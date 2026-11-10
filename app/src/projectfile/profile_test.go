package projectfile

import (
	"strings"
	"testing"
)

func TestSetProfile(t *testing.T) {
	const base = "name: shop\nvendor: acme\nenvs: [dev]\n"
	tests := []struct {
		name, src, profile, want, err string
	}{
		{"set goes after the vendor", base, "strict", "name: shop\nvendor: acme\nprofile: strict\nenvs: [dev]\n", ""},
		{"change in place", base + "profile: strict\n", "discovery", base + "profile: discovery\n", ""},
		{"clear", base + "profile: strict\n", "", base, ""},
		{"clear when absent", base, "", base, ""},
		{"invalid", base, "loose", "", "strict, balanced, discovery"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustParse(t, tt.src)
			err := f.Apply(Op{Kind: "set_profile", Profile: tt.profile})
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want it to list %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := mustApply(t, tt.src, Op{Kind: "set_profile", Profile: tt.profile}); got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestValidateRefusesABadHandWrittenProfile(t *testing.T) {
	found := false
	for _, i := range mustParse(t, "name: shop\nprofile: loose\n").Validate(nil) {
		found = found || i.Level == "error" && i.Field == "profile"
	}
	if !found {
		t.Error("an invalid profile is an error on the field profile")
	}
}
