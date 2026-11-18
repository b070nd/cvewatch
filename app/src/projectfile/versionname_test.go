package projectfile

import (
	"strings"
	"testing"
)

func TestATechnologyNamedLikeAVersionOffersToBecomeTheVersion(t *testing.T) {
	f, err := Parse([]byte("name: shop\nenvs: [prod]\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: mysql}\n  - {name: v8-0-31}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got *Issue
	for _, i := range f.Validate(nil) {
		if strings.Contains(i.Message, "looks like a version") {
			got = &i
		}
	}
	if got == nil || got.Field != "techs[2]" || len(got.Fixes) != 1 {
		t.Fatalf("want one issue with one fix: %+v", got)
	}
	if err := f.Apply(got.Fixes[0].Ops...); err != nil {
		t.Fatal(err)
	}
	b, err := f.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "v8-0-31") || !strings.Contains(text, "mysql") || !strings.Contains(text, "8.0.31") {
		t.Errorf("mysql takes the version and the entry goes:\n%s", text)
	}
	if !versionAsName("8.0.31") || !versionAsName("v8-0-31") || versionAsName("php") || versionAsName("v8") {
		t.Error("versionAsName")
	}
}
