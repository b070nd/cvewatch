package ecosystem

import (
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

func TestCanonicalAndNormalize(t *testing.T) {
	for in, want := range map[string]string{"pip": "pypi", "PyPI": "pypi", "golang": "go", "Packagist": "composer", "maven": "maven", "weird": "weird"} {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
	cases := []struct{ eco, in, want string }{
		{"pip", "Django_REST.framework", "django-rest-framework"},
		{"pypi", "ruamel.yaml", "ruamel-yaml"},
		{"maven", "Org.Apache.Logging.Log4j/Log4j-Core", "org.apache.logging.log4j:log4j-core"},
		{"npm", "@Scope/Pkg", "@scope/pkg"},
		{"composer", "Symfony/Http-Kernel", "symfony/http-kernel"},
	}
	for _, c := range cases {
		if got := NormalizeName(c.eco, c.in); got != c.want {
			t.Errorf("NormalizeName(%q,%q) = %q, want %q", c.eco, c.in, got, c.want)
		}
	}
	if eco, ok := FromPURL("golang"); !ok || eco != model.EcoGo {
		t.Error("purl golang")
	}
	if _, ok := FromPURL("deb"); ok || Known("deb") {
		t.Error("deb is not an ecosystem we handle")
	}
}
