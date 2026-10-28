package pipeline

import "testing"

func TestHostileLinksAreDropped(t *testing.T) {
	for _, u := range []string{"javascript:alert(1)", "https://a.test/x>|<!channel>", "https://a.test/a b", "ftp://a.test/x", "https:///nohost"} {
		if safeURL(u) {
			t.Errorf("%q must be refused", u)
		}
	}
	if !safeURL("https://a.test/path?q=1") {
		t.Error("plain https link refused")
	}
}
