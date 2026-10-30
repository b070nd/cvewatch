package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runSettings(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	return capture(t, func() error { return settingsCmd(root, args) })
}

func TestSettingsListGetAndSchema(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runSettings(t, root, "list")
	if err != nil || !strings.Contains(out, "Core\n  interval = 4h") || !strings.Contains(out, "HTTP\n  http.timeout = 30s") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = runSettings(t, root, "list", "http"); err != nil || strings.Contains(out, "interval") || !strings.Contains(out, "http.timeout") {
		t.Fatalf("a section filter: %v\n%s", err, out)
	}
	if _, err = runSettings(t, root, "list", "nonsense"); err == nil {
		t.Fatal("an unknown section must be an error")
	}
	if out, err = runSettings(t, root, "get", "http.timeout"); err != nil || strings.TrimSpace(out) != "http.timeout = 30s" {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = runSettings(t, root, "get", "http.retries"); err != nil || !strings.Contains(out, "http.retries =") && !strings.Contains(out, "not set") {
		t.Fatalf("an unset setting shows its default: %v\n%s", err, out)
	}
	if _, err = runSettings(t, root, "get", "no.such.thing"); err == nil {
		t.Fatal("an unknown path must be an error")
	}
	if out, err = runSettings(t, root, "schema", "HTTP"); err != nil || !strings.Contains(out, "http.timeout") || strings.Contains(out, "interval ") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = runSettings(t, root, "schema", "-json"); err != nil || !strings.Contains(out, `"path": "http.timeout"`) {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestSettingsEditPreviewsUnlessYes(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runSettings(t, root, "set", "http.timeout", "45s")
	if err != nil || !strings.Contains(out, "+  timeout: 45s") && !strings.Contains(out, "45s") || !strings.Contains(out, "not saved: add -yes") {
		t.Fatalf("%v\n%s", err, out)
	}
	if readFile(t, root, "config/config.yaml") != settingsText {
		t.Fatal("a preview wrote config.yaml")
	}
	out, err = runSettings(t, root, "set", "http.timeout", "45s", "-yes")
	if err != nil || !strings.Contains(out, "saved") || !strings.Contains(out, "next daemon cycle") {
		t.Fatalf("%v\n%s", err, out)
	}
	got := readFile(t, root, "config/config.yaml")
	if !strings.Contains(got, "timeout: 45s") || !strings.Contains(got, "# my settings") || !strings.Contains(got, "# daemon period") {
		t.Fatalf("value or comments lost:\n%s", got)
	}

	if _, err = runSettings(t, root, "unset", "http.timeout", "-yes"); err != nil || strings.Contains(readFile(t, root, "config/config.yaml"), "timeout") {
		t.Fatalf("unset: %v\n%s", err, readFile(t, root, "config/config.yaml"))
	}
	if _, err = runSettings(t, root, "add", "notify.digest.channels", "slack", "-yes"); err != nil || !strings.Contains(readFile(t, root, "config/config.yaml"), "slack") {
		t.Fatalf("add: %v\n%s", err, readFile(t, root, "config/config.yaml"))
	}
	if _, err = runSettings(t, root, "add", "policy.rules", `{"name":"slow","owner_within":"168h"}`, "-yes"); err != nil || !strings.Contains(readFile(t, root, "config/config.yaml"), "owner_within") {
		t.Fatalf("add a record: %v\n%s", err, readFile(t, root, "config/config.yaml"))
	}
}

func TestSettingsRefuseWhatDoesNotValidate(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runSettings(t, root, "set", "http.timeout", "soon", "-yes")
	if err == nil {
		t.Fatalf("a bad duration was accepted:\n%s", out)
	}
	if readFile(t, root, "config/config.yaml") != settingsText {
		t.Fatal("a rejected edit wrote the file")
	}
	if _, err = runSettings(t, root, "set", "http.timeout"); err == nil {
		t.Fatal("a missing value must be an error")
	}
	if _, err = runSettings(t, root, "frobnicate"); err == nil {
		t.Fatal("an unknown command must be an error")
	}
	if _, err = runSettings(t, root); err == nil {
		t.Fatal("no command must explain itself")
	}
}

func TestSettingsDiffNeverWrites(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runSettings(t, root, "diff", "set", "interval", "2h", "-yes")
	if err != nil || !strings.Contains(out, "2h") || strings.Contains(out, "next daemon cycle") {
		t.Fatalf("%v\n%s", err, out)
	}
	if readFile(t, root, "config/config.yaml") != settingsText {
		t.Fatal("diff wrote the file")
	}
	if _, err = runSettings(t, root, "diff"); err == nil {
		t.Fatal("diff needs an edit")
	}
}

func TestSettingsWorkOnABrokenConfig(t *testing.T) {
	root := fixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, "config", "config.yaml"), []byte("interval: [oops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runSettings(t, root, "list")
	if err != nil || !strings.Contains(out, "config: cannot be read") {
		t.Fatalf("a broken config.yaml must still list: %v\n%s", err, out)
	}
	if _, err = runSettings(t, root, "diff", "set", "interval", "2h"); err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("a field edit of a broken document must say why it cannot be made: %v", err)
	}
}

func TestSettingsHideSecrets(t *testing.T) {
	root := fixtureRoot(t)
	feed := "sources:\n  - id: priv\n    type: rss\n    url: https://feed.example.com/rss?token=SECRET-TOKEN\n    headers:\n      X-Key: SECRET-HEADER\n"
	os.WriteFile(filepath.Join(root, "sources", "s.yaml"), []byte(feed), 0o644)
	for _, args := range [][]string{
		{"list"},
		{"get", "sources.[id=priv].url"},
		{"get", "sources"},
		{"set", "sources.[id=priv].url", "https://feed.example.com/rss?token=SECRET-NEW"},
		{"set", "sources.[id=priv].headers.X-Key", "SECRET-OTHER"},
	} {
		out, _ := runSettings(t, root, args...)
		if strings.Contains(out, "SECRET") {
			t.Errorf("%v printed a secret:\n%s", args, out)
		}
	}
	if out, _ := runSettings(t, root, "get", "sources.[id=priv].url"); !strings.Contains(out, "(set)") {
		t.Errorf("a secret reads (set): %s", out)
	}
}
