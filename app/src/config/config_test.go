package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func put(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaultsAndWarnings(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/a.yaml", "name: a\ntechs: [{name: cobol}]\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Interval.Hours() != 4 || len(b.Warnings) != 1 || len(b.Projects[0].EffectiveEnvs()) != 4 {
		t.Fatalf("%+v", b)
	}
}

func TestLoadRejectsMistakes(t *testing.T) {
	cases := map[string][2]string{
		"unknown key": {"config/config.yaml", "intervall: 1h\n"},
		"bad env":     {"config/projects/a.yaml", "name: a\nenvs: [qa]\n"},
		"bad source":  {"sources/s.yaml", "sources: [{id: x, type: rss}]\n"},
		"http source": {"sources/s.yaml", "sources: [{id: x, type: rss, url: 'http://a.test/f'}]\n"},
		"creds":       {"sources/s.yaml", "sources: [{id: x, type: rss, url: 'https://u:p@a.test/f'}]\n"},
		"retention":   {"config/config.yaml", "lookback: 100h\nretention: 120h\n"},
		"bad since":   {"config/projects/a.yaml", "name: a\nsince: soon\n"},
	}
	for name, c := range cases {
		root := t.TempDir()
		put(t, root, c[0], c[1])
		if _, err := Load(root); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: empty error", name)
		}
	}
}

func TestProjectSinceIsADateAndFutureDatesWarn(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/a.yaml", "name: a\ntechs: [{name: php}]\nsince: 2026-01-01\n")
	put(t, root, "config/projects/b.yaml", "name: b\ntechs: [{name: php}]\nsince: 2030-01-01\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := b.Projects[0].Since, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("since = %v, want %v", got, want)
	}
	if !b.Projects[1].Since.After(time.Now()) {
		t.Fatalf("since 2030 must be in the future: %v", b.Projects[1].Since)
	}
	if len(b.Warnings) != 1 || b.Warnings[0] != "project b: since 2030-01-01 is in the future, so every dated vulnerability is skipped for now" {
		t.Fatalf("warnings = %v", b.Warnings)
	}
}
