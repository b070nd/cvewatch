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

func TestLoadLenientDropsBrokenProjects(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [yaml, key, env, lock, good]}\n")
	put(t, root, "config/projects/good.yaml", "name: good\ntechs: [{name: php}]\n")
	put(t, root, "config/projects/yaml.yaml", "name: yaml\ntechs: [\n")
	put(t, root, "config/projects/key.yaml", "name: key\nbogus: 1\n")
	put(t, root, "config/projects/env.yaml", "name: env\nenvs: [qa]\n")
	put(t, root, "config/projects/lock.yaml", "name: lock\nlockfiles: [{type: nope, path: x}]\n")
	b, err := LoadLenient(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Projects) != 1 || b.Projects[0].Name != "good" {
		t.Fatalf("projects = %+v", b.Projects)
	}
	want := map[string]string{"yaml": "yaml", "key": "bogus", "env": `unknown env "qa"`, "lock": `lockfile type "nope"`}
	if len(b.Broken) != len(want) {
		t.Fatalf("broken = %+v", b.Broken)
	}
	for _, br := range b.Broken {
		sub, ok := want[br.Name]
		if !ok || !strings.Contains(br.Err, sub) || strings.Contains(br.Err, "\n") {
			t.Errorf("broken %+v, want %q", br, sub)
		}
		if br.File != filepath.Join(root, "config", "projects", br.Name+".yaml") {
			t.Errorf("file = %q", br.File)
		}
	}
}

func TestLoadStillFailsOnBrokenProject(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"yaml": {"name: a\ntechs: [\n", "a.yaml"},
		"key":  {"name: a\nbogus: 1\n", "bogus"},
		"env":  {"name: a\nenvs: [qa]\n", `unknown env "qa"`},
		"lock": {"name: a\nlockfiles: [{type: nope, path: x}]\n", `lockfile type "nope"`},
	}
	for name, c := range cases {
		root := t.TempDir()
		put(t, root, "config/projects/a.yaml", c.body)
		if _, err := Load(root); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load error = %v", name, err)
		}
		b, err := LoadLenient(root)
		if err != nil || len(b.Projects) != 0 || len(b.Broken) != 1 || !strings.Contains(b.Broken[0].Err, c.want) {
			t.Errorf("%s: LoadLenient = %+v, %v", name, b, err)
		}
	}
}

func TestLoadLenientStillFailsOnOtherProblems(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "intervall: 1h\n")
	put(t, root, "config/projects/bad.yaml", "name: bad\nenvs: [qa]\n")
	if _, err := LoadLenient(root); err == nil {
		t.Fatal("a broken config.yaml must stay fatal")
	}
}

func TestLoadLenientAccessNamesBrokenProjects(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [env]}\n")
	put(t, root, "config/projects/env.yaml", "name: env\nenvs: [qa]\n")
	if _, err := LoadLenient(root); err != nil {
		t.Fatalf("access to a broken project must stay valid: %v", err)
	}
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [nope]}\n")
	if _, err := LoadLenient(root); err == nil {
		t.Fatal("access to an unknown project must fail")
	}
}
