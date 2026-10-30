package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ops"
)

func runDiscover(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	return capture(t, func() error {
		return withSession(root, slog.New(slog.NewTextHandler(io.Discard, nil)), func(s *ops.Session) error { return discoverCmd(s, args) })
	})
}

func TestDiscoverFile(t *testing.T) {
	root := fixtureRoot(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(file, []byte("ARG PG=16\nFROM postgres:${PG}\nFROM nginx:1.25-alpine AS web\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runDiscover(t, root, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Looked at " + file, "postgresql", "16", "nginx", "1.25", "web-server"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	out, err = runDiscover(t, root, file, "-json")
	if err != nil || !strings.Contains(out, `"infra": true`) || !strings.Contains(out, `"category": "database"`) {
		t.Fatalf("json: %v\n%s", err, out)
	}

	if out, err = runDiscover(t, root, dir); err != nil || !strings.Contains(out, "Looked at "+dir) || strings.Contains(out, "(web-server)") {
		t.Fatalf("a folder scan keeps its output: %v\n%s", err, out)
	}
	other := filepath.Join(dir, "notes.txt")
	os.WriteFile(other, []byte("x"), 0o644)
	if _, err := runDiscover(t, root, other); err == nil || !strings.Contains(err.Error(), "not a Dockerfile") {
		t.Fatalf("err = %v", err)
	}
}
