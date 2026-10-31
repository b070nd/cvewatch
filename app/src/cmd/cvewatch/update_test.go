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

func runStatus(t *testing.T, root string) string {
	t.Helper()
	out, err := capture(t, func() error {
		return withSession(root, slog.New(slog.NewTextHandler(io.Discard, nil)), func(s *ops.Session) error { return statusCmd(s, nil) })
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProjectEditWritesTheUpdateBlock(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runProject(t, root, "shop", "-update-every", "2h", "-update-auto", "false")
	if err != nil || !strings.Contains(out, "every: 2h") || !strings.Contains(out, "auto: false") || !strings.Contains(out, "not saved: add -save") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(readFile(t, root, "config/projects/shop.yaml"), "update") {
		t.Fatal("a preview wrote the file")
	}
	if _, err := runProject(t, root, "shop", "-update-every", "2h", "-update-auto", "false", "-save"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "update:\n  every: 2h\n  auto: false\n") {
		t.Fatalf("file:\n%s", got)
	}
	if _, err := runProject(t, root, "shop", "-update-every", "default", "-update-auto", "true", "-save"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, "config/projects/shop.yaml"); strings.Contains(got, "update") {
		t.Fatalf("the defaults leave no block:\n%s", got)
	}
}

func TestProjectUpdateFlagsErrors(t *testing.T) {
	for _, args := range [][]string{
		{"shop", "-update-auto", "maybe"},
		{"shop", "-update-every", ""},
	} {
		if _, err := parseProjectEdit(args); err == nil {
			t.Errorf("%v should be rejected", args)
		}
	}
	if _, err := runProject(t, fixtureRoot(t), "shop", "-update-every", "1m", "-save"); err == nil {
		t.Error("a period under 5m must be an error")
	}
	e, err := parseProjectEdit([]string{"shop", "-update-auto", "true"})
	if err != nil || len(e.ops) != 1 || e.ops[0].Kind != "set_update" || e.ops[0].Every != "" || e.ops[0].Auto == nil || !*e.ops[0].Auto {
		t.Fatalf("auto alone: %+v %v", e, err)
	}
}

func TestStatusListsTheUpdateScheduleOfEveryProject(t *testing.T) {
	root := fixtureRoot(t)
	out := runStatus(t, root)
	if !strings.Contains(out, "\nProjects\n") || !strings.Contains(out, "shop") || !strings.Contains(out, "due now") || !strings.Contains(out, "last update never") {
		t.Fatalf("a project never updated is due:\n%s", out)
	}
	if _, err := runProject(t, root, "shop", "-update-auto", "false", "-save"); err != nil {
		t.Fatal(err)
	}
	if out = runStatus(t, root); !strings.Contains(out, "paused") {
		t.Fatalf("a project that opted out is paused:\n%s", out)
	}
	cfg := filepath.Join(root, "config", "config.yaml")
	if err := os.WriteFile(cfg, []byte(readFile(t, root, "config/config.yaml")+"update:\n  auto: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out = runStatus(t, root); !strings.Contains(out, "scheduled updates are off") || !strings.Contains(out, "manual") {
		t.Fatalf("with the main switch off the schedule is manual:\n%s", out)
	}
}
