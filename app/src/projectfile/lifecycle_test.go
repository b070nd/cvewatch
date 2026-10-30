package projectfile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

const sinceFile = `name: blog   # the blog
techs:
  - {name: php, version: "8.2"}
lockfiles:
  - {type: composer, path: composer.lock}   # backend
  - {type: npm, path: package-lock.json, env: prod, dev: true}
`

func TestSetSince(t *testing.T) {
	got := mustApply(t, sinceFile, Op{Kind: "set_since", Since: "2026-01-31"})
	f := mustParse(t, got)
	if y, m, d := f.Project().Since.Date(); y != 2026 || m != 1 || d != 31 {
		t.Fatalf("since not set:\n%s", got)
	}
	for _, keep := range []string{"# the blog", "# backend"} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost comment %q:\n%s", keep, got)
		}
	}
	if !strings.Contains(got, "since: 2026-01-31\n") {
		t.Errorf("date should be a plain scalar:\n%s", got)
	}
	// change in place, then clear
	got = mustApply(t, got, Op{Kind: "set_since", Since: "2026-02-01"})
	if strings.Count(got, "since:") != 1 || !strings.Contains(got, "2026-02-01") {
		t.Fatalf("not replaced:\n%s", got)
	}
	got = mustApply(t, got, Op{Kind: "set_since"})
	if strings.Contains(got, "since") || !mustParse(t, got).Project().Since.IsZero() {
		t.Fatalf("not cleared:\n%s", got)
	}
	if got != sinceFile {
		t.Fatalf("clearing should restore the file:\n%s", got)
	}
}

func TestSetSinceRejectsBadDates(t *testing.T) {
	for _, bad := range []string{"yesterday", "2026-13-01", "31-01-2026", "2026-1-1x"} {
		f := mustParse(t, sinceFile)
		err := f.Apply(Op{Kind: "set_since", Since: bad})
		if err == nil || !strings.Contains(err.Error(), "since") {
			t.Errorf("%q: err = %v", bad, err)
		}
		if mustBytes(t, f) != sinceFile {
			t.Errorf("%q changed the file", bad)
		}
	}
}

func TestFutureSinceWarns(t *testing.T) {
	f := mustParse(t, sinceFile)
	if err := f.Apply(Op{Kind: "set_since", Since: "2999-01-01"}); err != nil {
		t.Fatal(err)
	}
	var warned bool
	for _, i := range f.Validate(nil) {
		if i.Field == "since" && i.Level == "warning" && strings.Contains(i.Message, "future") {
			warned = true
		}
		if i.Level == "error" {
			t.Errorf("unexpected error %+v", i)
		}
	}
	if !warned {
		t.Fatal("no future-date warning")
	}
	if err := f.Apply(Op{Kind: "set_since", Since: "2020-01-01"}); err != nil {
		t.Fatal(err)
	}
	for _, i := range f.Validate(nil) {
		if i.Field == "since" {
			t.Errorf("past date warned: %+v", i)
		}
	}
}

func TestSetLockfileDev(t *testing.T) {
	got := mustApply(t, sinceFile, Op{Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "composer.lock", Dev: true}})
	ls := mustParse(t, got).Project().Lockfiles
	if !ls[0].Dev || !ls[1].Dev {
		t.Fatalf("dev not set: %+v\n%s", ls, got)
	}
	if !strings.Contains(got, "# backend") {
		t.Errorf("lost comment:\n%s", got)
	}
	// clearing drops the key; the env narrows which lockfile is meant
	got = mustApply(t, got, Op{Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "package-lock.json", Env: "prod"}})
	ls = mustParse(t, got).Project().Lockfiles
	if ls[1].Dev || !ls[0].Dev || strings.Count(got, "dev:") != 1 {
		t.Fatalf("dev not cleared on the npm lockfile only: %+v\n%s", ls, got)
	}
	// setting what is already set changes nothing
	if again := mustApply(t, got, Op{Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "composer.lock", Dev: true}}); again != got {
		t.Fatalf("not idempotent:\n%s", again)
	}
}

func TestSetLockfileDevErrors(t *testing.T) {
	for name, op := range map[string]Op{
		"unknown path": {Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "nope.lock", Dev: true}},
		"wrong env":    {Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "composer.lock", Env: "prod", Dev: true}},
		"bad env":      {Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "composer.lock", Env: "qa", Dev: true}},
	} {
		f := mustParse(t, sinceFile)
		if err := f.Apply(op); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if mustBytes(t, f) != sinceFile {
			t.Errorf("%s: changed the file", name)
		}
	}
	f := mustParse(t, "name: bare\n")
	if err := f.Apply(Op{Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "x", Dev: true}}); err == nil {
		t.Error("a project without lockfiles accepted a dev flag")
	}
}

func TestSetName(t *testing.T) {
	f := mustParse(t, sinceFile)
	if err := f.SetName("blog2"); err != nil {
		t.Fatal(err)
	}
	got := mustBytes(t, f)
	if !strings.HasPrefix(got, "name: blog2") || !strings.Contains(got, "# the blog") || mustParse(t, got).Project().Name != "blog2" {
		t.Fatalf("name not rewritten in place:\n%s", got)
	}
	if err := f.SetName("Bad Name"); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestArchiveMovesTheFileToBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "projects", "shop.yaml")
	backups := filepath.Join(dir, "backups")
	if err := Write(path, []byte("name: shop\n"), backups, time.Time{}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 28, 9, 30, 5, 0, time.UTC)
	got, err := Archive(path, backups, t0)
	if err != nil || got != filepath.Join(backups, "shop-20261028-093005.yaml") {
		t.Fatalf("got %q %v", got, err)
	}
	if b, _ := os.ReadFile(got); string(b) != "name: shop\n" {
		t.Fatal("backup lost the content")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("original still there")
	}
	if _, err := Archive(path, backups, t0); err == nil {
		t.Fatal("archiving a missing file succeeded")
	}
}

func TestDisabledFiles(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"shop.yaml", "old.yaml.disabled", "x.yaml.disabled.bak", ".hid.yaml.disabled", "notes.disabled"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("name: x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := ListDisabled(dir); err != nil || !reflect.DeepEqual(got, []string{"old"}) {
		t.Fatalf("got %v %v", got, err)
	}
	if got, _ := List(dir); !reflect.DeepEqual(got, []string{"shop"}) {
		t.Fatalf("a disabled file is listed as live: %v", got)
	}
	if p, err := DisabledPath(dir, "old"); err != nil || p != filepath.Join(dir, "old.yaml.disabled") {
		t.Fatalf("got %q %v", p, err)
	}
	if _, err := DisabledPath(dir, "../x"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if got, err := ListDisabled(filepath.Join(dir, "missing")); err != nil || len(got) != 0 {
		t.Fatalf("missing dir: %v %v", got, err)
	}
	// a disabled file's backup is named after the project
	if got := BackupTarget(filepath.Join(dir, "old.yaml.disabled"), "b", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); got != filepath.Join("b", "old-20260102-030405.yaml") {
		t.Fatalf("got %q", got)
	}
}
