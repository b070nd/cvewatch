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

func vendorRoot(t *testing.T) string {
	t.Helper()
	root := fixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, "config", "projects", "blog.yaml"), []byte("name: blog\nenvs: [dev]\ntechs: [{name: php}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func run(t *testing.T, root string, fn func(*ops.Session) error) (string, error) {
	t.Helper()
	return capture(t, func() error {
		return withSession(root, slog.New(slog.NewTextHandler(io.Discard, nil)), fn)
	})
}

func TestProjectVendorFlagSetsAndClears(t *testing.T) {
	root := vendorRoot(t)
	if _, err := runProject(t, root, "shop", "-vendor", "acme", "-save"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, root, "config/projects/shop.yaml"), "name: shop\nvendor: acme\n") {
		t.Fatalf("file:\n%s", readFile(t, root, "config/projects/shop.yaml"))
	}
	out, err := runProject(t, root, "list")
	if err != nil || !strings.Contains(out, "shop") || !strings.Contains(out, "acme") || !strings.Contains(out, "blog               -") {
		t.Fatalf("list shows the vendor, - for none: %v\n%s", err, out)
	}
	if _, err := runProject(t, root, "shop", "-vendor", "Not Valid", "-save"); err == nil {
		t.Fatal("a bad vendor must be refused")
	}
	if _, err := runProject(t, root, "shop", "-vendor", "", "-save"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, root, "config/projects/shop.yaml"), "vendor") {
		t.Fatal("an empty -vendor must clear it")
	}
}

func TestVendorFlagOnTheListingCommands(t *testing.T) {
	root := vendorRoot(t)
	if _, err := runProject(t, root, "shop", "-vendor", "acme", "-save"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list", "update", "run"} {
		o, err := parseList(name, []string{"-vendor", "ACME", "-project", "shop"})
		if err != nil || o.Vendor != "acme" || o.Project != "shop" {
			t.Errorf("%s: %+v %v", name, o.Filter, err)
		}
	}
	if _, err := parseList("list", []string{"-vendor", "no good"}); err == nil {
		t.Error("a bad vendor must be refused")
	}

	out, err := run(t, root, func(s *ops.Session) error { return exportCmd(s, []string{"-vendor", "acme", "-format", "csv"}) })
	if err != nil || !strings.Contains(out, ",acme") || strings.Contains(out, "blog") {
		t.Fatalf("export: %v\n%s", err, out)
	}
	out, err = run(t, root, func(s *ops.Session) error { return exportCmd(s, []string{"-vendor", "-", "-format", "json"}) })
	if err != nil || strings.Contains(out, `"project": "shop"`) {
		t.Fatalf("export -vendor -: %v\n%s", err, out)
	}
	out, err = run(t, root, func(s *ops.Session) error { return searchCmd(s, []string{"-vendor", "acme", "-json", "php"}) })
	if err != nil || !strings.Contains(out, `"vendor": "acme"`) {
		t.Fatalf("search: %v\n%s", err, out)
	}
	out, err = run(t, root, func(s *ops.Session) error { return searchCmd(s, []string{"-json", "vendor:acme env:prod"}) })
	if err != nil || strings.Count(out, `"env":`) != 1 || !strings.Contains(out, `"env": "prod"`) {
		t.Fatalf("search term: %v\n%s", err, out)
	}
}

func TestShowWhyAndEvidenceTakeAVendorOrProject(t *testing.T) {
	root := vendorRoot(t)
	if _, err := runProject(t, root, "shop", "-vendor", "acme", "-save"); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(*ops.Session, []string) error{"show": show, "evidence": evidenceCmd} {
		in, err := run(t, root, func(s *ops.Session) error { return fn(s, []string{"CVE-2026-1", "-json", "-vendor", "acme"}) })
		if err != nil || !strings.Contains(in, "shop") {
			t.Errorf("%s -vendor acme: %v\n%s", name, err, in)
		}
		out, err := run(t, root, func(s *ops.Session) error { return fn(s, []string{"CVE-2026-1", "-json", "-vendor", "-"}) })
		if err != nil || strings.Contains(out, `"project": "shop"`) {
			t.Errorf("%s -vendor -: %v\n%s", name, err, out)
		}
		if _, err := run(t, root, func(s *ops.Session) error { return fn(s, []string{"CVE-2026-1", "-vendor", "Bad Name"}) }); err == nil {
			t.Errorf("%s: a bad vendor must be refused", name)
		}
	}
	out, err := run(t, root, func(s *ops.Session) error { return why(s, []string{"CVE-2026-1", "-json", "-project", "blog"}) })
	if err != nil || strings.Contains(out, "shop") {
		t.Errorf("why -project blog: %v\n%s", err, out)
	}
}
