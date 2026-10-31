package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ops"
)

func runTech(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	return capture(t, func() error { return techCmd(root, args) })
}

func TestTechAddEditRemoveList(t *testing.T) {
	root := fixtureRoot(t)
	before := readFile(t, root, "config/techs.yaml")

	out, err := runTech(t, root, "add", "algolia", "-alias", "algolia", "-alias", "algolia search", "-category", "search")
	if err != nil || !strings.Contains(out, "+") || !strings.Contains(out, "not saved: add -yes") || readFile(t, root, "config/techs.yaml") != before {
		t.Fatalf("a preview writes nothing: %v\n%s", err, out)
	}
	if out, err = runTech(t, root, "add", "algolia", "-alias", "algolia search", "-cpe", "algolia:search", "-yes"); err != nil || !strings.Contains(out, "saved") {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := readFile(t, root, "config/techs.yaml"); !strings.Contains(got, "name: algolia") || !strings.Contains(got, "algolia search") {
		t.Fatalf("techs.yaml:\n%s", got)
	}
	if out, err = runTech(t, root, "list"); err != nil || !strings.Contains(out, "algolia") {
		t.Fatalf("list shows the user entries: %v\n%s", err, out)
	}
	if _, err = runTech(t, root, "add", "algolia"); err == nil {
		t.Fatal("a duplicate must be refused")
	}
	if _, err = runTech(t, root, "edit", "nginx", "-vendor", "x"); err == nil {
		t.Fatal("a name that is not the user's own cannot be edited")
	}
	if _, err = runTech(t, root, "edit", "algolia"); err == nil {
		t.Fatal("an edit without a flag must say so")
	}
	if out, err = runTech(t, root, "edit", "algolia", "-cpe", "", "-vendor", "Algolia SAS", "-yes"); err != nil || !strings.Contains(out, "saved") {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := readFile(t, root, "config/techs.yaml"); strings.Contains(got, "cpe") || !strings.Contains(got, "vendor: Algolia SAS") || !strings.Contains(got, "algolia search") {
		t.Fatalf("an empty -cpe clears, the others stay:\n%s", got)
	}
	if out, err = runTech(t, root, "remove", "algolia", "-yes"); err != nil || !strings.Contains(out, "saved") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = runTech(t, root, "list", "-json"); err != nil || strings.Contains(out, "algolia") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestCatalogSaysWhenNothingIsClose(t *testing.T) {
	root := fixtureRoot(t)
	run := func(args ...string) string {
		out, err := capture(t, func() error {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			return withReadSession(root, log, func(s *ops.Session) error { return catalogCmd(s, args) })
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := run("algolia")
	if !strings.Contains(out, `"algolia" is not in the catalog.`) || strings.Contains(out, "Did you mean") || !strings.Contains(out, "cvewatch tech add algolia") {
		t.Fatalf("%s", out)
	}
	if out = run("rabbitMW"); !strings.Contains(out, "Did you mean: rabbitmq") {
		t.Fatalf("%s", out)
	}
}

func TestProjectEditShowsHintsAndTheKeywordCommand(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runProject(t, root, "shop", "-set", "algolia=1")
	if err != nil || !strings.Contains(out, `"algolia" is not in the catalog`) || !strings.Contains(out, "cvewatch tech add algolia -yes") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Count(out, `"algolia" is not in the catalog`) != 1 {
		t.Fatalf("the warning and the hint are one line:\n%s", out)
	}
}
