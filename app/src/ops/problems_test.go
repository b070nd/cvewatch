package ops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func writeProject(t *testing.T, s *Session, name, body string) {
	t.Helper()
	if err := os.MkdirAll(s.projectsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.projectsDir(), name+".yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findIssue(issues []projectfile.Issue, project, field, msg string) (projectfile.Issue, bool) {
	for _, i := range issues {
		if i.Project == project && i.Field == field && strings.Contains(i.Message, msg) {
			return i, true
		}
	}
	return projectfile.Issue{}, false
}

func TestProjectProblemsShowFixesAndTheFixesWork(t *testing.T) {
	s := editable(t, nil, "alice")
	os.WriteFile(filepath.Join(s.Cfg.Root, "package-lock.json"), []byte("{}"), 0o600)
	writeProject(t, s, "shop", "name: shop\ntechs: [{name: pph, version: \"8.2\"}]\nlockfiles:\n  - {type: composer, path: gone/composer.lock}\n  - {type: composer, path: package-lock.json}\n")
	writeProject(t, s, "mw", "name: mw\ntechs: [{name: php}]\n")
	writeProject(t, s, "broken", "name: [\n")

	issues, err := s.ProjectProblems("")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ project, field, msg, level, fix string }{
		{"shop", "lockfiles[0].path", "does not exist", "error", "remove lockfile gone/composer.lock"},
		{"shop", "lockfiles[1].type", "looks like", "warning", `use lockfile type "npm" for package-lock.json instead of "composer"`},
		{"shop", "techs[0]", "not in the catalog", "warning", `use technology name "php" instead of "pph"`},
		{"broken", "file", "projectfile", "error", ""},
	} {
		i, ok := findIssue(issues, c.project, c.field, c.msg)
		if !ok || i.Level != c.level {
			t.Fatalf("missing %s %s (%s): %+v", c.project, c.field, c.level, issues)
		}
		if c.fix == "" && len(i.Fixes) != 0 || c.fix != "" && (len(i.Fixes) != 1 || i.Fixes[0].Label != c.fix) {
			t.Errorf("%s %s: fixes = %+v, want %q", c.project, c.field, i.Fixes, c.fix)
		}
	}
	if _, ok := findIssue(issues, "mw", "", ""); ok {
		t.Errorf("clean project reported: %+v", issues)
	}
	for n, i := range issues {
		if i.Project == "" {
			t.Errorf("issue without project: %+v", i)
		}
		if n > 0 && issues[n-1].Level == "warning" && i.Level == "error" {
			t.Errorf("an error comes after a warning: %+v", issues)
		}
	}
	if issues[0].Project != "broken" || issues[1].Field != "lockfiles[0].path" {
		t.Errorf("order wrong: %+v", issues)
	}

	// applying every fix through EditProject leaves nothing behind
	for _, i := range issues {
		for _, fix := range i.Fixes {
			if _, err := s.EditProject(ProjectChange{Project: i.Project, Ops: fix.Ops, Save: true}); err != nil {
				t.Fatalf("%q: %v", fix.Label, err)
			}
		}
	}
	after, err := s.ProjectProblems("shop")
	if err != nil || len(after) != 0 {
		t.Fatalf("shop after fixes: %+v %v", after, err)
	}
	if one, err := s.ProjectProblems("broken"); err != nil || len(one) != 1 {
		t.Fatalf("one project: %+v %v", one, err)
	}
}

func TestProjectProblemsAreScopedByAccess(t *testing.T) {
	acc := map[string]config.Grant{"carol": {Projects: []string{"shop"}}}
	s := editable(t, acc, "carol")
	writeProject(t, s, "shop", "name: shop\ntechs: [{name: pph}]\n")
	writeProject(t, s, "mw", "name: mw\ntechs: [{name: pph}]\n")

	issues, err := s.ProjectProblems("")
	if err != nil || len(issues) != 1 || issues[0].Project != "shop" {
		t.Fatalf("got %+v %v", issues, err)
	}
	if _, err := s.ProjectProblems("mw"); !errors.Is(err, ErrDenied) {
		t.Fatalf("mw: %v", err)
	}
	if _, err := s.ProjectProblems("shop"); err != nil {
		t.Fatalf("shop: %v", err)
	}
	if _, err := s.ProjectProblems("../shop"); err == nil {
		t.Fatal("a bad name was accepted")
	}
	if _, err := editable(t, nil, "alice").ProjectProblems("nope"); err == nil {
		t.Fatal("a project without a file must be an error")
	}
	if got, err := editable(t, nil, "alice").ProjectProblems(""); err != nil || len(got) != 0 {
		t.Fatalf("no files: %+v %v", got, err)
	}
}

func TestProjectProblemsReportUnreadableLockfiles(t *testing.T) {
	s := editable(t, nil, "alice")
	bad := filepath.Join(s.Cfg.Root, "bad", "composer.lock")
	os.MkdirAll(filepath.Dir(bad), 0o755)
	os.WriteFile(bad, []byte("not json"), 0o600)
	gone := filepath.Join(s.Cfg.Root, "gone", "composer.lock")
	s.Cfg.Projects[0].Lockfiles = []model.Lockfile{{Type: "composer", Path: bad}, {Type: "composer", Path: gone}}
	writeProject(t, s, "shop", "name: shop\nlockfiles:\n  - {type: composer, path: "+bad+"}\n  - {type: composer, path: "+gone+"}\n")

	issues, err := s.ProjectProblems("shop")
	if err != nil {
		t.Fatal(err)
	}
	i, ok := findIssue(issues, "shop", "lockfiles[0]", "could not be read")
	if !ok || i.Level != "error" || len(i.Fixes) != 1 || i.Fixes[0].Label != "remove lockfile "+bad {
		t.Fatalf("unreadable lockfile: %+v", issues)
	}
	if len(issues) != 2 {
		t.Errorf("a missing file must be reported once: %+v", issues)
	}
	if _, err := s.EditProject(ProjectChange{Project: "shop", Ops: i.Fixes[0].Ops, Save: true}); err != nil {
		t.Fatal(err)
	}
}
