package ops

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// mismatchSession is lcSession with the shop's file called magento2-shop.yaml,
// like the sample config. With loaded, the session's configuration is the one
// config.Load makes from the folder, so it knows which file declared which name.
func mismatchSession(t *testing.T, loaded bool) *Session {
	t.Helper()
	s, _ := lcSession(t, "root", false)
	if err := os.Rename(filepath.Join(s.projectsDir(), "shop.yaml"), filepath.Join(s.projectsDir(), "magento2-shop.yaml")); err != nil {
		t.Fatal(err)
	}
	if loaded {
		b, err := config.LoadLenient(s.Cfg.Root)
		if err != nil {
			t.Fatal(err)
		}
		b.DataDir, b.AlertsDir, b.Catalog = s.Cfg.DataDir, s.Cfg.AlertsDir, s.Cfg.Catalog
		*s.Cfg = *b
	}
	return s
}

func eachResolution(t *testing.T, fn func(t *testing.T, s *Session)) {
	for name, loaded := range map[string]bool{"config knows the file": true, "file found on disk": false} {
		t.Run(name, func(t *testing.T) { fn(t, mismatchSession(t, loaded)) })
	}
}

func TestProjectNamesFollowTheNameInTheFile(t *testing.T) {
	eachResolution(t, func(t *testing.T, s *Session) {
		names, err := s.ProjectNames()
		if err != nil || !reflect.DeepEqual(names, []string{"mw", "shop"}) {
			t.Fatalf("%v %v", names, err)
		}
		if path, err := s.ProjectFile("shop"); err != nil || filepath.Base(path) != "magento2-shop.yaml" {
			t.Fatalf("%q %v", path, err)
		}
		if _, err := s.ProjectFile("magento2-shop"); err == nil || !strings.Contains(err.Error(), `file of project "shop"`) {
			t.Fatalf("the file name is not a project name: %v", err)
		}
		if _, err := s.EditProject(ProjectChange{Project: "magento2-shop", Ops: addPHP, Save: true}); err == nil {
			t.Fatal("an edit by file name must not touch the file of another project")
		}
	})
}

func TestProblemsNoteAFileNamedDifferently(t *testing.T) {
	eachResolution(t, func(t *testing.T, s *Session) {
		issues, err := s.ProjectProblems("shop")
		if err != nil {
			t.Fatal(err)
		}
		i, ok := findIssue(issues, "shop", "name", "file magento2-shop.yaml declares shop")
		if !ok || i.Level != "warning" {
			t.Fatalf("%+v", issues)
		}
		if _, ok := findIssue(issues, "mw", "name", "declares"); ok {
			t.Fatal("a file named after its project is fine")
		}
	})
}

func TestEditProjectWritesTheFileThatDeclaresTheName(t *testing.T) {
	eachResolution(t, func(t *testing.T, s *Session) {
		p, err := s.EditProject(ProjectChange{Project: "shop", Ops: []projectfile.Op{{Kind: "set_since", Since: "2026-01-02"}}, Save: true})
		if err != nil || !p.Saved || p.Created || filepath.Base(p.Path) != "magento2-shop.yaml" {
			t.Fatalf("%+v %v", p, err)
		}
		if !strings.Contains(readRoot(t, s, "config/projects/magento2-shop.yaml"), "2026-01-02") || exists(t, s, "config/projects/shop.yaml") {
			t.Fatal("the edit went to the wrong file")
		}
	})
}

func TestLifecycleOnAFileNamedDifferently(t *testing.T) {
	const old = "config/projects/magento2-shop.yaml"
	eachResolution(t, func(t *testing.T, s *Session) {
		t.Run("delete", func(t *testing.T) {
			p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", Apply: true, Confirm: true})
			if err != nil || !p.Applied || exists(t, s, old) || filepath.Base(p.Backup) != "magento2-shop-20261003-120000.yaml" {
				t.Fatalf("%+v %v", p, err)
			}
			if names, _ := s.ProjectNames(); !reflect.DeepEqual(names, []string{"mw"}) {
				t.Fatalf("names %v", names)
			}
		})
	})
	eachResolution(t, func(t *testing.T, s *Session) {
		p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDisable, Project: "shop", Apply: true})
		if err != nil || !p.Applied || exists(t, s, old) || !exists(t, s, old+".disabled") {
			t.Fatalf("%+v %v", p, err)
		}
		if off, _ := s.DisabledProjects(); !reflect.DeepEqual(off, []string{"shop"}) {
			t.Fatalf("disabled %v", off)
		}
		if path, ok := s.DisabledFile("shop"); !ok || filepath.Base(path) != "magento2-shop.yaml.disabled" {
			t.Fatalf("%q %v", path, ok)
		}
		if p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "shop", Apply: true}); err != nil || !p.Applied {
			t.Fatalf("%+v %v", p, err)
		}
		if !exists(t, s, old) || exists(t, s, old+".disabled") || exists(t, s, "config/projects/shop.yaml") {
			t.Fatal("enable must give the file its own name back")
		}
		configLoads(t, s)
	})
	eachResolution(t, func(t *testing.T, s *Session) {
		if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDisable, Project: "shop", Apply: true}); err != nil {
			t.Fatal(err)
		}
		p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", Apply: true, Confirm: true})
		if err != nil || exists(t, s, old+".disabled") || filepath.Base(p.Backup) != "magento2-shop-20261003-120000.yaml" {
			t.Fatalf("a disabled file goes too: %+v %v", p, err)
		}
	})
}

func TestRenameAndDuplicateOfAFileNamedDifferently(t *testing.T) {
	const old = "config/projects/magento2-shop.yaml"
	eachResolution(t, func(t *testing.T, s *Session) {
		if p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: "shop-eu", Apply: true}); err != nil || !p.Applied {
			t.Fatalf("%+v %v", p, err)
		}
		if !exists(t, s, "config/projects/shop-eu.yaml") || !exists(t, s, old) {
			t.Fatal("the copy is <newname>.yaml and the original stays")
		}
		p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true})
		if err != nil || !p.Applied || exists(t, s, old) || !strings.Contains(readRoot(t, s, "config/projects/webshop.yaml"), "name: webshop") {
			t.Fatalf("%+v %v", p, err)
		}
		if len(findingsOf(s.Ledger, "webshop")) == 0 || len(findingsOf(s.Ledger, "shop")) != 0 {
			t.Fatal("the findings follow the name")
		}
		configLoads(t, s)
	})
}

func TestNameTakenSeesAFileNamedDifferently(t *testing.T) {
	eachResolution(t, func(t *testing.T, s *Session) {
		// a copy named like the project that magento2-shop.yaml holds
		if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDuplicate, Project: "mw", NewName: "shop"}); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("err = %v", err)
		}
	})
}
