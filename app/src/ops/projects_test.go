package ops

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func editable(t *testing.T, access map[string]config.Grant, actor string) *Session {
	t.Helper()
	cfg := bundle(t, access)
	cfg.Root = t.TempDir()
	cfg.Catalog = catalog.New(cfg.Techs)
	return open(t, cfg, seeded(t), actor)
}

var addPHP = []projectfile.Op{{Kind: "set_tech", Tech: "php", Version: "8.2"}}

func TestEditProjectPreviewDoesNotWrite(t *testing.T) {
	s := editable(t, nil, "alice")
	p, err := s.EditProject(ProjectChange{Project: "blog", Ops: addPHP})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Created || p.Saved || !strings.Contains(p.Diff, "php") || p.Blocked() {
		t.Fatalf("preview wrong: %+v", p)
	}
	if _, err := os.Stat(p.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview wrote the file")
	}
}

func TestEditProjectSavesAuditsAndBacksUp(t *testing.T) {
	s := editable(t, nil, "alice")
	if p, err := s.EditProject(ProjectChange{Project: "blog", Ops: addPHP, Save: true}); err != nil || !p.Saved {
		t.Fatalf("create: %+v %v", p, err)
	}
	more := []projectfile.Op{{Kind: "set_tech", Tech: "php", Version: "8.3"}}
	p, err := s.EditProject(ProjectChange{Project: "blog", Ops: more, Save: true})
	if err != nil || !p.Saved || p.Created {
		t.Fatalf("edit: %+v %v", p, err)
	}
	if b, _ := os.ReadFile(p.Path); !strings.Contains(string(b), "8.3") {
		t.Fatalf("file not updated:\n%s", b)
	}
	if bk, _ := os.ReadDir(s.Cfg.DataDir + "/project-backups"); len(bk) != 1 {
		t.Fatalf("want one backup, got %d", len(bk))
	}
	log, _ := os.ReadFile(s.Cfg.DataDir + "/audit.log")
	if strings.Count(string(log), `"action":"project"`) != 2 {
		t.Fatalf("audit log:\n%s", log)
	}
	if n, err := s.Audit.Verify(); err != nil || n != 2 {
		t.Fatalf("audit chain: %d %v", n, err)
	}
}

func TestEditProjectRefusesErrors(t *testing.T) {
	s := editable(t, nil, "alice")
	_, err := s.EditProject(ProjectChange{Project: "blog", Save: true,
		Ops: []projectfile.Op{{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "nope", Path: "x"}}}})
	if err == nil {
		t.Fatal("an invalid lockfile type was saved")
	}
	if _, err := s.EditProject(ProjectChange{Project: "../evil", Ops: addPHP, Save: true}); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestEditProjectAccessRules(t *testing.T) {
	acc := map[string]config.Grant{
		"bob":   {Projects: []string{"shop"}, Write: true},
		"carol": {Projects: []string{"shop"}},
		"root":  {Projects: []string{"*"}, Write: true},
	}
	bump := []projectfile.Op{{Kind: "set_tech", Tech: "php", Version: "8.4"}}
	seed := func(s *Session) {
		if _, err := os.Stat(s.projectsDir()); err != nil {
			os.MkdirAll(s.projectsDir(), 0o700)
		}
		os.WriteFile(s.projectsDir()+"/shop.yaml", []byte("name: shop\ntechs:\n  - {name: php, version: \"8.2\"}\n"), 0o600)
	}
	for _, c := range []struct {
		actor, project string
		save, ok       bool
	}{
		{"bob", "shop", true, true},
		{"bob", "blog", true, false},   // create needs everything
		{"carol", "shop", false, true}, // may preview what she can see
		{"carol", "shop", true, false}, // but not write
		{"nobody", "shop", false, false},
		{"root", "blog", true, true},
	} {
		s := editable(t, acc, c.actor)
		seed(s)
		_, err := s.EditProject(ProjectChange{Project: c.project, Ops: bump, Save: c.save})
		if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("%s %s save=%v: err=%v", c.actor, c.project, c.save, err)
		}
	}
}

func TestProjectNamesAreScoped(t *testing.T) {
	acc := map[string]config.Grant{"carol": {Projects: []string{"shop"}}}
	s := editable(t, acc, "carol")
	os.MkdirAll(s.projectsDir(), 0o700)
	for _, n := range []string{"shop", "mw"} {
		os.WriteFile(s.projectsDir()+"/"+n+".yaml", []byte("name: "+n+"\n"), 0o600)
	}
	got, err := s.ProjectNames()
	if err != nil || len(got) != 1 || got[0] != "shop" {
		t.Fatalf("got %v %v", got, err)
	}
}
