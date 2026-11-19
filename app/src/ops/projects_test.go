package ops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

var addPHP = []projectfile.Op{{Kind: projectfile.KindSetTech, Tech: "php", Version: "8.2"}}

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
	more := []projectfile.Op{{Kind: projectfile.KindSetTech, Tech: "php", Version: "8.3"}}
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
		Ops: []projectfile.Op{{Kind: projectfile.KindAddLockfile, Lockfile: model.Lockfile{Type: "nope", Path: "x"}}}})
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
	bump := []projectfile.Op{{Kind: projectfile.KindSetTech, Tech: "php", Version: "8.4"}}
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

func TestEditProjectWritesTheUpdateBlockAndTheViewShowsIt(t *testing.T) {
	s := editable(t, nil, "alice")
	paused := false
	p, err := s.EditProject(ProjectChange{Project: "blog", Ops: append(addPHP, projectfile.Op{Kind: projectfile.KindSetUpdate, Every: "2h", Auto: &paused}), Save: true})
	if err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	if b, _ := os.ReadFile(p.Path); !strings.Contains(string(b), "update:\n  every: 2h\n  auto: false\n") {
		t.Fatalf("block not written:\n%s", b)
	}
	if _, err := s.EditProject(ProjectChange{Project: "blog", Ops: []projectfile.Op{{Kind: projectfile.KindSetUpdate, Every: "1m"}}, Save: true}); err == nil {
		t.Error("a period under 5m is refused")
	}
	v := ViewOf(model.Project{Name: "blog", Update: model.ProjectUpdate{Auto: &paused, Every: 2 * time.Hour}})
	if v.Update == nil || v.Update.Auto || v.Update.Every != "2h" {
		t.Errorf("view = %+v", v.Update)
	}
	if ViewOf(model.Project{Name: "blog"}).Update != nil {
		t.Error("no block, no view of one")
	}
}

func TestLockfileOpsAcceptDeclaredOrResolvedPath(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/projects/blog.yaml", "name: blog\nlockfiles:\n  - {type: composer, path: ../shop/composer.lock}\n  - {type: npm, path: web/package-lock.json, env: prod}\n  - {type: npm, path: web/../web/package-lock.json, env: dev}\n")
	resolved := filepath.Join(s.Cfg.Root, "..", "shop", "composer.lock")
	resolved = filepath.Clean(resolved)

	// the resolved path, as listings show it, is enough
	p, err := s.EditProject(ProjectChange{Project: "blog", Save: true, Ops: []projectfile.Op{
		{Kind: projectfile.KindSetLockfileDev, Lockfile: model.Lockfile{Path: resolved, Dev: true}}}})
	if err != nil || !p.Saved || len(p.Result.Lockfiles) != 3 || !p.Result.Lockfiles[0].Dev || p.Result.Lockfiles[0].Path != "../shop/composer.lock" {
		t.Fatalf("%+v %v", p.Result.Lockfiles, err)
	}
	p, err = s.EditProject(ProjectChange{Project: "blog", Save: true, Ops: []projectfile.Op{
		{Kind: projectfile.KindRemoveLockfile, Lockfile: model.Lockfile{Path: resolved}}}})
	if err != nil || len(p.Result.Lockfiles) != 2 {
		t.Fatalf("%+v %v", p.Result.Lockfiles, err)
	}
	if strings.Contains(readRoot(t, s, "config/projects/blog.yaml"), "composer") {
		t.Fatal("lockfile still declared")
	}

	// the declared spelling still works, and wins over a resolved match
	if p, err = s.EditProject(ProjectChange{Project: "blog", Ops: []projectfile.Op{
		{Kind: projectfile.KindRemoveLockfile, Lockfile: model.Lockfile{Path: "web/../web/package-lock.json"}}}}); err != nil || len(p.Result.Lockfiles) != 1 {
		t.Fatalf("%+v %v", p.Result.Lockfiles, err)
	}

	// two spellings of the same file are ambiguous without an env, and named in the error
	abs := filepath.Join(s.Cfg.Root, "web", "package-lock.json")
	_, err = s.EditProject(ProjectChange{Project: "blog", Ops: []projectfile.Op{{Kind: projectfile.KindRemoveLockfile, Lockfile: model.Lockfile{Path: abs}}}})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), "web/package-lock.json") || !strings.Contains(err.Error(), "web/../web/package-lock.json") {
		t.Fatalf("err = %v", err)
	}
	// an env picks one
	if p, err = s.EditProject(ProjectChange{Project: "blog", Ops: []projectfile.Op{{Kind: projectfile.KindRemoveLockfile, Lockfile: model.Lockfile{Path: abs, Env: "dev"}}}}); err != nil || len(p.Result.Lockfiles) != 1 || p.Result.Lockfiles[0].Env != "prod" {
		t.Fatalf("%+v %v", p.Result.Lockfiles, err)
	}
	// an unknown path keeps today's error
	if _, err = s.EditProject(ProjectChange{Project: "blog", Ops: []projectfile.Op{{Kind: projectfile.KindRemoveLockfile, Lockfile: model.Lockfile{Path: "nope.lock"}}}}); err == nil || !strings.Contains(err.Error(), "no lockfile with path") {
		t.Fatalf("err = %v", err)
	}
}

func TestANewProjectCanStartFromATemplate(t *testing.T) {
	s := editable(t, nil, "alice")
	dir := config.ProjectsDir(s.Cfg.Root)
	os.MkdirAll(dir, 0o755)
	tmpl := "# the team's web shop layout\nname: webshop\nenvs: [local, prod] # our two\ntechs:\n  - {name: php, version: \"8.2\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "webshop.yaml.dist"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}
	if names, err := s.ProjectTemplates(); err != nil || len(names) != 1 || names[0] != "webshop" {
		t.Fatalf("templates: %v %v", names, err)
	}
	p, err := s.EditProject(ProjectChange{Project: "blog", Template: "webshop", Save: true})
	if err != nil || !p.Saved || !p.Created {
		t.Fatalf("%+v %v", p, err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "blog.yaml"))
	if !strings.Contains(string(got), "name: blog") || !strings.Contains(string(got), "envs: [local, prod] # our two") || !strings.Contains(string(got), "# the team's web shop layout") {
		t.Fatalf("the template is copied with the new name and its comments:\n%s", got)
	}
	if _, err := s.EditProject(ProjectChange{Project: "blog", Template: "webshop"}); err == nil {
		t.Fatal("a template only starts a new project")
	}
	if _, err := s.EditProject(ProjectChange{Project: "news", Template: "../config"}); err == nil || !strings.Contains(err.Error(), "no project template") {
		t.Fatalf("only a listed template is read: %v", err)
	}
	if n, err := s.Audit.Verify(); err != nil || n != 1 {
		t.Fatalf("the creation is audited: n=%d err=%v", n, err)
	}
}
