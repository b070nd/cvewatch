package ops

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/store"
)

const (
	lcShop = "# the shop\nname: shop   # prod webshop\ntechs:\n  - {name: php, version: \"8.2\"}\nlockfiles: []\n"
	lcMW   = "name: mw\nenvs: [prod]\n"
	lcCfg  = "# who may do what\naccess:\n  root: {projects: ['*'], write: true}\n  alice: {projects: [shop, mw], write: true}   # shop team\n  bob: {projects: [shop]}\n"
)

func lcAccess() map[string]config.Grant {
	return map[string]config.Grant{
		"root":  {Projects: []string{"*"}, Write: true},
		"alice": {Projects: []string{"shop", "mw"}, Write: true},
		"bob":   {Projects: []string{"shop"}},
	}
}

// lcSession opens a session on a folder holding the projects shop and mw and,
// with access, the matching rules in config.yaml.
func lcSession(t *testing.T, actor string, access bool) (*Session, store.Storage) {
	t.Helper()
	var acc map[string]config.Grant
	if access {
		acc = lcAccess()
	}
	cfg := bundle(t, acc)
	cfg.Root = t.TempDir()
	cfg.Catalog = catalog.New(cfg.Techs)
	st := seeded(t)
	s := open(t, cfg, st, actor)
	writeRoot(t, s, "config/projects/shop.yaml", lcShop)
	writeRoot(t, s, "config/projects/mw.yaml", lcMW)
	if access {
		writeRoot(t, s, "config/config.yaml", lcCfg)
	}
	return s, st
}

// snapshot is every file under the config folder, data folder and alerts folder.
func snapshot(t *testing.T, s *Session) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range []string{s.Cfg.Root, s.Cfg.DataDir, s.Cfg.AlertsDir} {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(p)
				out[p] = string(b)
			}
			return nil
		})
	}
	return out
}

func stored(t *testing.T, st store.Storage) *ledger.Ledger {
	t.Helper()
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	return ledger.New(state)
}

func findingsOf(l *ledger.Ledger, project string) []model.Finding {
	var out []model.Finding
	for _, f := range l.Findings() {
		if f.Project == project {
			out = append(out, f)
		}
	}
	return out
}

func exists(t *testing.T, s *Session, rel string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(s.Cfg.Root, filepath.FromSlash(rel)))
	return err == nil
}

func configLoads(t *testing.T, s *Session) {
	t.Helper()
	if _, issues := config.Check(s.Cfg.Root, nil); len(issues) > 0 {
		t.Fatalf("the configuration does not load: %+v", issues)
	}
}

func events(t *testing.T, s *Session) []string {
	t.Helper()
	evs, err := s.Audit.Events()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		out = append(out, e.Action+": "+e.Note)
	}
	return out
}

func TestLifecyclePreviewHasNoSideEffects(t *testing.T) {
	for _, c := range []struct {
		req     LifecycleRequest
		destroy bool
	}{
		{LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop"}, true},
		{LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: "shop2"}, false},
		{LifecycleRequest{Verb: VerbDelete, Project: "shop"}, true},
		{LifecycleRequest{Verb: VerbDisable, Project: "shop"}, true}, // drops access rules
	} {
		s, _ := lcSession(t, "root", true)
		before, findings := snapshot(t, s), s.Ledger.Findings()
		p, err := s.ProjectLifecycle(c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.req.Verb, err)
		}
		if p.Applied || p.Destructive != c.destroy || p.RequiresConfirm != c.destroy || len(p.Files) == 0 {
			t.Errorf("%s: %+v", c.req.Verb, p)
		}
		if p.Findings.Total != 1 || p.Findings.ByStatus[model.StatusOpen] != 1 {
			t.Errorf("%s: findings %+v", c.req.Verb, p.Findings)
		}
		if c.req.Verb != VerbDuplicate && (len(p.Access) != 2 || p.Access[0].Actor != "alice" || p.Access[1].Actor != "bob") {
			t.Errorf("%s: access %+v", c.req.Verb, p.Access)
		}
		if !reflect.DeepEqual(before, snapshot(t, s)) || !reflect.DeepEqual(findings, s.Ledger.Findings()) {
			t.Errorf("%s: the preview changed something", c.req.Verb)
		}
	}
}

func TestRenameMigratesFindingsFilesAndAccess(t *testing.T) {
	s, st := lcSession(t, "root", true)
	configLoads(t, s)
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true})
	if err != nil || !p.Applied {
		t.Fatalf("%+v %v", p, err)
	}
	if exists(t, s, "config/projects/shop.yaml") {
		t.Fatal("the old file is still loaded")
	}
	got := readRoot(t, s, "config/projects/webshop.yaml")
	if !strings.Contains(got, "name: webshop") || !strings.Contains(got, "# the shop") || !strings.Contains(got, "# prod webshop") {
		t.Fatalf("file:\n%s", got)
	}
	if b, err := os.ReadFile(p.Backup); err != nil || string(b) != lcShop {
		t.Fatalf("backup %q: %v", p.Backup, err)
	}
	cfg := readRoot(t, s, "config/config.yaml")
	if strings.Contains(cfg, "[shop") || !strings.Contains(cfg, "[webshop, mw]") || !strings.Contains(cfg, "bob: {projects: [webshop]}") || !strings.Contains(cfg, "# shop team") || !strings.Contains(cfg, "# who may do what") {
		t.Fatalf("access not rewritten, or comments lost:\n%s", cfg)
	}
	if bk, _ := os.ReadDir(filepath.Join(s.Cfg.DataDir, "config-backups")); len(bk) != 1 {
		t.Fatalf("want a backup of config.yaml, got %d", len(bk))
	}
	for _, l := range []*ledger.Ledger{s.Ledger, stored(t, st)} {
		if len(findingsOf(l, "shop")) != 0 || len(findingsOf(l, "webshop")) != 1 || len(findingsOf(l, "mw")) != 1 {
			t.Fatalf("findings: %+v", l.Findings())
		}
	}
	rep, _ := filepath.Glob(filepath.Join(s.Cfg.AlertsDir, "*", "*.md"))
	if len(rep) != 1 {
		t.Fatalf("reports: %v", rep)
	}
	if b, _ := os.ReadFile(rep[0]); !strings.Contains(string(b), "webshop") || strings.Contains(string(b), "| shop |") {
		t.Fatalf("report still names the old project:\n%s", b)
	}
	configLoads(t, s)
	if ev := events(t, s); len(ev) != 1 || !strings.HasPrefix(ev[0], "project: renamed project to webshop") || !strings.Contains(ev[0], "alice") {
		t.Fatalf("audit: %v", ev)
	}
	if n, err := s.Audit.Verify(); err != nil || n != 1 {
		t.Fatalf("chain %d %v", n, err)
	}
}

func TestDestructiveVerbsNeedConfirm(t *testing.T) {
	for _, req := range []LifecycleRequest{
		{Verb: VerbRename, Project: "mw", NewName: "mw2"},
		{Verb: VerbDelete, Project: "mw"},
	} {
		s, _ := lcSession(t, "root", false)
		before := snapshot(t, s)
		req.Apply = true
		p, err := s.ProjectLifecycle(req)
		if !errors.Is(err, ErrConfirm) || p.Applied || !p.RequiresConfirm {
			t.Fatalf("%s: %+v %v", req.Verb, p, err)
		}
		if !reflect.DeepEqual(before, snapshot(t, s)) {
			t.Fatalf("%s changed things without a confirmation", req.Verb)
		}
		req.Confirm = true
		if p, err := s.ProjectLifecycle(req); err != nil || !p.Applied {
			t.Fatalf("%s confirmed: %+v %v", req.Verb, p, err)
		}
	}
	// with nobody's rules naming the project, disable loses nothing and needs no confirmation
	s, _ := lcSession(t, "root", false)
	if p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDisable, Project: "mw", Apply: true}); err != nil || !p.Applied || p.RequiresConfirm {
		t.Fatalf("disable: %+v %v", p, err)
	}
	if p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: "shop2", Apply: true}); err != nil || !p.Applied {
		t.Fatalf("duplicate: %+v %v", p, err)
	}
}

func TestLifecycleNamesAndCollisions(t *testing.T) {
	s, _ := lcSession(t, "root", false)
	writeRoot(t, s, "config/projects/parked.yaml.disabled", "name: parked\n")
	for _, c := range []struct {
		req  LifecycleRequest
		want string
	}{
		{LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "mw"}, "already exists"},
		{LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: "parked"}, "already exists"},
		{LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "shop"}, "same as the old"},
		{LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "Bad Name"}, "invalid project name"},
		{LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "../evil"}, "invalid project name"},
		{LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: ""}, "invalid project name"},
		{LifecycleRequest{Verb: VerbRename, Project: "nope", NewName: "x"}, "unknown project"},
		{LifecycleRequest{Verb: VerbDelete, Project: "../x"}, "invalid project name"},
		{LifecycleRequest{Verb: VerbRename, Project: "parked", NewName: "x"}, "disabled"},
		{LifecycleRequest{Verb: VerbEnable, Project: "shop"}, "already enabled"},
		{LifecycleRequest{Verb: VerbEnable, Project: "nope"}, "no disabled project"},
		{LifecycleRequest{Verb: "explode", Project: "shop"}, "unknown verb"},
		{LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "x", CloseFindings: true}, "delete only"},
	} {
		c.req.Apply, c.req.Confirm = true, true
		before := snapshot(t, s)
		if _, err := s.ProjectLifecycle(c.req); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: err = %v, want %q", c.req, err, c.want)
		}
		if !reflect.DeepEqual(before, snapshot(t, s)) {
			t.Errorf("%+v: a refused request changed files", c.req)
		}
	}
	if len(findingsOf(s.Ledger, "shop")) != 1 {
		t.Fatal("findings changed")
	}
}

func TestRenameRefusesFindingsThatWouldCollide(t *testing.T) {
	s, st := lcSession(t, "root", false)
	// an earlier project named "old" left a finding with the same key as shop's
	for _, f := range s.Ledger.Findings() {
		if f.Project == "shop" {
			f.Project = "old"
			s.Ledger.AddFinding(f)
		}
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "old", Apply: true, Confirm: true}); err == nil || !strings.Contains(err.Error(), "already holds a finding") {
		t.Fatalf("err = %v", err)
	}
	if len(findingsOf(stored(t, st), "shop")) != 1 || exists(t, s, "config/projects/old.yaml") {
		t.Fatal("state changed")
	}
	// a duplicate under that name is fine and says what it joins
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: "old"})
	if err != nil || !strings.Contains(strings.Join(p.Warnings, "|"), `under the name "old"`) {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestLifecycleAccessRules(t *testing.T) {
	req := func(v LifecycleVerb) LifecycleRequest {
		return LifecycleRequest{Verb: v, Project: "shop", NewName: "shop2", Apply: true, Confirm: true}
	}
	for _, c := range []struct {
		actor string
		verb  LifecycleVerb
		ok    bool
	}{
		{"root", VerbRename, true},
		{"alice", VerbRename, false}, // the new name is in nobody's rules
		{"alice", VerbDuplicate, false},
		{"alice", VerbDelete, false}, // it would rewrite the access rules
		{"bob", VerbDelete, false},
		{"bob", VerbDisable, false},
		{"mallory", VerbRename, false},
	} {
		s, st := lcSession(t, c.actor, true)
		before := snapshot(t, s)
		p, err := s.ProjectLifecycle(req(c.verb))
		if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("%s %s: %+v %v", c.actor, c.verb, p, err)
		}
		if !c.ok && (!reflect.DeepEqual(before, snapshot(t, s)) || len(findingsOf(stored(t, st), "shop")) != 1) {
			t.Errorf("%s %s: a refused request changed things", c.actor, c.verb)
		}
	}
	// someone who may see the project can still see the consequences
	s, _ := lcSession(t, "bob", true)
	r := req(VerbDelete)
	r.Apply = false
	if p, err := s.ProjectLifecycle(r); err != nil || p.Findings.Total != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	s, _ = lcSession(t, "bob", true)
	r.Project = "mw"
	if _, err := s.ProjectLifecycle(r); !errors.Is(err, ErrDenied) {
		t.Fatalf("bob previewed a project he cannot see: %v", err)
	}
	// a read-only session previews but never applies
	s, _ = lcSession(t, "root", false)
	s.readOnly = true
	if _, err := s.ProjectLifecycle(req(VerbDuplicate)); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only: %v", err)
	}
}

func TestDeleteBacksUpAndLeavesFindingsLikeReconcileDoes(t *testing.T) {
	s, st := lcSession(t, "root", true)
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", Apply: true, Confirm: true})
	if err != nil || !p.Applied {
		t.Fatalf("%+v %v", p, err)
	}
	if exists(t, s, "config/projects/shop.yaml") {
		t.Fatal("file not removed")
	}
	if b, err := os.ReadFile(p.Backup); err != nil || string(b) != lcShop || filepath.Dir(p.Backup) != filepath.Join(s.Cfg.DataDir, "project-backups") {
		t.Fatalf("backup %q: %v", p.Backup, err)
	}
	if f := findingsOf(stored(t, st), "shop"); len(f) != 1 || f[0].Status != model.StatusOpen || len(f[0].History) != 0 {
		t.Fatalf("findings must stay as they are: %+v", f)
	}
	cfg := readRoot(t, s, "config/config.yaml")
	// bob had no other project, so his rule goes with it
	if strings.Contains(cfg, "[shop") || !strings.Contains(cfg, "alice: {projects: [mw], write: true}") || strings.Contains(cfg, "bob") || !strings.Contains(cfg, "# who may do what") {
		t.Fatalf("access:\n%s", cfg)
	}
	if !strings.Contains(strings.Join(p.Warnings, "|"), "bob is left with no project") {
		t.Fatalf("warnings: %v", p.Warnings)
	}
	configLoads(t, s)
	if ev := events(t, s); len(ev) != 1 || !strings.Contains(ev[0], "deleted project") || !strings.Contains(ev[0], "1 findings kept") {
		t.Fatalf("audit: %v", ev)
	}
}

func TestDeleteCanCloseOpenFindings(t *testing.T) {
	s, st := lcSession(t, "root", false)
	// a second, already fixed finding stays fixed
	v := s.Ledger.Relevant()[0]
	s.Ledger.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvDev, Status: model.StatusFixed, Note: "patched"})
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", CloseFindings: true})
	if err != nil || p.Findings.Total != 2 || !strings.Contains(strings.Join(p.Warnings, "|"), "1 open findings are marked ignored") {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", CloseFindings: true, Apply: true, Confirm: true}); err != nil {
		t.Fatal(err)
	}
	got := map[model.Env]model.Finding{}
	for _, f := range findingsOf(stored(t, st), "shop") {
		got[f.Env] = f
	}
	prod, dev := got[model.EnvProd], got[model.EnvDev]
	if prod.Status != model.StatusIgnored || prod.Note != "project deleted" || len(prod.History) != 1 || prod.History[0].Actor != "root" {
		t.Fatalf("open finding: %+v", prod)
	}
	if dev.Status != model.StatusFixed || dev.Note != "patched" {
		t.Fatalf("fixed finding changed: %+v", dev)
	}
	if mw := findingsOf(stored(t, st), "mw"); len(mw) != 1 || mw[0].Status != model.StatusOpen {
		t.Fatal("another project's findings changed")
	}
}

func TestDisableAndEnableRoundTrip(t *testing.T) {
	s, st := lcSession(t, "root", true)
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDisable, Project: "shop", Apply: true}); !errors.Is(err, ErrConfirm) {
		t.Fatalf("disabling drops access rules, so it needs confirmation: %v", err)
	}
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDisable, Project: "shop", Apply: true, Confirm: true})
	if err != nil || !p.Applied {
		t.Fatalf("%+v %v", p, err)
	}
	if exists(t, s, "config/projects/shop.yaml") || readRoot(t, s, "config/projects/shop.yaml.disabled") != lcShop {
		t.Fatal("file not parked")
	}
	if names, _ := s.ProjectNames(); !reflect.DeepEqual(names, []string{"mw"}) {
		t.Fatalf("names %v", names)
	}
	if dis, err := s.DisabledProjects(); err != nil || !reflect.DeepEqual(dis, []string{"shop"}) {
		t.Fatalf("disabled %v %v", dis, err)
	}
	configLoads(t, s) // the access rules no longer name it
	if f := findingsOf(stored(t, st), "shop"); len(f) != 1 || f[0].Status != model.StatusOpen {
		t.Fatalf("findings: %+v", f)
	}
	// a restricted actor sees no disabled projects
	r := *s
	r.Actor = "alice"
	r.Cfg = &config.Bundle{Settings: config.Settings{Access: lcAccess()}}
	if dis, _ := r.DisabledProjects(); len(dis) != 0 {
		t.Fatalf("restricted actor sees %v", dis)
	}

	e, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "shop"})
	if err != nil || e.Destructive || e.Findings.Total != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	if e, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "shop", Apply: true}); err != nil || !e.Applied {
		t.Fatalf("%+v %v", e, err)
	}
	if readRoot(t, s, "config/projects/shop.yaml") != lcShop || exists(t, s, "config/projects/shop.yaml.disabled") {
		t.Fatal("not restored")
	}
	configLoads(t, s)
	if ev := events(t, s); len(ev) != 2 || !strings.Contains(ev[0], "disabled project") || !strings.Contains(ev[1], "enabled project") {
		t.Fatalf("audit: %v", ev)
	}
}

func TestEnableRefusesWhatWouldBreakTheConfiguration(t *testing.T) {
	s, _ := lcSession(t, "root", false)
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDisable, Project: "shop", Apply: true}); err != nil {
		t.Fatal(err)
	}
	// another file now declares the name the disabled one wants back
	writeRoot(t, s, "config/projects/other.yaml", "name: shop\n")
	before := snapshot(t, s)
	_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "shop", Apply: true})
	if err == nil || !strings.Contains(err.Error(), "would not load") {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s)) {
		t.Fatal("files changed")
	}
	// a live file of that name is a plain refusal
	writeRoot(t, s, "config/projects/shop.yaml", "name: shop\n")
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "shop", Apply: true}); err == nil || !strings.Contains(err.Error(), "already enabled") {
		t.Fatalf("err = %v", err)
	}
	// a disabled file with errors is not brought back
	s, _ = lcSession(t, "root", false)
	writeRoot(t, s, "config/projects/bad.yaml.disabled", "name: bad\nlockfiles:\n  - {type: nope, path: x}\n")
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "bad", Apply: true}); err == nil || !strings.Contains(err.Error(), "has errors") {
		t.Fatalf("err = %v", err)
	}
	writeRoot(t, s, "config/projects/worse.yaml.disabled", "name: worse\nbogus: 1\n")
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbEnable, Project: "worse", Apply: true}); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteWorksOnADisabledAndABrokenProject(t *testing.T) {
	s, _ := lcSession(t, "root", false)
	writeRoot(t, s, "config/projects/parked.yaml.disabled", "name: parked\n")
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "parked", Apply: true, Confirm: true})
	if err != nil || exists(t, s, "config/projects/parked.yaml.disabled") || filepath.Base(p.Backup) != "parked-20261003-120000.yaml" {
		t.Fatalf("%+v %v", p, err)
	}
	writeRoot(t, s, "config/projects/broken.yaml", "name: [oops\n")
	p, err = s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "broken"})
	if err != nil || !strings.Contains(strings.Join(p.Warnings, "|"), "does not parse") {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "broken", Apply: true, Confirm: true}); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateKeepsCommentsAndTouchesNothingElse(t *testing.T) {
	s, st := lcSession(t, "root", true)
	cfgBefore := readRoot(t, s, "config/config.yaml")
	findings := s.Ledger.Findings()
	p, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDuplicate, Project: "shop", NewName: "shop-eu", Apply: true})
	if err != nil || !p.Applied || p.Backup != "" {
		t.Fatalf("%+v %v", p, err)
	}
	got := readRoot(t, s, "config/projects/shop-eu.yaml")
	if !strings.Contains(got, "name: shop-eu") || !strings.Contains(got, "# the shop") || !strings.Contains(got, "# prod webshop") || !strings.Contains(got, `{name: php, version: "8.2"}`) {
		t.Fatalf("copy:\n%s", got)
	}
	if readRoot(t, s, "config/projects/shop.yaml") != lcShop || readRoot(t, s, "config/config.yaml") != cfgBefore {
		t.Fatal("the original or the access rules changed")
	}
	if !reflect.DeepEqual(findings, stored(t, st).Findings()) {
		t.Fatal("findings changed")
	}
	configLoads(t, s)
	if ev := events(t, s); len(ev) != 1 || !strings.Contains(ev[0], "duplicated project as shop-eu") {
		t.Fatalf("audit: %v", ev)
	}
}

func TestLifecycleRefusesWhenAccessRulesCannotBeRewritten(t *testing.T) {
	// the rules in force name the project, but config.yaml cannot give that up
	for name, body := range map[string]string{
		"syntax error":      "access: [oops\n",
		"not in the file":   "access:\n  root: {projects: ['*'], write: true}\n",
		"unreadable access": "access: nonsense\n",
	} {
		s, _ := lcSession(t, "root", true)
		writeRoot(t, s, "config/config.yaml", body)
		before := snapshot(t, s)
		_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true})
		if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: err = %v", name, err)
		}
		if !reflect.DeepEqual(before, snapshot(t, s)) || len(findingsOf(s.Ledger, "webshop")) != 0 {
			t.Errorf("%s: a half-applied state", name)
		}
	}
}

func TestLifecycleWritesNothingWithoutTheAuditRecord(t *testing.T) {
	s, st := lcSession(t, "root", false)
	if err := os.MkdirAll(filepath.Join(s.Cfg.DataDir, "audit.log"), 0o755); err != nil { // a directory cannot be appended to
		t.Fatal(err)
	}
	before := snapshot(t, s)
	_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "audit log") {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s)) || len(findingsOf(stored(t, st), "shop")) != 1 {
		t.Fatal("changed without a record")
	}
}

// failingSave makes saving the ledger fail while it is switched on.
type failingSave struct {
	store.Storage
	fail bool
}

func (f *failingSave) Save(s ledger.State) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Storage.Save(s)
}

func TestRenameUndoesItselfWhenTheLedgerCannotBeSaved(t *testing.T) {
	s, st := lcSession(t, "root", true)
	fail := &failingSave{Storage: st, fail: true}
	s.store = fail
	_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "disk full") || !strings.Contains(err.Error(), "everything was put back") {
		t.Fatalf("err = %v", err)
	}
	if exists(t, s, "config/projects/webshop.yaml") || readRoot(t, s, "config/projects/shop.yaml") != lcShop {
		t.Fatal("files not as before")
	}
	if len(findingsOf(s.Ledger, "shop")) != 1 || len(findingsOf(stored(t, st), "shop")) != 1 {
		t.Fatal("findings not as before")
	}
	if readRoot(t, s, "config/config.yaml") != lcCfg {
		t.Fatal("access rules changed")
	}
	// the record stays, with the failure after it
	if ev := events(t, s); len(ev) != 2 || !strings.HasPrefix(ev[0], "project: ") || !strings.HasPrefix(ev[1], "project-failed: ") || !strings.Contains(ev[1], "disk full") {
		t.Fatalf("audit: %v", ev)
	}
	// and the same request works once saving does
	fail.fail = false
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true}); err != nil {
		t.Fatal(err)
	}
}

func TestRenameUndoesTheLedgerWhenTheAccessRulesCannotBeWritten(t *testing.T) {
	s, st := lcSession(t, "root", true)
	// config-backups is a file, so backing up config.yaml fails
	if err := os.MkdirAll(s.Cfg.DataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Cfg.DataDir, "config-backups"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: "shop", NewName: "webshop", Apply: true, Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "everything was put back") {
		t.Fatalf("err = %v", err)
	}
	if exists(t, s, "config/projects/webshop.yaml") || readRoot(t, s, "config/projects/shop.yaml") != lcShop || readRoot(t, s, "config/config.yaml") != lcCfg {
		t.Fatal("files not as before")
	}
	for _, l := range []*ledger.Ledger{s.Ledger, stored(t, st)} {
		if len(findingsOf(l, "shop")) != 1 || len(findingsOf(l, "webshop")) != 0 {
			t.Fatalf("findings: %+v", l.Findings())
		}
	}
	configLoads(t, s)
}

func TestDeleteUndoesTheAccessRulesWhenTheBackupFails(t *testing.T) {
	s, _ := lcSession(t, "root", true)
	if err := os.MkdirAll(s.Cfg.DataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Cfg.DataDir, "project-backups"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", Apply: true, Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "everything was put back") {
		t.Fatalf("err = %v", err)
	}
	if readRoot(t, s, "config/projects/shop.yaml") != lcShop || readRoot(t, s, "config/config.yaml") != lcCfg {
		t.Fatal("the project or its access rules were lost")
	}
	configLoads(t, s)
}

func TestDeleteUndoesEverythingWhenClosingFindingsFails(t *testing.T) {
	s, st := lcSession(t, "root", true)
	fail := &failingSave{Storage: st, fail: true}
	s.store = fail
	_, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbDelete, Project: "shop", CloseFindings: true, Apply: true, Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "everything was put back") {
		t.Fatalf("err = %v", err)
	}
	if readRoot(t, s, "config/projects/shop.yaml") != lcShop || readRoot(t, s, "config/config.yaml") != lcCfg {
		t.Fatal("not restored")
	}
	if f := findingsOf(s.Ledger, "shop"); len(f) != 1 || f[0].Status != model.StatusOpen {
		t.Fatalf("findings: %+v", f)
	}
}

func TestSinceAndLockfileDevThroughEditProject(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/projects/blog.yaml", "# blog\nname: blog   # mine\nlockfiles:\n  - {type: composer, path: composer.lock}   # php\n")
	p, err := s.EditProject(ProjectChange{Project: "blog", Save: true, Ops: []projectfile.Op{
		{Kind: "set_since", Since: "2026-03-04"},
		{Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Path: "composer.lock", Dev: true}},
	}})
	if err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	if p.Result.Since != "2026-03-04" || len(p.Result.Lockfiles) != 1 || !p.Result.Lockfiles[0].Dev {
		t.Fatalf("view: %+v", p.Result)
	}
	got := readRoot(t, s, "config/projects/blog.yaml")
	if !strings.Contains(got, "# blog") || !strings.Contains(got, "# mine") || !strings.Contains(got, "# php") || !strings.Contains(got, "since: 2026-03-04") {
		t.Fatalf("file:\n%s", got)
	}
	// a future date saves with a warning, a malformed one is refused
	p, err = s.EditProject(ProjectChange{Project: "blog", Save: true, Ops: []projectfile.Op{{Kind: "set_since", Since: "2999-01-01"}}})
	warned := false
	for _, i := range p.Issues {
		warned = warned || i.Level == "warning" && i.Field == "since"
	}
	if err != nil || !warned {
		t.Fatalf("%+v %v", p.Issues, err)
	}
	if _, err := s.EditProject(ProjectChange{Project: "blog", Save: true, Ops: []projectfile.Op{{Kind: "set_since", Since: "soon"}}}); err == nil {
		t.Fatal("a malformed date was saved")
	}
	p, err = s.EditProject(ProjectChange{Project: "blog", Save: true, Ops: []projectfile.Op{{Kind: "set_since"}}})
	if err != nil || p.Result.Since != "" || strings.Contains(readRoot(t, s, "config/projects/blog.yaml"), "since") {
		t.Fatalf("%+v %v", p, err)
	}
}
