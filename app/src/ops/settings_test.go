package ops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/config"
)

const settingsYAML = `# my settings
interval: 4h   # daemon period
http:
  timeout: 30s
`

func writeRoot(t *testing.T, s *Session, rel, body string) {
	t.Helper()
	p := filepath.Join(s.Cfg.Root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readRoot(t *testing.T, s *Session, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Cfg.Root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func setTimeout(v string) SettingsChange {
	return SettingsChange{Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "http.timeout", Value: v}}}
}

func TestEditSettingsPreviewDoesNotWrite(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/config.yaml", settingsYAML)
	p, err := s.EditSettings(setTimeout("45s"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Saved || p.Blocked() || !strings.Contains(p.Diff, "+   timeout: 45s") || len(p.Changed) != 1 || p.Note == "" {
		t.Fatalf("%+v", p)
	}
	if readRoot(t, s, "config/config.yaml") != settingsYAML {
		t.Fatal("preview wrote the file")
	}
}

func TestEditSettingsSavesAuditsAndBacksUp(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/config.yaml", settingsYAML)
	c := setTimeout("45s")
	c.Save = true
	p, err := s.EditSettings(c)
	if err != nil || !p.Saved || len(p.Written) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	got := readRoot(t, s, "config/config.yaml")
	if !strings.Contains(got, "# my settings") || !strings.Contains(got, "# daemon period") || !strings.Contains(got, "timeout: 45s") {
		t.Fatalf("comments or value lost:\n%s", got)
	}
	bk, _ := os.ReadDir(filepath.Join(s.Cfg.DataDir, "config-backups"))
	if len(bk) != 1 {
		t.Fatalf("want one backup, got %d", len(bk))
	}
	if old, _ := os.ReadFile(filepath.Join(s.Cfg.DataDir, "config-backups", bk[0].Name())); string(old) != settingsYAML {
		t.Fatal("backup is not the old file")
	}
	evs, _ := s.Audit.Events()
	if len(evs) != 1 || evs[0].Action != "settings" || evs[0].Actor != "alice" || !strings.Contains(evs[0].Note, "set http.timeout") || strings.Contains(evs[0].Note, "45s") {
		t.Fatalf("audit: %+v", evs)
	}
	if n, err := s.Audit.Verify(); err != nil || n != 1 {
		t.Fatalf("chain: %d %v", n, err)
	}
	// saving the same value again changes nothing: no second backup, no second record
	if p, err := s.EditSettings(c); err != nil || p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	if n, _ := s.Audit.Verify(); n != 1 {
		t.Fatal("a no-op was audited")
	}
}

func TestEditSettingsRefusesInvalidCandidateAndLeavesFileAlone(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "config/config.yaml", settingsYAML)
	c := SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "lookback", Value: "9000h"}}}
	p, err := s.EditSettings(c)
	if err == nil || p.Saved || !p.Blocked() {
		t.Fatalf("%+v %v", p, err)
	}
	found := false
	for _, i := range p.Issues {
		found = found || i.Field == "retention" && i.Doc == confdoc.IDSettings
	}
	if !found {
		t.Fatalf("not attributed to the field: %+v", p.Issues)
	}
	if readRoot(t, s, "config/config.yaml") != settingsYAML {
		t.Fatal("the file changed")
	}
	if _, err := os.Stat(filepath.Join(s.Cfg.DataDir, "config-backups")); err == nil {
		t.Fatal("a backup was made for nothing")
	}
	if evs, _ := s.Audit.Events(); len(evs) != 0 {
		t.Fatalf("audited a change that was refused: %+v", evs)
	}
	// a value the type refuses never gets as far as a candidate
	if _, err := s.EditSettings(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "interval", Value: "soon"}}}); err == nil {
		t.Fatal("accepted")
	}
	if readRoot(t, s, "config/config.yaml") != settingsYAML {
		t.Fatal("the file changed")
	}
}

func TestEditSettingsNeverReturnsSecrets(t *testing.T) {
	s := editable(t, nil, "alice")
	writeRoot(t, s, "sources/custom.yaml", "sources:\n  - id: v\n    type: rss\n    url: https://a.test/f?token=SEKRIT\n    headers: {Authorization: Bearer SEKRIT}\n")
	c := SettingsChange{Edits: []confdoc.Edit{
		{Op: confdoc.OpSet, Path: "sources.[id=v].headers.Authorization", Value: "Bearer NEWSEKRIT"},
		{Op: confdoc.OpSet, Path: "sources.[id=v].type", Value: "hn"},
	}}
	p, err := s.EditSettings(c)
	if err != nil {
		t.Fatal(err)
	}
	all := p.Diff
	for _, i := range p.Issues {
		all += i.Message
	}
	if strings.Contains(all, "SEKRIT") || !strings.Contains(p.Diff, "type: hn") || !strings.Contains(p.Diff, "(set") {
		t.Fatalf("diff:\n%s", p.Diff)
	}
	v, err := s.Settings().View()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range v.Docs {
		if strings.Contains(d.Text, "SEKRIT") {
			t.Fatalf("view leaks: %s", d.Text)
		}
		for _, e := range d.Entries {
			if strings.Contains(e.Value, "SEKRIT") {
				t.Fatalf("entry leaks: %+v", e)
			}
		}
	}
}

func TestEditSettingsAccess(t *testing.T) {
	acc := map[string]config.Grant{
		"root":  {Projects: []string{"*"}, Write: true},
		"viewr": {Projects: []string{"*"}},
		"bob":   {Projects: []string{"shop"}, Write: true},
	}
	body := "access:\n  root: {projects: ['*'], write: true}\n  viewr: {projects: ['*']}\n  bob: {projects: [shop], write: true}\n"
	grantSelf := SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "access.bob", Value: map[string]any{"projects": []any{"*"}, "write": true}}}}
	for _, c := range []struct {
		actor string
		save  bool
		ok    bool
	}{
		{"root", true, true},
		{"root", false, true},
		{"viewr", false, true}, // may look at what a change would do
		{"viewr", true, false},
		{"bob", true, false}, // restricted: cannot grant itself the rest
		{"bob", false, false},
		{"mallory", false, false},
	} {
		s := editable(t, acc, c.actor)
		writeRoot(t, s, "config/config.yaml", body)
		writeRoot(t, s, "config/projects/shop.yaml", "name: shop\n")
		ch := grantSelf
		ch.Save = c.save
		_, err := s.EditSettings(ch)
		if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("%s save=%v: err=%v", c.actor, c.save, err)
		}
		if c.actor == "bob" && strings.Contains(readRoot(t, s, "config/config.yaml"), "bob: {projects: ['*']") {
			t.Fatal("a restricted actor granted itself rights")
		}
	}
	// the same refusal for any other section
	s := editable(t, acc, "bob")
	writeRoot(t, s, "config/config.yaml", body)
	if _, err := s.EditSettings(func() SettingsChange { c := setTimeout("1s"); c.Save = true; return c }()); !errors.Is(err, ErrDenied) {
		t.Fatalf("restricted actor changed settings: %v", err)
	}
}

func TestEditSettingsCannotLockTheActorOut(t *testing.T) {
	acc := map[string]config.Grant{"root": {Projects: []string{"*"}, Write: true}}
	s := editable(t, acc, "root")
	body := "access:\n  root: {projects: ['*'], write: true}\n  bob: {projects: [shop]}\n"
	writeRoot(t, s, "config/config.yaml", body)
	writeRoot(t, s, "config/projects/shop.yaml", "name: shop\n")
	p, err := s.EditSettings(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "access.root.write", Value: false}}})
	if err == nil || !p.Blocked() || readRoot(t, s, "config/config.yaml") != body {
		t.Fatalf("%+v %v", p, err)
	}
	// starting rules from nothing must name the actor too
	s = editable(t, nil, "root")
	writeRoot(t, s, "config/config.yaml", "interval: 4h\n")
	writeRoot(t, s, "config/projects/shop.yaml", "name: shop\n")
	add := func(who string) SettingsChange {
		return SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "access." + who, Value: map[string]any{"projects": []any{"*"}, "write": true}}}}
	}
	if _, err := s.EditSettings(add("someone")); err == nil {
		t.Fatal("rules that lock the author out were saved")
	}
	if _, err := s.EditSettings(add("root")); err != nil {
		t.Fatal(err)
	}
}

func TestEditSettingsReadOnlySessionPreviewsOnly(t *testing.T) {
	s := editable(t, nil, "alice")
	s.readOnly = true
	writeRoot(t, s, "config/config.yaml", settingsYAML)
	c := setTimeout("45s")
	if _, err := s.EditSettings(c); err != nil {
		t.Fatal(err)
	}
	c.Save = true
	if _, err := s.EditSettings(c); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("%v", err)
	}
}

func TestOpenSettingsWorksOnABrokenConfig(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "config", "config.yaml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	write := func(body string) {
		if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// semantic breakage: unknown key and a bad value; the file still parses
	write("interval: 4h\nintervall: 2h\nhttp:\n  retries: lots\n  timeout: 30s   # keep\n")
	if _, err := config.Load(root); err == nil {
		t.Fatal("the fixture must not load")
	}
	ss, err := OpenSettings(root)
	if err != nil {
		t.Fatal(err)
	}
	ss.Actor = "alice"
	v, err := ss.View()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Issues) == 0 || v.Issues[0].Doc != confdoc.IDSettings || v.Issues[0].Line == 0 || v.Issues[0].Field == "" {
		t.Fatalf("issues: %+v", v.Issues)
	}
	var settings DocView
	for _, d := range v.Docs {
		if d.ID == confdoc.IDSettings {
			settings = d
		}
	}
	if !settings.Exists || len(settings.Entries) == 0 || !strings.Contains(settings.Text, "# keep") {
		t.Fatalf("%+v", settings)
	}
	// repair one problem at a time; each save removes an error and adds none
	p, err := ss.Edit(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpUnset, Path: "intervall"}}})
	if err != nil || !p.Saved {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := config.Load(root); err == nil {
		t.Fatal("still broken by retries")
	}
	if _, err = ss.Edit(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "http.retries", Value: 3}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(root); err != nil {
		t.Fatalf("repair did not work: %v", err)
	}
	if n, err := audit.Open(ss.DataDir).Verify(); err != nil || n != 2 {
		t.Fatalf("audit: %d %v", n, err)
	}
	if got, _ := os.ReadFile(cfg); !strings.Contains(string(got), "# keep") {
		t.Fatalf("comment lost:\n%s", got)
	}
	// but an edit that adds a new error is refused while the others stay
	write("lookback: 9000h\n")
	ss, _ = OpenSettings(root)
	ss.Actor = "alice"
	if _, err := ss.Edit(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpAppend, Path: "policy.rules", Value: map[string]any{"name": "x"}}}}); err == nil {
		t.Fatal("a new error was saved on top of the old one")
	}
	if p, err := ss.Edit(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "interval", Value: "2h"}}}); err != nil || !p.Saved {
		t.Fatalf("an unrelated change was refused because of an old error: %+v %v", p, err)
	}

	// a syntax error: viewable, repairable only by replacing the document
	write("interval: [\n")
	ss, _ = OpenSettings(root)
	ss.Actor = "alice"
	v, err = ss.View()
	if err != nil || len(v.Issues) == 0 {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := ss.Edit(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpReplace, Doc: confdoc.IDSettings, Value: "interval: 2h\n"}}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unreadable access rules must refuse writes: %v", err)
	}
}

func TestOpenSettingsEnforcesAccessEvenWhenConfigIsBroken(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "config", "config.yaml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	os.MkdirAll(filepath.Join(root, "config", "projects"), 0o755)
	os.WriteFile(filepath.Join(root, "config", "projects", "shop.yaml"), []byte("name: shop\n"), 0o644)
	os.WriteFile(cfg, []byte("interval: nope\naccess:\n  bob: {projects: [shop], write: true}\n  root: {projects: ['*'], write: true}\n"), 0o644)
	for actor, ok := range map[string]bool{"root": true, "bob": false} {
		ss, err := OpenSettings(root)
		if err != nil {
			t.Fatal(err)
		}
		ss.Actor = actor
		_, err = ss.Edit(SettingsChange{Save: true, Edits: []confdoc.Edit{{Op: confdoc.OpSet, Path: "interval", Value: "1h"}}})
		if ok != (err == nil) || err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", actor, err)
		}
	}
}

func TestSettingsSessionSaysWhyItCannotWrite(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "config", "config.yaml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	body := "access:\n  root: {projects: ['*'], write: true}\n  carol: {projects: ['*']}\n"
	os.WriteFile(cfg, []byte(body), 0o644)
	for actor, writable := range map[string]bool{"root": true, "carol": false} {
		ss, err := OpenSettings(root)
		if err != nil {
			t.Fatal(err)
		}
		ss.Actor = actor
		if err := ss.Writable(); (err == nil) != writable || err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", actor, err)
		}
		if ss.RulesUnreadable() {
			t.Errorf("%s: the rules are readable", actor)
		}
	}
	os.WriteFile(cfg, []byte("access: [\n"), 0o644)
	ss, err := OpenSettings(root)
	if err != nil {
		t.Fatal(err)
	}
	if !ss.RulesUnreadable() || ss.Writable() == nil {
		t.Fatal("unreadable rules refuse writes and say so")
	}
}
