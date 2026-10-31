package ops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/status"
)

func problemOf(r status.Report, key string) (status.Problem, bool) {
	for _, p := range r.Problems {
		if p.Key == key {
			return p, true
		}
	}
	return status.Problem{}, false
}

func TestStatusListsProjectsThatCannotBeUsed(t *testing.T) {
	s := editable(t, nil, "alice")
	writeProject(t, s, "shop", "name: shop\ntechs: [{name: php}]\nlockfiles:\n  - {type: composer, path: gone/composer.lock}\n")
	writeProject(t, s, "mw", "name: mw\ntechs: [{name: php}]\n")
	writeProject(t, s, "broken", "name: [\n")
	s.Cfg.Broken = append(s.Cfg.Broken, config.BrokenProject{Name: "later", File: "later.yaml", Err: "later.yaml: bad field"})

	rep, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	shop, ok := problemOf(rep, "project:shop")
	if !ok || shop.Level != status.Yellow || !strings.Contains(shop.Detail, "gone/composer.lock") || shop.Hint == "" {
		t.Errorf("an unreadable lockfile: %+v", shop)
	}
	if p, ok := problemOf(rep, "project:broken"); !ok || p.Level != status.Yellow {
		t.Errorf("a file that does not parse: %+v", p)
	}
	if p, ok := problemOf(rep, "project:later"); !ok || p.Detail != "bad field" {
		t.Errorf("a project the loader skipped: %+v", p)
	}
	if _, ok := problemOf(rep, "project:mw"); ok {
		t.Error("a sound project is no problem")
	}
}

func TestStatusProjectProblemsFollowTheActorsAccess(t *testing.T) {
	s := editable(t, map[string]config.Grant{"bob": {Projects: []string{"mw"}}}, "bob")
	writeProject(t, s, "shop", "name: shop\ntechs: [{name: php}]\nlockfiles:\n  - {type: composer, path: gone/composer.lock}\n")
	writeProject(t, s, "mw", "name: mw\ntechs: [{name: php}]\n")
	s.Cfg.Broken = append(s.Cfg.Broken, config.BrokenProject{Name: "other", File: "other.yaml", Err: "other.yaml: bad"})
	rep, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep.Problems {
		if strings.HasPrefix(p.Key, "project:") {
			t.Errorf("bob may not see %s", p.Key)
		}
	}
}

func TestStatusTurnsRedWhenTheAuditChainIsBroken(t *testing.T) {
	s := editable(t, nil, "alice")
	if rep, err := s.Status(); err != nil || rep.Problems == nil {
		t.Fatalf("%v %+v", err, rep)
	} else if _, ok := problemOf(rep, "audit"); ok {
		t.Fatal("no log, no problem")
	}
	if err := os.MkdirAll(s.Cfg.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Cfg.DataDir, "audit.log"), []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := problemOf(rep, "audit")
	if !ok || p.Level != status.Red || rep.Level != status.Red || rep.Problems[0].Key != "audit" {
		t.Fatalf("%s %+v", rep.Level, rep.Problems)
	}
}
