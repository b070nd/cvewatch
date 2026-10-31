package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/setup"
)

// openEnvList opens the environments of the second project (shop) in the field editor.
func openEnvList(d *driver) {
	d.screen("projects")
	d.press("down", "c")
	d.toField(0)
	d.press("enter")
}

func findingsIn(t *testing.T, b *fake, project string, env model.Env) int {
	t.Helper()
	st, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range st.Findings {
		if f.Project == project && f.Env == env {
			n++
		}
	}
	return n
}

func TestEnvRenamePreviewCountsFindingsAndMovesThem(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	openEnvList(d)
	d.press("r")
	d.want("Rename environment dev of shop", "> New name")
	d.press("ctrl+u")
	d.typ("qa")
	d.press("enter")
	d.want("Save this change?", "environment dev becomes qa: 1 finding moves with it")
	if findingsIn(t, b, "shop", "dev") != 1 {
		t.Fatal("looking at the preview moved a finding")
	}
	d.press("y")
	d.want("ok: saved shop: rename environment dev to qa")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "qa, prod") || strings.Contains(got, "dev") {
		t.Fatalf("envs:\n%s", got)
	}
	if findingsIn(t, b, "shop", "dev") != 0 || findingsIn(t, b, "shop", "qa") != 1 {
		t.Fatalf("the finding of dev should have followed: dev %d, qa %d", findingsIn(t, b, "shop", "dev"), findingsIn(t, b, "shop", "qa"))
	}
}

func TestEnvRenameRefusesTheSameAndTakenNames(t *testing.T) {
	b, _ := diskFake(t, nil)
	d := start(t, b, Options{})
	openEnvList(d)
	d.press("enter") // enter renames too
	d.want("Rename environment dev of shop")
	d.press("enter")
	d.want("problem:", "Rename environment dev of shop")
	d.press("ctrl+u")
	d.typ("PROD")
	d.press("enter")
	d.want("problem:", "already an environment")
	d.press("ctrl+u")
	d.typ("1st")
	d.press("enter")
	d.want("problem:", "not a valid environment name")
	d.wantNot("Save this change?")
}

func TestEnvAddAcceptsSeveralFreeNamesAndRefusesBadOnes(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	openEnvList(d)
	d.press("+")
	d.want("Add an environment to shop", "suggested:")
	d.typ("prod")
	d.press("enter")
	d.want("problem:", "already an environment of the project")
	d.press("ctrl+u")
	d.typ("qa y!")
	d.press("enter")
	d.want("problem:", "not a valid environment name")
	d.press("ctrl+u")
	d.press("enter")
	d.want("problem:", "give the name of an environment")
	d.press("ctrl+u")
	d.typ("Demo-EU, qa")
	d.press("enter")
	d.want("Save this change?", "add environment demo-eu, qa")
	if got := d.opKinds(); len(got) != 2 || got[0] != "add_env" || got[1] != "add_env" {
		t.Fatalf("ops %v", got)
	}
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "demo-eu") || !strings.Contains(got, "qa") {
		t.Fatalf("envs:\n%s", got)
	}
	d.want("demo-eu", "qa")
}

func TestEnvRemoveAsksAndKeepsAtLeastOne(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	openEnvList(d)
	d.press("down", "-")
	d.want("Remove environment prod from shop?")
	d.press("n")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "dev, prod") {
		t.Fatalf("no is no:\n%s", got)
	}
	d.press("x", "y")
	d.want("Save this change?", "remove environment prod")
	d.press("y")
	d.want("ok: saved shop: remove environment prod")
	if got := fileAt(t, root, "config/projects/shop.yaml"); strings.Contains(got, "prod]") {
		t.Fatalf("prod is gone from envs:\n%s", got)
	}

	// the only environment of a project stays
	d.press("esc", "esc", "esc")
	d.screen("projects")
	d.press("up", "c") // mw has prod alone
	d.want("Edit fields of mw")
	d.toField(0)
	d.press("enter", "x")
	d.want("a project needs at least one environment")
	d.wantNot("Remove environment")
}

func TestEnvsNotSetAreShownAndFixedWithOneKey(t *testing.T) {
	legacy := strings.Replace(editShop, "envs: [dev, prod]\n", "", 1)
	if legacy == editShop {
		t.Fatal("the fixture should have an envs line")
	}
	b, root := diskFake(t, map[string]string{"config/projects/shop.yaml": legacy})
	d := start(t, b, Options{})
	d.screen("projects")
	d.want("old default")
	d.press("down", "c")
	d.want("not set (old default: dev, int, staging, prod)")
	d.toField(0)
	d.press("enter")
	d.want("envs is not set", "ENVIRONMENT", "dev", "int", "staging", "prod", "f fix envs")
	d.press("f")
	d.want("Keep the old default", "Only local")
	d.press("esc")
	d.wantNot("Keep the old default")
	if b.writes != 0 {
		t.Fatal("looking wrote something")
	}
	d.press("f", "enter")
	d.want("Save this change?", "write the old default environments into the file")
	if got := d.opKinds(); len(got) != 1 || got[0] != "set_envs" {
		t.Fatalf("ops %v", got)
	}
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "dev, int, staging, prod") {
		t.Fatalf("the old default is written:\n%s", got)
	}
	d.wantNot("envs is not set")
	d.wantNot("f fix envs")
}

func TestEnvsNotSetCanStartFromLocal(t *testing.T) {
	legacy := strings.Replace(editShop, "envs: [dev, prod]\n", "", 1)
	b, root := diskFake(t, map[string]string{"config/projects/shop.yaml": legacy})
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("down", "c")
	d.toField(0)
	d.press("enter", "f", "down", "enter")
	d.want("Save this change?", "set environments to local")
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "envs: [local]") {
		t.Fatalf("envs:\n%s", got)
	}
}

func TestEnvsOfAFileWithoutThemCanStillBeEdited(t *testing.T) {
	legacy := strings.Replace(editShop, "envs: [dev, prod]\n", "", 1)
	b, root := diskFake(t, map[string]string{"config/projects/shop.yaml": legacy})
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("down", "c")
	d.toField(0)
	d.press("enter", "+")
	d.typ("local")
	d.press("enter")
	d.want("Save this change?", "add environment local")
	d.press("y")
	d.want("ok: saved shop")
	// the first edit writes the old default with the new name after it
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "dev, int, staging, prod, local") {
		t.Fatalf("envs:\n%s", got)
	}
}

func TestNewProjectFormStartsWithLocalAndTakesFreeNames(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("n", "ctrl+u")
	d.typ("blog")
	d.press("enter", "enter") // techs (none), then add-techs
	d.typ("php")
	d.press("enter", "enter")
	d.typ("8.2")
	d.press("enter")
	d.want("Environments", "[x] local", "[ ] dev", "[ ] prod", "other...")
	d.press("end", " ", "enter")
	d.want("Other environments")
	d.typ("QA, demo-eu")
	d.press("enter")
	d.want("Does an environment differ from the rest? (default: no)")
	d.press("enter") // nothing answers yes or no: only y and n do
	d.press("n")
	d.want("Save this project?")
	d.wantNot("problem:")
	d.press("y")
	d.want("blog")
	got := readFile(t, filepath.Join(b.cfg.Root, "config", "projects", "blog.yaml"))
	for _, e := range []string{"local", "demo-eu", "qa"} {
		if !strings.Contains(got, e) {
			t.Fatalf("the file lacks %s:\n%s", e, got)
		}
	}
	if strings.Contains(got, "prod") || strings.Contains(got, "staging") {
		t.Fatalf("only the chosen names are written:\n%s", got)
	}
}

func TestEnvOpKindsAreDeclaredByEditorAndSetup(t *testing.T) {
	for _, k := range []string{"add_env", "remove_env", "rename_env"} {
		for name, list := range map[string][]string{"tui.OpKinds": OpKinds, "setup.OpKinds": setup.OpKinds} {
			found := false
			for _, o := range list {
				found = found || o == k
			}
			if !found {
				t.Errorf("%s lacks %s", name, k)
			}
		}
		for _, n := range setup.NotYet {
			if n == k {
				t.Errorf("%s is still listed as not yet handled", k)
			}
		}
	}
}
