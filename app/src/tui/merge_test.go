package tui

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScanInputsMergesTheStackWithoutDuplicates(t *testing.T) {
	b, root := diskFake(t, map[string]string{
		"repos/app/.ddev/config.yaml": "php_version: \"8.3\"\ndatabase:\n    type: mysql\n    version: \"8.0\"\n",
		"repos/app/.tool-versions":    "nginx 1.25.3\n",
		"repos/app/package-lock.json": `{"lockfileVersion":3,"packages":{}}`,
	})
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("down", "c")
	d.toField(0)
	d.press("s")
	d.want("Add inputs to shop")
	d.typ(filepath.Join(root, "repos", "app"))
	d.press("enter")
	d.want("mysql", "8.0", "nginx", "1.25.3", "package-lock.json")
	d.wantNot("8.3")
	d.press("y")
	d.want("ok: saved shop")
	got := fileAt(t, root, "config/projects/shop.yaml")
	for _, w := range []string{"mysql", "1.25.3", "package-lock.json", "# the shop", "# runtime"} {
		if !strings.Contains(got, w) {
			t.Errorf("the file lacks %q:\n%s", w, got)
		}
	}
	if strings.Count(got, "name: php") != 1 || strings.Contains(got, "8.3") {
		t.Errorf("php stays declared once, as it was:\n%s", got)
	}

	d.press("s")
	d.typ(filepath.Join(root, "repos", "app"))
	d.press("enter")
	d.want("php: app says 8.3, the project says 8.2", "Keep the project as it is")
	before := fileAt(t, root, "config/projects/shop.yaml")
	d.pickTo("Keep the project")
	d.press("enter")
	if fileAt(t, root, "config/projects/shop.yaml") != before {
		t.Error("keeping the project writes nothing")
	}
}

func TestScanInputsReadsAFileTheGitignoreHides(t *testing.T) {
	b, root := diskFake(t, map[string]string{
		"repos/app/.gitignore": "Dockerfile\n",
		"repos/app/Dockerfile": "FROM redis:7.2.4\n",
	})
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("down", "c")
	d.toField(0)
	d.press("s")
	d.typ(filepath.Join(root, "repos", "app", "Dockerfile"))
	d.press("enter")
	d.wantNot("ignored by .gitignore")
	d.want("redis", "7.2.4")
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "redis") {
		t.Errorf("the Dockerfile's stack is in the project:\n%s", got)
	}
}

func TestScanInputsAsksWhereADifferentVersionApplies(t *testing.T) {
	b, root := diskFake(t, map[string]string{"repos/app/Dockerfile": "FROM acme/base:1.1-php-8.3.1\n"})
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("down", "c")
	d.toField(0)
	d.press("s")
	d.typ(filepath.Join(root, "repos", "app", "Dockerfile"))
	d.press("enter")
	d.want("php: ", "says 8.3.1, the project says 8.2", "Only in dev", "Only in prod", "Everywhere", "Keep the project as it is")
	d.pickTo("Only in dev")
	d.press("enter")
	d.want("set php to 8.3.1 in dev")
	d.press("y")
	d.want("ok: saved shop")
	got := fileAt(t, root, "config/projects/shop.yaml")
	if !strings.Contains(got, "8.3.1") || !strings.Contains(got, "8.2.30") {
		t.Errorf("dev gets 8.3.1 and prod keeps its own:\n%s", got)
	}
}

func TestAddingALockfileAcceptsADockerfile(t *testing.T) {
	b, root := diskFake(t, map[string]string{"repos/app/Dockerfile": "FROM redis:7.2.4\n"})
	d := start(t, b, Options{})
	d.screen("projects")
	d.press("down", "c")
	d.toField(2)
	d.press("enter")
	d.press("+")
	d.want("Add a lockfile to shop")
	d.typ(filepath.Join(root, "repos", "app", "Dockerfile"))
	d.press("enter")
	d.wantNot("Type of")
	d.want("redis", "7.2.4")
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "redis") {
		t.Errorf("the Dockerfile's stack is in the project:\n%s", got)
	}
}
