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
	d.want("nothing new")
}
