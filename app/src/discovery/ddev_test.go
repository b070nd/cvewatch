package discovery

import (
	"fmt"
	"strings"
	"testing"
)

func TestDDEVConfigNamesPHPNodeDatabaseAndWebServer(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".ddev/config.yaml", "name: shop\nphp_version: \"8.2\"\nnodejs_version: 16\nwebserver_type: nginx-fpm\ndatabase:\n    type: mysql\n    version: 8.0\n")
	res := scan(t, root, Options{})
	want(t, res, "php", "8.2", Medium)
	want(t, res, "nodejs", "16", Medium)
	want(t, res, "mysql", "8.0", Medium)
	if p := find(res, "mysql"); p == nil || !strings.Contains(p.Evidence[0].Detail, "DDEV runs mysql 8.0") || p.Evidence[0].File != ".ddev/config.yaml" {
		t.Errorf("the evidence names the file and what it says: %+v", p)
	}
}

func TestManyDisagreeingFilesGetOneNote(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".php-version", "8.1.2\n")
	for i := range 8 {
		write(t, root, fmt.Sprintf("m%d/.php-version", i), "7.4.1\n")
	}
	res := scan(t, root, Options{})
	var notes []string
	for _, n := range res.Notes {
		if strings.HasPrefix(n, "php:") {
			notes = append(notes, n)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "8 other files differ") {
		t.Errorf("want one summary note, got %q", notes)
	}
}
