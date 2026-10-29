package ops

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func repairRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"config/config.yaml":        "data_dir: data\nalerts_dir: alerts\n",
		"config/techs.yaml":         "techs: [{name: php}]\n",
		"config/projects/shop.yaml": "name: shop\ntechs: [{name: php, version: \"8.2\"}]\n",
		"config/projects/yaml.yaml": "name: yaml\ntechs: [\n",
		"config/projects/key.yaml":  "name: key\nbogus: 1\n",
		"config/projects/env.yaml":  "name: env\nenvs: [qa]\n",
		"config/projects/lock.yaml": "name: lock\nlockfiles: [{type: nope, path: x}]\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var bumpPHP = []projectfile.Op{{Kind: "set_tech", Tech: "php", Version: "8.3"}}

func TestOpenRepairKeepsGoodProjectsEditable(t *testing.T) {
	root := repairRoot(t)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if _, err := Open(root, log); err == nil {
		t.Fatal("Open must still fail on broken project files")
	}
	s, err := OpenRepair(root, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Cfg.Broken) != 4 || len(s.Cfg.Projects) != 1 || s.Cfg.Projects[0].Name != "shop" {
		t.Fatalf("broken = %+v, projects = %+v", s.Cfg.Broken, s.Cfg.Projects)
	}
	p, err := s.EditProject(ProjectChange{Project: "shop", Ops: bumpPHP})
	if err != nil {
		t.Fatal(err)
	}
	if p.Saved || !strings.Contains(p.Diff, "8.3") {
		t.Fatalf("preview wrong: %+v", p)
	}
}

func TestOpenReadOnlyRepairKeepsGoodProjectsEditable(t *testing.T) {
	root := repairRoot(t)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if _, err := OpenReadOnly(root, log); err == nil {
		t.Fatal("OpenReadOnly must still fail on broken project files")
	}
	s, err := OpenReadOnlyRepair(root, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Cfg.Broken) != 4 {
		t.Fatalf("broken = %+v", s.Cfg.Broken)
	}
	p, err := s.EditProject(ProjectChange{Project: "shop", Ops: bumpPHP})
	if err != nil {
		t.Fatal(err)
	}
	if p.Saved || !strings.Contains(p.Diff, "8.3") {
		t.Fatalf("preview wrong: %+v", p)
	}
}
