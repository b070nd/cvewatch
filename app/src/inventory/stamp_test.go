package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
)

func TestFilesStampFollowsTheFilesTheJudgementDependsOn(t *testing.T) {
	root := t.TempDir()
	dir := config.ProjectsDir(root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "shop.yaml")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lock := filepath.Join(root, "composer.lock")
	if err := os.WriteFile(lock, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Bundle{Root: root}
	cfg.Projects = append(cfg.Projects, model.Project{Name: "shop", Lockfiles: []model.Lockfile{{Type: "composer", Path: lock}}})

	write("name: shop\n")
	one := FilesStamp(cfg)
	if one != FilesStamp(cfg) {
		t.Fatal("the stamp of unchanged files differs")
	}
	write("name: shop\nsince: 2024-01-01\n")
	two := FilesStamp(cfg)
	if two == one {
		t.Fatal("an edited project file keeps the stamp")
	}
	if err := os.WriteFile(lock, []byte(`{"packages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if FilesStamp(cfg) == two {
		t.Fatal("an edited lockfile keeps the stamp")
	}
}
