package wizard

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/store"
)

func TestCreateFromDockerfile(t *testing.T) {
	root := t.TempDir()
	techs := []model.Tech{
		{Name: "php", Title: "PHP", Category: "language", Detect: model.Detect{Images: []string{"php"}}},
		{Name: "nginx", Title: "NGINX", Category: "web-server", Detect: model.Detect{Images: []string{"nginx"}}},
	}
	cfg := &config.Bundle{
		Settings: config.Settings{DataDir: filepath.Join(root, "data"), AlertsDir: filepath.Join(root, "alerts")},
		Root:     root, Techs: techs, Catalog: catalog.New(techs), Projects: []model.Project{},
	}
	s, err := ops.OpenWith(cfg, store.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	file := filepath.Join(root, "repos", "shop", "Dockerfile")
	write(t, file, "ARG PHP=8.2\nFROM php:${PHP}-fpm\nFROM nginx:1.25-alpine\n")

	// name, techs (all), nothing to add, environments (keep), confirm.
	out, err := run(t, "shop\nall\n\n\nyes\n", func(io IO) error { return Setup(io, s, file, "") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b, err := os.ReadFile(projectFile(s, "shop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: shop", `{name: php, version: "8.2"}`, `{name: nginx, version: "1.25"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("file lacks %q:\n%s", want, b)
		}
	}
}
