package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

func testCatalog() *catalog.Catalog {
	return catalog.New([]model.Tech{
		{Name: "nginx", Title: "Nginx", Detect: model.Detect{Images: []string{"nginx"}, Files: []string{"nginx.conf"}}},
		{Name: "php", Title: "PHP", Detect: model.Detect{Versions: []model.VersionHint{
			{File: ".php-version", Pattern: `^\s*(\S+)`},
			{File: "broken.txt", Pattern: `(`}, // invalid, ignored
		}}},
		{Name: "nodejs", Title: "Node.js", Detect: model.Detect{Versions: []model.VersionHint{{File: ".nvmrc", Pattern: `^\s*(\S+)`}}}},
		{Name: "go", Aliases: []string{"golang"}, Title: "Go"},
		{Name: "postgres", Aliases: []string{"postgresql"}, Title: "PostgreSQL", Detect: model.Detect{Images: []string{"postgres"}}},
		{Name: "mysql", Title: "MySQL", Detect: model.Detect{Images: []string{"mysql"}}},
		{Name: "redis", Title: "Redis", Detect: model.Detect{Images: []string{"redis"}}},
		{Name: "express", Title: "Express", Detect: model.Detect{Packages: []model.PackageHint{{Ecosystem: "npm", Name: "express"}}}},
		{Name: "laravel", Title: "Laravel", Detect: model.Detect{Packages: []model.PackageHint{{Ecosystem: "composer", Name: "laravel/framework"}}}},
		{Name: "wordpress", Title: "WordPress", Detect: model.Detect{Files: []string{"wp-config.php"}}},
	})
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func scan(t *testing.T, root string, o Options) Result {
	t.Helper()
	res, err := Scan(root, testCatalog(), o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func find(res Result, tech string) *TechProposal {
	for i := range res.Techs {
		if res.Techs[i].Tech == tech {
			return &res.Techs[i]
		}
	}
	return nil
}

func want(t *testing.T, res Result, tech, version string, c Confidence) *TechProposal {
	t.Helper()
	p := find(res, tech)
	if p == nil {
		t.Fatalf("%s not proposed; got %+v", tech, res.Techs)
	}
	if p.Version != version || p.Confidence != c {
		t.Errorf("%s = %q/%s, want %q/%s", tech, p.Version, p.Confidence, version, c)
	}
	if len(p.Evidence) == 0 {
		t.Errorf("%s has no evidence", tech)
	}
	return p
}

func TestLockfilesAndPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "web/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/express":{"version":"4.18.2"},"node_modules/left-pad":{"version":"1.0.0"}}}`)
	write(t, root, "api/composer.lock", `{"packages":[{"name":"laravel/framework","version":"v10.1.0"}]}`)
	write(t, root, "api/bad/composer.lock", `not json`)
	res := scan(t, root, Options{})

	if res.Root != root && !strings.HasSuffix(res.Root, filepath.Base(root)) {
		t.Errorf("root = %s", res.Root)
	}
	wantLocks := []LockProposal{
		{"composer", "api/bad/composer.lock", 0},
		{"composer", "api/composer.lock", 1},
		{"npm", "web/package-lock.json", 2},
	}
	if !reflect.DeepEqual(res.Lockfiles, wantLocks) {
		t.Errorf("lockfiles = %+v", res.Lockfiles)
	}
	p := want(t, res, "express", "4.18.2", High)
	if p.Evidence[0] != (Evidence{"web/package-lock.json", "package express in web/package-lock.json"}) {
		t.Errorf("evidence = %+v", p.Evidence)
	}
	want(t, res, "laravel", "10.1.0", High)
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "api/bad/composer.lock") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestVersionHints(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".nvmrc", "v20.11.1\n")
	write(t, root, "sub/.PHP-Version", "8.2-fpm\n")
	write(t, root, "broken.txt", "x")
	res := scan(t, root, Options{})
	want(t, res, "nodejs", "20.11.1", High)
	want(t, res, "php", "8.2-fpm", Medium)
}

func TestToolVersions(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".tool-versions", "# tools\nnodejs 18.19.0 20.0.0\ngolang 1.22.1 # comment\npostgres system\nunknown 1\n")
	res := scan(t, root, Options{})
	want(t, res, "nodejs", "18.19.0", High)
	want(t, res, "go", "1.22.1", High)
	want(t, res, "postgres", "", Low)
}

func TestGoMod(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module x\n\ngo 1.22\n")
	res := scan(t, root, Options{})
	p := want(t, res, "go", "1.22", High)
	if p.Evidence[0].File != "go.mod" {
		t.Errorf("evidence = %+v", p.Evidence)
	}
	if len(res.Lockfiles) != 1 || res.Lockfiles[0].Type != "go" {
		t.Errorf("lockfiles = %+v", res.Lockfiles)
	}
}

func TestPackageJSON(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/package.json", `{"engines":{"node":">=18"},"dependencies":{"express":"^4.17.1"}}`)
	write(t, root, "b/package.json", `{"engines":{"node":"^20.1.0"}}`)
	res := scan(t, root, Options{})
	// 18 and 20.1 are both Low; the more specific series wins.
	want(t, res, "nodejs", "20.1", Low)
	want(t, res, "express", "4.17.1", Low)

	root = t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"20.9.0"}}`)
	want(t, scan(t, root, Options{}), "nodejs", "20.9.0", High)
}

func TestComposerJSON(t *testing.T) {
	root := t.TempDir()
	write(t, root, "composer.json", `{"require":{"php":">=8.1","laravel/framework":"^10.0"}}`)
	res := scan(t, root, Options{})
	want(t, res, "php", "8.1", Low)
	want(t, res, "laravel", "10.0", Low)
}

func TestVersionDisagreementNote(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".php-version", "8.2\n")
	write(t, root, "composer.json", `{"require":{"php":">=8.1"}}`)
	res := scan(t, root, Options{})
	want(t, res, "php", "8.2", High)
	if len(res.Notes) != 1 || res.Notes[0] != "php: .php-version says 8.2 but composer.json requires >=8.1" {
		t.Errorf("notes = %q", res.Notes)
	}
	if p := find(res, "php"); len(p.Evidence) != 2 || p.Evidence[0].File != ".php-version" {
		t.Errorf("evidence = %+v", p.Evidence)
	}
}

func TestDockerfile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", `# build
FROM --platform=linux/amd64 postgres:16.2 AS builder
FROM builder AS again
FROM scratch
ARG BASE=redis
FROM ${BASE}:7
FROM $BASE
FROM docker.io/library/nginx:1.25.3-alpine@sha256:abc AS web
FROM mysql:latest
`)
	write(t, root, "svc/api.dockerfile", "FROM redis\n")
	res := scan(t, root, Options{})
	want(t, res, "postgres", "16.2", Medium)
	want(t, res, "nginx", "1.25.3", Medium)
	want(t, res, "mysql", "", Low)
	want(t, res, "redis", "", Low) // only the unversioned api.dockerfile; ${BASE} lines are skipped
	if len(res.Techs) != 4 {
		t.Errorf("techs = %+v", res.Techs)
	}
}

func TestComposeAndKubernetes(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docker-compose.yml", "services:\n  db:\n    image: postgres:15\n  cache:\n    image: redis:7.2-alpine\n  app:\n    build: .\n")
	write(t, root, "k8s/web.yaml", "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: nginx:1.27\n---\nkind: Pod\nspec:\n  containers:\n    - image: mysql:8\n")
	write(t, root, "chart/templates/dep.yaml", "spec:\n  containers:\n    - image: \"{{ .Values.image }}\"\n    - image: redis:5\n")
	res := scan(t, root, Options{})
	want(t, res, "postgres", "15", Medium)
	want(t, res, "redis", "7.2", Medium) // the Helm template's redis:5 is skipped
	want(t, res, "nginx", "1.27", Medium)
	want(t, res, "mysql", "8", Medium)
}

func TestTerraform(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.tf", `resource "aws_db_instance" "db" {
  engine         = "postgres"
  instance_class = "db.t3"
  engine_version = "15.4"
}

resource "docker_container" "c" {
  image = "redis:7"
}

# image = "nginx:1"
resource "aws_db_instance" "other" {
  engine = "mysql"
}
`)
	res := scan(t, root, Options{})
	want(t, res, "postgres", "15.4", Medium)
	want(t, res, "redis", "7", Medium)
	if find(res, "mysql") != nil || find(res, "nginx") != nil {
		t.Errorf("unexpected techs: %+v", res.Techs)
	}
}

func TestMarkerFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "public/wp-config.php", "<?php")
	res := scan(t, root, Options{})
	p := want(t, res, "wordpress", "", Low)
	if p.Evidence[0] != (Evidence{"public/wp-config.php", "marker file wp-config.php"}) || p.Title != "WordPress" {
		t.Errorf("proposal = %+v", p)
	}
}

func TestSortingAndEvidenceCap(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-config.php", "")
	write(t, root, ".nvmrc", "18")
	for i := 0; i < 12; i++ {
		write(t, root, "d"+string(rune('a'+i))+"/nginx.conf", "")
	}
	res := scan(t, root, Options{})
	if res.Techs[0].Tech != "nodejs" || res.Techs[1].Tech != "nginx" || res.Techs[2].Tech != "wordpress" {
		t.Errorf("order = %+v", res.Techs)
	}
	if n := len(find(res, "nginx").Evidence); n != maxEvidence {
		t.Errorf("evidence = %d, want %d", n, maxEvidence)
	}
}

func TestSymlinkNotFollowed(t *testing.T) {
	outside := t.TempDir()
	write(t, outside, "Dockerfile", "FROM nginx:1\n")
	write(t, outside, "sub/.nvmrc", "18")
	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.Symlink(filepath.Join(outside, "Dockerfile"), filepath.Join(root, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	res := scan(t, root, Options{})
	if len(res.Techs) != 0 {
		t.Errorf("followed a symlink: %+v", res.Techs)
	}
}

func TestSkippedDirs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "node_modules/x/Dockerfile", "FROM nginx:1\n")
	write(t, root, ".git/Dockerfile", "FROM redis:1\n")
	write(t, root, "vendor/composer.lock", `{"packages":[]}`)
	res := scan(t, root, Options{})
	if len(res.Techs) != 0 || len(res.Lockfiles) != 0 {
		t.Errorf("found %+v %+v", res.Techs, res.Lockfiles)
	}
}

func TestMaxDepth(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/Dockerfile", "FROM nginx:1\n")
	write(t, root, "a/b/Dockerfile", "FROM redis:1\n")
	res := scan(t, root, Options{MaxDepth: 1})
	if find(res, "nginx") == nil || find(res, "redis") != nil {
		t.Errorf("techs = %+v", res.Techs)
	}
	if find(scan(t, root, Options{}), "redis") == nil {
		t.Error("default depth should reach a/b")
	}
}

func TestMaxFilesTruncates(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		write(t, root, "f"+string(rune('a'+i))+".txt", "x")
	}
	res := scan(t, root, Options{MaxFiles: 3})
	if !res.Truncated || len(res.Notes) != 1 {
		t.Errorf("truncated = %v notes = %v", res.Truncated, res.Notes)
	}
	if scan(t, root, Options{}).Truncated {
		t.Error("default limit should not truncate")
	}
}

func TestMaxFileSize(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM nginx:1\n"+strings.Repeat("# pad\n", 100))
	write(t, root, "Dockerfile.big", "FROM redis:1\n"+strings.Repeat("# pad\n", 100))
	res := scan(t, root, Options{MaxFileSize: 100})
	if len(res.Techs) != 0 || len(res.Notes) != 1 {
		t.Errorf("techs = %+v notes = %v", res.Techs, res.Notes)
	}
}

func TestScanErrors(t *testing.T) {
	root := t.TempDir()
	write(t, root, "f.txt", "x")
	for _, dir := range []string{filepath.Join(root, "missing"), filepath.Join(root, "f.txt")} {
		if _, err := Scan(dir, testCatalog(), Options{}); err == nil {
			t.Errorf("Scan(%s) should fail", dir)
		}
	}
	if os.Getuid() != 0 && runtime.GOOS != "windows" { // modes do not lock a folder on Windows
		locked := filepath.Join(root, "locked")
		if err := os.Mkdir(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(locked, 0o755)
		if _, err := Scan(locked, testCatalog(), Options{}); err == nil {
			t.Error("unreadable dir should fail")
		}
	}
}

func TestDeterministic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM nginx:1.25\n")
	write(t, root, "docker-compose.yml", "services:\n  a:\n    image: nginx:1.26\n  b:\n    image: redis\n")
	write(t, root, "composer.json", `{"require":{"php":"8.1"}}`)
	write(t, root, ".php-version", "8.3")
	a, b := scan(t, root, Options{}), scan(t, root, Options{})
	if !reflect.DeepEqual(a, b) {
		t.Errorf("scans differ:\n%+v\n%+v", a, b)
	}
}
