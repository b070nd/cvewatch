package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

func infraCatalog() *catalog.Catalog {
	img := func(name, cat string, images ...string) model.Tech {
		return model.Tech{Name: name, Title: name, Category: cat, Detect: model.Detect{Images: images}}
	}
	return catalog.New([]model.Tech{
		img("php", "language", "php"), img("nodejs", "runtime", "node"), img("python", "language", "python"),
		img("ubuntu", "os", "ubuntu"), img("debian", "os", "debian"), img("alpine", "os", "alpine"),
		img("nginx", "web-server", "nginx"), img("redis", "cache", "redis"), img("postgresql", "database", "postgres"),
		{Name: "go", Aliases: []string{"golang"}, Category: "language"},
	})
}

func scanOne(t *testing.T, name, content string) Result {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ScanFile(p, infraCatalog(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(dir); res.Root != dir && res.Root != want {
		t.Fatalf("root = %q, want the file's folder %q", res.Root, dir)
	}
	if filepath.Base(res.File) != name {
		t.Fatalf("file = %q", res.File)
	}
	return res
}

func versions(res Result) map[string]string {
	m := map[string]string{}
	for _, p := range res.Techs {
		m[p.Tech] = p.Version
	}
	return m
}

func TestScanFileDockerfileMultiStage(t *testing.T) {
	res := scanOne(t, "Dockerfile", `# syntax=docker/dockerfile:1
ARG PHP_VERSION=8.2
ARG NODE_TAG
FROM --platform=$BUILDPLATFORM node:20-alpine AS assets
FROM php:${PHP_VERSION}-fpm AS base
FROM base AS dev
FROM scratch AS export
FROM node:${NODE_TAG}
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx=1.24.0-1 curl \
    && rm -rf /var/lib/apt/lists/*
`)
	got := versions(res)
	for tech, v := range map[string]string{"nodejs": "20", "php": "8.2", "debian": "12", "nginx": "1.24.0"} {
		if got[tech] != v {
			t.Errorf("%s = %q, want %q (all: %v)", tech, got[tech], v, got)
		}
	}
	if len(res.Techs) != 4 || len(res.Lockfiles) != 0 {
		t.Errorf("techs = %v", got)
	}
	for _, p := range res.Techs {
		if !p.Infra || p.Category == "" {
			t.Errorf("%s: infra=%v category=%q, want infrastructure with a category", p.Tech, p.Infra, p.Category)
		}
	}
	if p := find(res, "nginx"); p == nil || p.Category != "web-server" || p.Evidence[0].File != "Dockerfile" {
		t.Errorf("nginx = %+v", p)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "NODE_TAG") {
		t.Errorf("notes = %v, want the variable with no default named", res.Notes)
	}
}

func TestScanFileDockerfileVariants(t *testing.T) {
	res := scanOne(t, "api.Dockerfile", "FROM ubuntu:jammy\nRUN apk add --no-cache --virtual .build-deps redis postgresql-15\n")
	got := versions(res)
	if got["ubuntu"] != "22.04" {
		t.Errorf("ubuntu = %q", got["ubuntu"])
	}
	if v, ok := got["redis"]; !ok || v != "" || got["postgresql"] != "15" {
		t.Errorf("apk packages after --virtual: %v", got)
	}
	if p := find(res, "redis"); p.Confidence != Low {
		t.Errorf("an unpinned package is only a hint: %+v", p)
	}
	if got := scanOne(t, "Containerfile", "FROM alpine:3.19\n"); versions(got)["alpine"] != "3.19" {
		t.Errorf("containerfile: %v", versions(got))
	}
	if res := scanOne(t, "Dockerfile", "FROM scratch\nCOPY app /app\n"); len(res.Techs) != 0 {
		t.Errorf("scratch gave %v", res.Techs)
	}
}

func TestScanFileCompose(t *testing.T) {
	res := scanOne(t, "docker-compose.yml", `services:
  web:
    image: nginx:1.25-alpine
  cache:
    image: redis:${REDIS_TAG:-7.2}
  db:
    image: postgres:${PG_TAG}
  app:
    build: .
`)
	got := versions(res)
	if got["nginx"] != "1.25" || got["redis"] != "7.2" {
		t.Errorf("got %v", got)
	}
	if _, ok := got["postgresql"]; ok {
		t.Errorf("an unresolved tag was proposed: %v", got)
	}
	if p := find(res, "redis"); p == nil || !p.Infra || p.Category != "cache" {
		t.Errorf("redis = %+v", p)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "PG_TAG") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestScanFileKubernetes(t *testing.T) {
	res := scanOne(t, "deploy.yaml", "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: registry.example.com/team/nginx:1.25.3\n        - image: redis:7\n---\nkind: Pod\nspec:\n  containers:\n    - image: postgres:16\n")
	got := versions(res)
	if got["redis"] != "7" || got["postgresql"] != "16" {
		t.Errorf("got %v", got)
	}
}

func TestScanFileInfraIsOnlyForContainerFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Dockerfile", "FROM php:8.2\n")
	write(t, dir, "composer.lock", `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}]}`)
	res, err := Scan(dir, infraCatalog(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p := find(res, "php"); p == nil || !p.Infra {
		t.Errorf("php from a Dockerfile alone should be infra: %+v", p)
	}
	write(t, dir, ".php-version", "8.2.1\n")
	cat := catalog.New([]model.Tech{{Name: "php", Category: "language", Detect: model.Detect{Images: []string{"php"},
		Versions: []model.VersionHint{{File: ".php-version", Pattern: `^\s*(\S+)`}}}}})
	res, err = Scan(dir, cat, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p := find(res, "php"); p == nil || p.Infra || p.Category != "" {
		t.Errorf("php also read from .php-version is not infra: %+v", p)
	}
}

func TestScanFileRejects(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", "hello")
	for name, path := range map[string]string{"unsupported": filepath.Join(dir, "notes.txt"), "folder": dir, "missing": filepath.Join(dir, "nope.yaml")} {
		if _, err := ScanFile(path, infraCatalog(), Options{}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestSupportedFile(t *testing.T) {
	for name, want := range map[string]bool{"Dockerfile": true, "Dockerfile.dev": true, "app.dockerfile": true, "Containerfile": true,
		"docker-compose.override.yml": true, "compose.yaml": true, "k8s/deploy.yml": true, "main.tf": true, "package-lock.json": true,
		"README.md": false, "main.go": false} {
		if got := SupportedFile(name); got != want {
			t.Errorf("SupportedFile(%q) = %v", name, got)
		}
	}
}
