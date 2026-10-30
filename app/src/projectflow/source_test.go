package projectflow

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ops"
)

func TestResolveSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cwd := t.TempDir()
	t.Chdir(cwd)
	write(t, filepath.Join(home, "code", "app", "Dockerfile"), "FROM php:8.2\n")
	write(t, filepath.Join(cwd, "rel", "docker-compose.yml"), "services: {}\n")
	write(t, filepath.Join(cwd, "notes.txt"), "x")

	tests := []struct {
		name, in, want string
		kind           SourceKind
		err            string
	}{
		{name: "folder", in: "rel", want: filepath.Join(cwd, "rel"), kind: SourceFolder},
		{name: "home folder", in: "~", want: home, kind: SourceFolder},
		{name: "dockerfile under home", in: filepath.FromSlash("~/code/app/Dockerfile"), want: filepath.Join(home, "code", "app", "Dockerfile"), kind: SourceFile},
		{name: "compose file", in: filepath.FromSlash("rel/docker-compose.yml"), want: filepath.Join(cwd, "rel", "docker-compose.yml"), kind: SourceFile},
		{name: "spaces", in: "  rel  ", want: filepath.Join(cwd, "rel"), kind: SourceFolder},
		{name: "unsupported file", in: "notes.txt", err: "notes.txt is a file, not a folder, and not a Dockerfile"},
		{name: "missing", in: "nope", err: "no such folder or file: nope"},
		{name: "empty", in: " ", err: "no folder or file given"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveSource(tc.in)
			if tc.err != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || got.Path != tc.want || got.Kind != tc.kind || got.IsFile() != (tc.kind == SourceFile) {
				t.Fatalf("got %+v, %v; want %q %s", got, err, tc.want, tc.kind)
			}
			if wantDir := tc.want; tc.kind == SourceFile {
				wantDir = filepath.Dir(tc.want)
				if got.Dir() != wantDir {
					t.Fatalf("Dir = %q, want %q", got.Dir(), wantDir)
				}
			}
		})
	}
	if _, err := ResolveFolder("notes.txt"); err == nil || err.Error() != "notes.txt is a file, not a folder" {
		t.Fatalf("ResolveFolder must keep rejecting files: %v", err)
	}
}

func TestOpenCreatingFromDockerfile(t *testing.T) {
	for name, mk := range layouts {
		t.Run(name, func(t *testing.T) {
			l := mk(t)
			file := filepath.Join(l.repo, "Dockerfile")
			write(t, file, "ARG PHP_VERSION=8.2\nFROM php:${PHP_VERSION}-fpm AS base\nFROM nginx:1.25\n")
			s := session(t, l.root, "alice", nil)

			o, err := Open(s, Request{Folder: file})
			if err != nil {
				t.Fatal(err)
			}
			if !o.Creating || o.Flow == nil || !strings.Contains(o.Note, "3 technologies") || !strings.Contains(o.Note, "3 infrastructure") || strings.ContainsAny(o.Note, "\n\t") {
				t.Fatalf("opened = %+v", o)
			}
			d := o.Flow.Draft()
			versions := map[string]string{}
			for _, tech := range d.Project.Techs {
				versions[tech.Name] = tech.Version
			}
			if versions["php"] != "8.2" || versions["nginx"] != "1.25" || len(d.Project.Lockfiles) != 0 {
				t.Fatalf("draft = %+v", d.Project)
			}
			if got := o.Flow.Current().Default; got != "app" {
				t.Fatalf("the name should default to the file's folder, got %q", got)
			}
			prev, err := s.EditProject(ops.ProjectChange{Project: "app", Ops: Edits(s, o.Flow)})
			if err != nil || prev.Blocked() || !strings.Contains(prev.Diff, "php") {
				t.Fatalf("preview = %+v, %v", prev, err)
			}
		})
	}
}

func TestOpenRejectsAnUnsupportedFile(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "repo", "notes.txt"), "x")
	s := session(t, root, "alice", nil)
	if _, err := Open(s, Request{Folder: filepath.Join(root, "repo", "notes.txt")}); err == nil || !strings.Contains(err.Error(), "not a Dockerfile") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenLeavesIgnoredPathsOutUnlessAsked(t *testing.T) {
	l := layouts["absolute root"](t)
	write(t, filepath.Join(l.repo, ".gitignore"), "Dockerfile.dev\nlegacy/\n")
	write(t, filepath.Join(l.repo, "Dockerfile.dev"), "FROM nginx:1.25\n")
	write(t, filepath.Join(l.repo, "legacy", "Dockerfile"), "FROM php:8.2\n")
	write(t, filepath.Join(l.repo, "Dockerfile"), "FROM redis:7\n")
	s := session(t, l.root, "alice", nil)

	o, err := Open(s, Request{Folder: l.repo})
	if err != nil {
		t.Fatal(err)
	}
	for _, tech := range o.Flow.Draft().Project.Techs {
		if tech.Name == "php" {
			t.Fatalf("an ignored folder was scanned: %+v", o.Flow.Draft().Project.Techs)
		}
	}
	file := filepath.Join(l.repo, "Dockerfile.dev")
	if _, err := Open(s, Request{Folder: file}); err == nil || !strings.Contains(err.Error(), "is ignored by .gitignore") {
		t.Fatalf("an ignored file must be refused, err = %v", err)
	}
	if _, err := Open(s, Request{Folder: file, IncludeIgnored: true}); err != nil {
		t.Fatalf("IncludeIgnored: %v", err)
	}
}
