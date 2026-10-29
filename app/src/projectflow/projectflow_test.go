package projectflow

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/setup"
	"github.com/b070nd/cvewatch/app/src/store"
)

const composerLock = `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}],"packages-dev":[]}`
const npmLock = `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/left-pad":{"version":"1.3.0"}}}`

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// layout is a config root and a repository folder under it.
type layout struct {
	root string // as given to config.Load
	real string // the folder behind root
	repo string // absolute repository folder, spelled through root when root is a link
}

func abs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var layouts = map[string]func(t *testing.T) layout{
	"absolute root": func(t *testing.T) layout {
		dir := t.TempDir()
		return layout{root: dir, real: dir, repo: filepath.Join(dir, "repos", "app")}
	},
	"dot root": func(t *testing.T) layout {
		dir := t.TempDir()
		t.Chdir(dir)
		return layout{root: ".", real: dir, repo: filepath.Join(dir, "repos", "app")}
	},
	"symlinked root": func(t *testing.T) layout {
		dir, links := t.TempDir(), t.TempDir()
		link := filepath.Join(links, "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Skip("symlinks are not available")
		}
		return layout{root: link, real: dir, repo: filepath.Join(link, "repos", "app")}
	},
}

func session(t *testing.T, root, actor string, access map[string]config.Grant) *ops.Session {
	t.Helper()
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Access = access
	s, err := ops.OpenWith(cfg, store.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.Actor = actor
	t.Cleanup(func() { s.Close() })
	return s
}

func project(t *testing.T, real, name, body string) {
	t.Helper()
	write(t, filepath.Join(real, "config", "projects", name+".yaml"), "name: "+name+"\n"+body)
}

func TestResolveFolder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cwd := t.TempDir()
	t.Chdir(cwd)
	write(t, filepath.Join(home, "code", "app", "x"), "")
	write(t, filepath.Join(cwd, "rel", "x"), "")
	write(t, filepath.Join(cwd, "afile"), "")
	sep := string(filepath.Separator)

	tests := []struct {
		name, in, want, err string
	}{
		{name: "home", in: "~", want: home},
		{name: "home subfolder", in: "~/code/app", want: filepath.Join(home, "code", "app")},
		{name: "home with os separator", in: "~" + sep + "code", want: filepath.Join(home, "code")},
		{name: "spaces", in: "  ~/code  ", want: filepath.Join(home, "code")},
		{name: "relative to the working directory", in: "rel", want: filepath.Join(cwd, "rel")},
		{name: "dot", in: ".", want: cwd},
		{name: "unclean", in: "rel/../rel/./", want: filepath.Join(cwd, "rel")},
		{name: "absolute", in: home, want: home},
		{name: "missing", in: "nope", err: "no such folder: nope"},
		{name: "missing under home", in: "~/nope", err: "no such folder: ~/nope"},
		{name: "a file", in: "afile", err: "afile is a file, not a folder"},
		{name: "empty", in: "  ", err: "no folder given"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveFolder(tc.in)
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestOpenCreatingFromFolder(t *testing.T) {
	for name, mk := range layouts {
		t.Run(name, func(t *testing.T) {
			l := mk(t)
			project(t, l.real, "taken-file", "")
			write(t, filepath.Join(l.repo, "composer.lock"), composerLock)
			s := session(t, l.root, "alice", nil)

			o, err := Open(s, Request{Folder: l.repo})
			if err != nil {
				t.Fatal(err)
			}
			if !o.Creating || o.Name != "" || o.Flow == nil {
				t.Fatalf("opened = %+v", o)
			}
			if !strings.HasPrefix(o.Note, "scanned ") || !strings.Contains(o.Note, "1 lockfile") || strings.ContainsAny(o.Note, "\n\t") {
				t.Fatalf("note = %q", o.Note)
			}
			d := o.Flow.Draft()
			if d.Existing != nil || len(d.Project.Lockfiles) != 1 || d.Project.Lockfiles[0].Type != "composer" {
				t.Fatalf("draft = %+v", d)
			}
			for _, n := range []string{"taken-file", "shop"} {
				if o.Flow.NameTaken == nil || (n == "taken-file") != o.Flow.NameTaken(n) {
					t.Errorf("NameTaken(%q) wrong", n)
				}
			}
			got := Edits(s, o.Flow)
			want := []projectfile.Op{{Kind: "add_lockfile", Lockfile: d.Project.Lockfiles[0]}}
			want[0].Lockfile.Path = "repos/app/composer.lock"
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("edits = %+v, want %+v", got, want)
			}
			prev, err := s.EditProject(ops.ProjectChange{Project: "fresh", Ops: got})
			if err != nil || prev.Blocked() || !strings.Contains(prev.Diff, "repos/app/composer.lock") {
				t.Fatalf("preview = %+v, %v", prev, err)
			}
		})
	}
}

func TestOpenNameTaken(t *testing.T) {
	root := t.TempDir()
	project(t, root, "shop", "")
	project(t, root, "blog", "")
	s := session(t, root, "alice", nil)
	o, err := Open(s, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Note != "" || !o.Flow.NameTaken("shop") || !o.Flow.NameTaken("blog") || o.Flow.NameTaken("other") {
		t.Fatalf("taken names wrong: %+v", o)
	}
	if err := o.Flow.Answer("shop"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("answer = %v", err)
	}
}

func TestOpenNameTakenOnlyVisible(t *testing.T) {
	root := t.TempDir()
	project(t, root, "shop", "")
	project(t, root, "blog", "")
	access := map[string]config.Grant{"bob": {Projects: []string{"blog"}, Write: true}}
	s := session(t, root, "bob", access)
	o, err := Open(s, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if !o.Flow.NameTaken("blog") || !o.Flow.NameTaken("shop") {
		t.Fatal("configured projects count as taken even when hidden")
	}
}

func TestOpenFolderErrors(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "afile"), "")
	s := session(t, root, "alice", nil)
	for in, want := range map[string]string{
		filepath.Join(root, "missing"): "no such folder",
		filepath.Join(root, "afile"):   "is a file, not a folder",
	} {
		if _, err := Open(s, Request{Folder: in}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("folder %q: err = %v, want %q", in, err, want)
		}
	}
}

func TestOpenFolderRelativeToWorkingDirectory(t *testing.T) {
	root, cwd := t.TempDir(), t.TempDir()
	write(t, filepath.Join(cwd, "app", "composer.lock"), composerLock)
	s := session(t, root, "alice", nil)
	t.Chdir(cwd)
	o, err := Open(s, Request{Folder: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if d := o.Flow.Draft(); len(d.Project.Lockfiles) != 1 || filepath.Base(d.Dir) != "app" || !filepath.IsAbs(d.Dir) {
		t.Fatalf("draft = %+v", d)
	}
}

func TestOpenFolderWithHome(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	write(t, filepath.Join(home, "app", "composer.lock"), composerLock)
	s := session(t, root, "alice", nil)
	o, err := Open(s, Request{Folder: "~/app"})
	if err != nil {
		t.Fatal(err)
	}
	if d := o.Flow.Draft(); len(d.Project.Lockfiles) != 1 || d.Dir != filepath.Join(home, "app") {
		t.Fatalf("draft = %+v", d)
	}
}

func TestEditExistingAndScanOwnFolder(t *testing.T) {
	for name, mk := range layouts {
		for _, raw := range []string{"repos/app/composer.lock", "./repos/app/composer.lock", "repos/../repos/app/composer.lock"} {
			t.Run(name+" "+raw, func(t *testing.T) {
				l := mk(t)
				project(t, l.real, "shop", "lockfiles:\n  - {type: composer, path: "+raw+"}\n")
				write(t, filepath.Join(l.repo, "composer.lock"), composerLock)
				s := session(t, l.root, "alice", nil)

				o, err := Open(s, Request{Project: "shop", Folder: l.repo})
				if err != nil {
					t.Fatal(err)
				}
				if o.Creating || o.Name != "shop" {
					t.Fatalf("opened = %+v", o)
				}
				if got := o.Flow.Draft().Project.Lockfiles; len(got) != 1 {
					t.Fatalf("lockfiles listed twice: %+v", got)
				}
				if got := Edits(s, o.Flow); len(got) != 0 {
					t.Fatalf("edits = %+v, want none", got)
				}

				// deselect the stored lockfile: the removal must name it the way the file spells it
				if err := o.Flow.Answer("lockfiles"); err != nil {
					t.Fatal(err)
				}
				if err := o.Flow.Answer(""); err != nil {
					t.Fatal(err)
				}
				got := Edits(s, o.Flow)
				if len(got) != 1 || got[0].Kind != "remove_lockfile" || got[0].Lockfile.Path != raw {
					t.Fatalf("edits = %+v", got)
				}
				prev, err := s.EditProject(ops.ProjectChange{Project: "shop", Ops: got})
				if err != nil || prev.Blocked() || !strings.Contains(prev.Diff, "composer") {
					t.Fatalf("preview = %+v, %v", prev, err)
				}
			})
		}
	}
}

func TestEditExistingAddsRootRelativePath(t *testing.T) {
	for name, mk := range layouts {
		t.Run(name, func(t *testing.T) {
			l := mk(t)
			project(t, l.real, "shop", "lockfiles:\n  - {type: composer, path: repos/app/composer.lock}\n")
			write(t, filepath.Join(l.repo, "composer.lock"), composerLock)
			write(t, filepath.Join(l.repo, "package-lock.json"), npmLock)
			s := session(t, l.root, "alice", nil)

			o, err := Open(s, Request{Project: "shop", Folder: l.repo})
			if err != nil {
				t.Fatal(err)
			}
			if got := o.Flow.Draft().Project.Lockfiles; len(got) != 2 {
				t.Fatalf("lockfiles = %+v", got)
			}
			got := Edits(s, o.Flow)
			if len(got) != 1 || got[0].Kind != "add_lockfile" || got[0].Lockfile.Path != "repos/app/package-lock.json" {
				t.Fatalf("edits = %+v", got)
			}
		})
	}
}

func TestEditsPathOutsideRoot(t *testing.T) {
	base := t.TempDir()
	root, repo := filepath.Join(base, "root"), filepath.Join(base, "other", "app")
	write(t, filepath.Join(root, "config", "projects", "keep.yaml"), "name: keep\n")
	write(t, filepath.Join(repo, "composer.lock"), composerLock)
	s := session(t, root, "alice", nil)
	o, err := Open(s, Request{Folder: repo})
	if err != nil {
		t.Fatal(err)
	}
	got := Edits(s, o.Flow)
	if len(got) != 1 || got[0].Lockfile.Path != "../other/app/composer.lock" {
		t.Fatalf("edits = %+v", got)
	}
}

func TestEditsKeepsRelativePaths(t *testing.T) {
	root := t.TempDir()
	s := session(t, root, "alice", nil)
	f := setup.NewFlow(s.Cfg.Catalog, nil)
	f.UseDiscovery("", discovery.Result{Lockfiles: []discovery.LockProposal{{Type: "composer", Path: "composer.lock"}}})
	got := Edits(s, f)
	if len(got) != 1 || got[0].Lockfile.Path != "composer.lock" {
		t.Fatalf("edits = %+v", got)
	}
}

func TestOpenEditingErrors(t *testing.T) {
	root := t.TempDir()
	project(t, root, "shop", "")
	project(t, root, "blog", "")
	access := map[string]config.Grant{"bob": {Projects: []string{"blog"}, Write: true}}

	t.Run("denied", func(t *testing.T) {
		s := session(t, root, "bob", access)
		if _, err := Open(s, Request{Project: "shop"}); !errors.Is(err, ops.ErrDenied) {
			t.Fatalf("err = %v, want access denied", err)
		}
		if o, err := Open(s, Request{Project: "blog"}); err != nil || o.Name != "blog" {
			t.Fatalf("allowed project: %+v, %v", o, err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		s := session(t, root, "alice", nil)
		if _, err := Open(s, Request{Project: "nope"}); err == nil || !strings.Contains(err.Error(), "no file under config/projects") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad name", func(t *testing.T) {
		s := session(t, root, "alice", nil)
		if _, err := Open(s, Request{Project: "../x"}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestEditExistingFolderTypedThroughOtherSpelling(t *testing.T) {
	l := layouts["symlinked root"](t)
	project(t, l.real, "shop", "lockfiles:\n  - {type: composer, path: repos/app/composer.lock}\n")
	write(t, filepath.Join(l.repo, "composer.lock"), composerLock)
	s := session(t, l.root, "alice", nil)

	o, err := Open(s, Request{Project: "shop", Folder: filepath.Join(l.real, "repos", "app")})
	if err != nil {
		t.Fatal(err)
	}
	if got := o.Flow.Draft().Project.Lockfiles; len(got) != 1 {
		t.Fatalf("lockfiles listed twice: %+v", got)
	}
	if got := Edits(s, o.Flow); len(got) != 0 {
		t.Fatalf("edits = %+v, want none", got)
	}
}
