package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ruled is an Ignore over a fresh folder whose single .gitignore holds text.
func ruled(t *testing.T, text string) (*Ignore, string) {
	t.Helper()
	root := t.TempDir()
	g := NewIgnore(root)
	g.rules[root] = parseRules(text, root)
	return g, root
}

func TestIgnoreMatcherTable(t *testing.T) {
	type c struct {
		rules, path string
		dir, want   bool
	}
	cases := []c{
		// a bare name matches at any depth, files and folders alike
		{"foo", "foo", false, true}, {"foo", "a/foo", false, true}, {"foo", "a/b/foo", true, true},
		{"foo", "foobar", false, false}, {"foo", "a/foo/x", false, true}, // inside an ignored folder
		// a trailing slash limits the rule to folders
		{"foo/", "foo", true, true}, {"foo/", "foo", false, false}, {"foo/", "a/foo", true, true}, {"foo/", "a/foo/x", false, true},
		// a leading slash, or a slash in the middle, anchors the rule at the .gitignore
		{"/foo", "foo", false, true}, {"/foo", "a/foo", false, false},
		{"a/b", "a/b", false, true}, {"a/b", "x/a/b", false, false}, {"a/b", "a/b/c", false, true},
		{"/a/b/", "a/b", true, true}, {"/a/b/", "a/b", false, false},
		// wildcards
		{"*.log", "x.log", false, true}, {"*.log", "d/x.log", false, true}, {"*.log", "x.logs", false, false}, {"*.log", ".log", false, true},
		{"a?c", "abc", false, true}, {"a?c", "ac", false, false}, {"a?c", "abbc", false, false},
		{"a/*.go", "a/x.go", false, true}, {"a/*.go", "a/b/x.go", false, false}, {"a/*", "a/b/c", false, true},
		{"*", "anything", false, true}, {"*", "a/b", false, true},
		{"te*st*x", "teAAstBBx", false, true}, {"te*st*x", "teAAstBB", false, false}, {"a*a*a*a*b", strings.Repeat("a", 200), false, false},
		// character classes
		{"[abc].txt", "b.txt", false, true}, {"[abc].txt", "d.txt", false, false},
		{"[!abc].txt", "d.txt", false, true}, {"[!abc].txt", "a.txt", false, false}, {"[^abc].txt", "d.txt", false, true},
		{"[a-c]x", "bx", false, true}, {"[a-c]x", "dx", false, false}, {"[]a]x", "]x", false, true},
		{"[[:digit:]]1", "51", false, true}, {"[[:digit:]]1", "a1", false, false}, {"[[:upper:][:digit:]]z", "Qz", false, true},
		{"[abc", "[abc", false, true}, {"[abc", "a", false, false}, // no closing bracket: a plain [
		// ** in all its positions
		{"**/foo", "foo", false, true}, {"**/foo", "a/b/foo", false, true}, {"**/foo", "foobar", false, false},
		{"foo/**", "foo/x", false, true}, {"foo/**", "foo/a/b", false, true}, {"foo/**", "foo", true, false}, {"foo/**", "bar/foo/x", false, false},
		{"a/**/b", "a/b", false, true}, {"a/**/b", "a/x/b", false, true}, {"a/**/b", "a/x/y/b", false, true}, {"a/**/b", "b", false, false}, {"a/**/b", "x/a/b", false, false},
		{"a**b", "axb", false, true}, {"a**b", "a/b", false, false}, {"**", "x", false, true},
		// escapes, comments, blanks and trailing spaces
		{`\#x`, "#x", false, true}, {"# x", "x", false, false}, {"# x", "# x", false, false}, {`\!x`, "!x", false, true},
		{"\n\n  \nfoo", "foo", false, true}, {"foo   ", "foo", false, true}, {`foo\ `, "foo ", false, true}, {`foo\ `, "foo", false, false},
		{`a\*b`, "a*b", false, true}, {`a\*b`, "aXb", false, false}, {`bad\`, "bad", false, false},
		{"foo\r\nbar\r\n", "foo", false, true}, {"foo\r\nbar\r\n", "bar", false, true},
		// negation: the last matching line wins
		{"*.log\n!keep.log", "keep.log", false, false}, {"*.log\n!keep.log", "other.log", false, true},
		{"!keep.log\n*.log", "keep.log", false, true},
		{"build/*\n!build/keep.txt", "build/keep.txt", false, false}, {"build/*\n!build/keep.txt", "build/x", false, true},
		// a file cannot be re-included when its folder is ignored
		{"build/\n!build/keep.txt", "build/keep.txt", false, true},
		{"build\n!build/keep.txt", "build/keep.txt", false, true},
		// nothing is ignored without rules, except .git
		{"", "src/main.go", false, false}, {"", ".git", true, true}, {"", "a/.git", false, true},
	}
	for _, tc := range cases {
		g, root := ruled(t, tc.rules)
		if got := g.Ignored(filepath.Join(root, filepath.FromSlash(tc.path)), tc.dir); got != tc.want {
			t.Errorf("rules %q, path %q (dir=%v): ignored = %v, want %v", tc.rules, tc.path, tc.dir, got, tc.want)
		}
	}
}

func TestIgnoreOutsideTheFolderIsNeverIgnored(t *testing.T) {
	g, root := ruled(t, "*")
	for _, p := range []string{root, filepath.Dir(root), filepath.Join(filepath.Dir(root), "other")} {
		if g.Ignored(p, true) {
			t.Errorf("%s reported ignored", p)
		}
	}
}

func TestIgnoreReadsRulesFromTheRepositoryRootDown(t *testing.T) {
	repo := t.TempDir()
	write(t, repo, ".git/HEAD", "ref: refs/heads/main\n")
	write(t, repo, ".git/info/exclude", "secret.txt\n")
	write(t, repo, ".gitignore", "*.log\n/dist/\nlocal/\n")
	write(t, repo, "svc/.gitignore", "!keep.log\n/tmp/\n")
	write(t, repo, "svc/api/.gitignore", "*.gen\n")
	write(t, repo, "vendored/.git/HEAD", "x\n") // a nested repository
	write(t, repo, "vendored/.gitignore", "own.txt\n")

	g := NewIgnore(filepath.Join(repo, "svc", "api"))
	at := func(rel string, dir bool) bool { return g.Ignored(filepath.Join(repo, filepath.FromSlash(rel)), dir) }
	for _, tc := range []struct {
		rel  string
		dir  bool
		want bool
	}{
		{"svc/api/x.log", false, true},      // from the repository root
		{"svc/api/keep.log", false, false},  // re-included by svc/.gitignore
		{"svc/api/a.gen", false, true},      // from its own folder
		{"svc/api/local", true, true},       // unanchored folder rule from the root
		{"svc/api/tmp", true, false},        // anchored in svc, not here
		{"svc/api/secret.txt", false, true}, // .git/info/exclude
		{"svc/api/main.go", false, false},
	} {
		if got := at(tc.rel, tc.dir); got != tc.want {
			t.Errorf("%s: ignored = %v, want %v", tc.rel, got, tc.want)
		}
	}

	g = NewIgnore(repo)
	if !g.Ignored(filepath.Join(repo, "dist"), true) || g.Ignored(filepath.Join(repo, "svc", "dist"), true) {
		t.Error("/dist/ is anchored at the repository root")
	}
	if !g.Ignored(filepath.Join(repo, "svc", "tmp"), true) {
		t.Error("svc/.gitignore did not apply to svc/tmp")
	}
	// the nested repository keeps its own rules and does not inherit the outer ones
	if g.Ignored(filepath.Join(repo, "vendored", "x.log"), false) || g.Ignored(filepath.Join(repo, "vendored", "secret.txt"), false) {
		t.Error("the outer rules leaked into a nested repository")
	}
	if !g.Ignored(filepath.Join(repo, "vendored", "own.txt"), false) {
		t.Error("the nested repository's own .gitignore was not read")
	}
}

func TestIgnoreWithoutRepositoryUsesTheFoldersOwnFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", "*.out\n")
	write(t, root, "sub/.gitignore", "only-here\n")
	g := NewIgnore(root)
	if !g.Ignored(filepath.Join(root, "sub", "a.out"), false) || !g.Ignored(filepath.Join(root, "sub", "only-here"), false) || g.Ignored(filepath.Join(root, "only-here"), false) {
		t.Error("a folder without .git must still honour .gitignore files at and below it")
	}
}

func TestIgnoreFileWithAByteOrderMark(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", "\ufefffoo\n")
	if !NewIgnore(root).Ignored(filepath.Join(root, "foo"), false) {
		t.Error("the byte order mark hid the first rule")
	}
}

func TestIgnoreNeverUsesTheHomeFolderAsARepository(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows
	write(t, home, ".git/HEAD", "x\n")
	write(t, home, ".gitignore", "*\n")
	write(t, home, "proj/Dockerfile", "FROM nginx:1\n")
	if NewIgnore(filepath.Join(home, "proj")).Ignored(filepath.Join(home, "proj", "Dockerfile"), false) {
		t.Error("a dotfiles repository in the home folder hid a project")
	}
	if NewIgnore(home).Ignored(filepath.Join(home, "proj"), true) {
		t.Error("the home folder's own .gitignore hid its folders")
	}
}

func TestScanSkipsIgnoredPathsAndSaysSo(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", "/generated/\n*.lock.bak\nlocal.Dockerfile\n")
	write(t, root, "web/Dockerfile", "FROM nginx:1.25\n")
	write(t, root, "web/local.Dockerfile", "FROM redis:7\n")             // ignored by the root file
	write(t, root, "generated/Dockerfile", "FROM redis:7\n")             // ignored folder
	write(t, root, "svc/.gitignore", "*.Dockerfile\n!keep.Dockerfile\n") // nested file with a negation
	write(t, root, "svc/db.Dockerfile", "FROM postgres:16\n")
	write(t, root, "svc/keep.Dockerfile", "FROM mysql:8\n")
	write(t, root, "svc/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/express":{"version":"4.18.2"}}}`)
	write(t, root, "other/package-lock.json", `{"lockfileVersion":3,"packages":{"":{}}}`)

	res := scan(t, root, Options{})
	if find(res, "nginx") == nil || find(res, "mysql") == nil || find(res, "express") == nil {
		t.Fatalf("kept paths missing: %+v", res.Techs)
	}
	if find(res, "redis") != nil || find(res, "postgres") != nil {
		t.Errorf("ignored paths were read: %+v", res.Techs)
	}
	if len(res.Lockfiles) != 2 { // a committed lockfile is not ignored
		t.Errorf("lockfiles = %+v", res.Lockfiles)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "3 paths ignored by .gitignore") {
		t.Errorf("notes = %v", res.Notes)
	}

	all := scan(t, root, Options{IncludeIgnored: true})
	if find(all, "redis") == nil || find(all, "postgres") == nil || len(all.Notes) != 0 {
		t.Errorf("IncludeIgnored: techs %+v notes %v", all.Techs, all.Notes)
	}
}

func TestScanIgnoredLockfile(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", "package-lock.json\n")
	write(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{}}}`)
	write(t, root, "composer.lock", `{"packages":[]}`)
	res := scan(t, root, Options{})
	if len(res.Lockfiles) != 1 || res.Lockfiles[0].Type != "composer" {
		t.Errorf("lockfiles = %+v", res.Lockfiles)
	}
}

func TestScanFileRefusesAnIgnoredFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", "Dockerfile.dev\n")
	write(t, root, "Dockerfile.dev", "FROM nginx:1.25\n")
	write(t, root, "Dockerfile", "FROM nginx:1.25\n")
	p := filepath.Join(root, "Dockerfile.dev")

	_, err := ScanFile(p, testCatalog(), Options{})
	if !errors.Is(err, ErrIgnored) || !strings.Contains(err.Error(), "Dockerfile.dev is ignored by .gitignore") {
		t.Fatalf("err = %v", err)
	}
	res, err := ScanFile(p, testCatalog(), Options{IncludeIgnored: true})
	if err != nil || find(res, "nginx") == nil {
		t.Fatalf("IncludeIgnored: %v %+v", err, res.Techs)
	}
	if _, err := ScanFile(filepath.Join(root, "Dockerfile"), testCatalog(), Options{}); err != nil {
		t.Errorf("a file that is not ignored: %v", err)
	}
}

func TestSuggestHidesIgnoredFolders(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".git/HEAD", "x\n")
	write(t, root, ".gitignore", "build-out/\n*.cache\n")
	for _, d := range []string{"build-out", "app", "x.cache", "b-visible"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, entries, err := Suggest(root + sep)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(namesOf(entries), ",")
	if got != "app,b-visible" {
		t.Errorf("entries = %s", got)
	}
}
