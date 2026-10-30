package wizard

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/setup"
	"github.com/b070nd/cvewatch/app/src/store"
)

// newSession opens a session over a temp root with a small catalog.
func newSession(t *testing.T) *ops.Session {
	t.Helper()
	root := t.TempDir()
	techs := []model.Tech{
		{Name: "php", Title: "PHP"},
		{Name: "nginx", Title: "NGINX"},
		{Name: "redis", Title: "Redis"},
		{Name: "laravel", Title: "Laravel", Detect: model.Detect{
			Packages: []model.PackageHint{{Ecosystem: "composer", Name: "laravel/framework"}}}},
	}
	cfg := &config.Bundle{
		Settings: config.Settings{DataDir: filepath.Join(root, "data"), AlertsDir: filepath.Join(root, "alerts")},
		Root:     root,
		Techs:    techs,
		Catalog:  catalog.New(techs),
		Projects: []model.Project{},
	}
	s, err := ops.OpenWith(cfg, store.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repo makes a folder inside the root with a composer.lock and a .tool-versions.
func repo(t *testing.T, s *ops.Session) string {
	t.Helper()
	dir := filepath.Join(s.Cfg.Root, "repos", "shop")
	write(t, filepath.Join(dir, "composer.lock"), `{"packages":[{"name":"laravel/framework","version":"v10.1.0"}]}`)
	write(t, filepath.Join(dir, ".tool-versions"), "php 8.2.1\n")
	return dir
}

func projectFile(s *ops.Session, name string) string {
	return filepath.Join(s.Cfg.Root, "config", "projects", name+".yaml")
}

// run feeds the lines to f and returns what was printed.
func run(t *testing.T, lines string, f func(IO) error) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := f(IO{In: strings.NewReader(lines), Out: &out})
	return out.String(), err
}

func TestCreateFromFolder(t *testing.T) {
	s := newSession(t)
	dir := repo(t, s)
	// name, techs (all), nothing to add, lockfiles (keep), envs (keep), confirm.
	out, err := run(t, "shop\nall\n\n\n\nyes\n", func(io IO) error { return Setup(io, s, dir, "") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"  1. [x] Laravel", "high: asdf pins php 8.2.1", "saved config/projects/shop.yaml",
		"cvewatch doctor", "cvewatch update"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	b, err := os.ReadFile(projectFile(s, "shop"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"name: shop", `{name: php, version: "8.2.1"}`, "{type: composer, path: repos/shop/composer.lock}"} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, s.Cfg.Root) || strings.Contains(got, dir) {
		t.Errorf("file holds an absolute path:\n%s", got)
	}
}

func TestCreateFromFolderUnderLoadedConfigRoot(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	cfg, err := config.Load(".")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ops.OpenWith(cfg, store.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "repos", "shop")
	write(t, filepath.Join(dir, "composer.lock"), `{"packages":[]}`)
	// name, techs (none), add techs (none), lockfiles (keep), envs (keep), confirm.
	out, err := run(t, "shop\n\n\n\n\nyes\n", func(io IO) error { return Setup(io, s, dir, "") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b, err := os.ReadFile(projectFile(s, "shop"))
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(root)
	if !strings.Contains(string(b), "{type: composer, path: repos/shop/composer.lock}") || strings.Contains(string(b), real) {
		t.Fatalf("file:\n%s", b)
	}
}

const blog = "# my blog\nname: blog\ntechs:\n  - {name: php, version: \"8.1\"}\n  - {name: nginx, version: \"1.24\"}\n"

func TestEditExistingMakesMinimalDiff(t *testing.T) {
	s := newSession(t)
	write(t, projectFile(s, "blog"), blog)
	// menu: techs, keep only php; menu: add redis, then done; menu: review, yes.
	in := "techs\n1\nadd-techs\nredis\n\nreview\nyes\n"
	out, err := run(t, in, func(io IO) error { return Setup(io, s, "", "blog") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var changed []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "+ ") || strings.HasPrefix(l, "- ") {
			changed = append(changed, l)
		}
	}
	if len(changed) != 2 || !strings.Contains(changed[0], "nginx") || !strings.Contains(changed[1], "redis") {
		t.Fatalf("want one removal and one addition, got %q\n%s", changed, out)
	}
	b, _ := os.ReadFile(projectFile(s, "blog"))
	want := "# my blog\nname: blog\ntechs:\n  - {name: php, version: \"8.1\"}\n  - {name: redis}\n"
	if string(b) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", b, want)
	}
}

func TestEditUnknownProject(t *testing.T) {
	s := newSession(t)
	if _, err := run(t, "", func(io IO) error { return Setup(io, s, "", "ghost") }); err == nil {
		t.Fatal("unknown project accepted")
	}
}

func TestBackAndHelp(t *testing.T) {
	s := newSession(t)
	out, err := run(t, "shop\nback\n?\nquit\n", func(io IO) error { return Setup(io, s, "", "") })
	if err != nil {
		t.Fatal(err)
	}
	// shown at the start, after back and after ?
	if n := strings.Count(out, "Lowercase letters, digits and dashes"); n != 3 {
		t.Errorf("name step shown %d times, want 3:\n%s", n, out)
	}
	if !strings.Contains(out, "Technologies") || !strings.HasSuffix(out, "nothing was changed\n") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestQuitWritesNothing(t *testing.T) {
	s := newSession(t)
	dir := repo(t, s)
	out, err := run(t, "shop\nall\nquit\n", func(io IO) error { return Setup(io, s, dir, "") })
	if err != nil || !strings.Contains(out, "nothing was changed") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(projectFile(s, "shop")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("quit wrote a file")
	}
}

func TestEOFAborts(t *testing.T) {
	s := newSession(t)
	for _, in := range []string{"", "shop\n", "shop"} {
		_, err := run(t, in, func(io IO) error { return Setup(io, s, "", "") })
		if err == nil || err.Error() != "input ended" {
			t.Errorf("input %q: err = %v", in, err)
		}
	}
	if _, err := os.Stat(projectFile(s, "shop")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an aborted flow wrote a file")
	}
}

func TestFiveBadAnswersAbort(t *testing.T) {
	s := newSession(t)
	out, err := run(t, strings.Repeat("Bad Name\n", 8), func(io IO) error { return Setup(io, s, "", "") })
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("err = %v", err)
	}
	if n := strings.Count(out, "  ! invalid project name"); n != 5 {
		t.Errorf("%d rejections shown, want 5:\n%s", n, out)
	}
	// a good answer in between resets the count
	out, err = run(t, strings.Repeat("Bad\n", 4)+"ok\nBad\nquit\n", func(io IO) error { return Setup(io, s, "", "") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestOutputIsPlainText(t *testing.T) {
	var out bytes.Buffer
	w := &wiz{out: &out}
	w.show(setup.Step{Title: "T\x1b[31m", Help: "line1\r\nline2\x07 \u202eevil",
		Kind: setup.KindMulti, Options: []setup.Option{{Value: "a", Label: "\x1b]0;pwn\x07label", Detail: "\x9bdetail\x00"}}})
	s := out.String()
	for _, r := range s {
		if r != '\n' && (unicode.IsControl(r) || r == '\u202e') {
			t.Fatalf("control character %U in %q", r, s)
		}
	}
	for _, want := range []string{"T[31m", "line1\nline2 evil", "[ ] ]0;pwnlabel", "detail"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%q", want, s)
		}
	}
}

func TestTranslate(t *testing.T) {
	multi := setup.Step{Kind: setup.KindMulti, Options: []setup.Option{
		{Value: "a", Selected: true}, {Value: "b"}, {Value: "c", Selected: true}}}
	for _, c := range []struct {
		st       setup.Step
		in, want string
	}{
		{multi, "", "a,c"},
		{multi, "2 3", "b,c"},
		{multi, "1,b", "a,b"},
		{multi, "all", "a,b,c"},
		{multi, "none", ""},
		{multi, "9", "9"}, // left for the flow to reject
		{setup.Step{Kind: setup.KindChoice, Options: multi.Options}, "2", "b"},
		{setup.Step{Kind: setup.KindChoice, Options: multi.Options}, "c", "c"},
		{setup.Step{Kind: setup.KindConfirm}, "Y", "yes"},
		{setup.Step{Kind: setup.KindConfirm}, "no", "no"},
		{setup.Step{Kind: setup.KindText, Default: "8.2"}, "", "8.2"},
		{setup.Step{Kind: setup.KindText, Default: "8.2"}, "-", ""},
		{setup.Step{Kind: setup.KindText}, " x ", "x"},
	} {
		if got := translate(c.st, strings.TrimSpace(c.in)); got != c.want {
			t.Errorf("%v %q = %q, want %q", c.st.Kind, c.in, got, c.want)
		}
	}
}

func TestMenuLoop(t *testing.T) {
	s := newSession(t)
	write(t, projectFile(s, "blog"), blog)
	dir := repo(t, s)
	in := strings.Join([]string{
		"9", "nonsense", // rejected, asked again
		"new", dir, "shop", "all", "", "", "", "yes", // create from a folder
		"1", "", "quit", // new from scratch, stopped: back at the menu
		"edit", "1", "quit", // edit blog, stopped: back at the menu
		"quit",
	}, "\n") + "\n"
	out, err := run(t, in, func(io IO) error { return Menu(io, s) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"Projects: blog\n", "Projects: blog, shop\n", "saved config/projects/shop.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "cvewatch projects\n"); n != 4 {
		t.Errorf("menu shown %d times, want 4", n)
	}
	if _, err := os.Stat(projectFile(s, "shop")); err != nil {
		t.Fatal(err)
	}
}

func TestMenuEndOfInputQuits(t *testing.T) {
	s := newSession(t)
	if _, err := run(t, "", func(io IO) error { return Menu(io, s) }); err != nil {
		t.Fatal(err)
	}
	// end of input inside a flow is still an error
	if _, err := run(t, "new\n\n", func(io IO) error { return Menu(io, s) }); err == nil || err.Error() != "input ended" {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateWithAnOwnKeywordAndHints(t *testing.T) {
	s := newSession(t)
	// shop; no scanned techs; algolia is refused with the way out, +algolia is taken; no version; default environments; save.
	in := "shop\n\nalgolia\n+algolia\n\n\n\nyes\n"
	out, err := run(t, in, func(io IO) error { return Setup(io, s, "", "") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		`"algolia" is not in the catalog; write +algolia to add it as your own keyword`,
		"Your own technologies, added to techs.yaml:",
		"warn: techs[0].version: algolia has no version",
		"info: envs: no prod environment",
		"added to techs.yaml as your own: algolia",
		"saved config/projects/shop.yaml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "is not in the catalog, so no advisory will match it") {
		t.Errorf("the staged keyword is known to the review:\n%s", out)
	}
	b, err := os.ReadFile(filepath.Join(s.Cfg.Root, "config", "techs.yaml"))
	if err != nil || !strings.Contains(string(b), "name: algolia") {
		t.Fatalf("techs.yaml: %s %v", b, err)
	}
	if p, _ := os.ReadFile(projectFile(s, "shop")); !strings.Contains(string(p), "algolia") {
		t.Fatalf("project file:\n%s", p)
	}
}

func TestQuitLeavesNoOwnKeywordBehind(t *testing.T) {
	s := newSession(t)
	out, err := run(t, "shop\n\n+algolia\n\nquit\n", func(io IO) error { return Setup(io, s, "", "") })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(s.Cfg.Root, "config", "techs.yaml")); err == nil {
		t.Fatal("quitting wrote techs.yaml")
	}
}
