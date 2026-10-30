package setup

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// repoDir is an absolute folder on every platform ("/repo/my-app" has no
// drive letter on Windows).
var repoDir, _ = filepath.Abs("/repo/my-app")

func testCatalog() *catalog.Catalog {
	return catalog.New([]model.Tech{
		{Name: "php", Title: "PHP", Aliases: []string{"php-fpm"}},
		{Name: "nginx", Title: "NGINX"},
		{Name: "redis", Title: "Redis"},
		{Name: "postgresql", Title: "PostgreSQL"},
		{Name: "postfix", Title: "Postfix"},
	})
}

func scan() discovery.Result {
	return discovery.Result{
		Root: repoDir,
		Techs: []discovery.TechProposal{
			{Tech: "php", Title: "PHP", Version: "8.2", Confidence: discovery.High,
				Evidence: []discovery.Evidence{{File: "composer.lock", Detail: "package php in composer.lock"}, {File: "Dockerfile"}}},
			{Tech: "nginx", Title: "NGINX", Version: "1.25", Confidence: discovery.Medium,
				Evidence: []discovery.Evidence{{File: "Dockerfile", Detail: "image nginx:1.25"}}},
			{Tech: "redis", Title: "Redis", Confidence: discovery.Low,
				Evidence: []discovery.Evidence{{File: "docker-compose.yml", Detail: "marker file docker-compose.yml"}}},
		},
		Lockfiles: []discovery.LockProposal{{Type: "composer", Path: "composer.lock", Packages: 42}},
		Notes:     []string{"stopped after 3000 files"},
	}
}

// answer checks the current step id and answers it.
func answer(t *testing.T, f *Flow, id, v string) {
	t.Helper()
	if got := f.Current().ID; got != id {
		t.Fatalf("current step = %q, want %q", got, id)
	}
	if err := f.Answer(v); err != nil {
		t.Fatalf("answer %q to %s: %v", v, id, err)
	}
}

func TestCreateFlowEndToEnd(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	f.UseDiscovery(repoDir, scan())

	if st := f.Current(); st.ID != "name" || st.Default != "my-app" || st.Kind != KindText {
		t.Fatalf("name step = %+v", st)
	}
	answer(t, f, "name", "shop")

	st := f.Current()
	want := []Option{
		{"php", "PHP", "high: package php in composer.lock (+1 more)", true},
		{"nginx", "NGINX", "medium: image nginx:1.25", true},
		{"redis", "Redis", "low: marker file docker-compose.yml", false},
	}
	if st.ID != "techs" || st.Kind != KindMulti || !reflect.DeepEqual(st.Options, want) {
		t.Fatalf("techs step = %+v", st)
	}
	if !strings.Contains(st.Help, "stopped after 3000 files") {
		t.Errorf("notes not shown: %q", st.Help)
	}
	answer(t, f, "techs", "php,nginx")

	answer(t, f, "add-techs", "postgres")
	if st := f.Current(); st.ID != "add-techs" || !strings.Contains(st.Help, "postgresql") {
		t.Fatalf("add-techs should repeat and list what was added: %+v", st)
	}
	answer(t, f, "add-techs", "")

	// php and nginx came with versions; only postgresql is asked.
	if st := f.Current(); st.ID != "version:postgresql" || st.Default != "" {
		t.Fatalf("version step = %+v", st)
	}
	answer(t, f, "version:postgresql", "16")

	st = f.Current()
	if st.ID != "lockfiles" || len(st.Options) != 1 || st.Options[0].Detail != "42 packages" || !st.Options[0].Selected || st.Options[0].Label != "composer composer.lock" {
		t.Fatalf("lockfiles step = %+v", st)
	}
	answer(t, f, "lockfiles", "0")

	st = f.Current()
	for _, o := range st.Options {
		if !o.Selected {
			t.Errorf("env %s should start selected", o.Value)
		}
	}
	answer(t, f, "envs", "dev,int,staging,prod")

	st = f.Current()
	if st.ID != "review" || st.Kind != KindConfirm || !strings.Contains(st.Help, "postgresql") {
		t.Fatalf("review step = %+v", st)
	}
	answer(t, f, "review", "yes")

	if !f.Done() || f.Current().ID != "done" {
		t.Fatal("flow should be done")
	}
	if err := f.Answer("x"); err == nil {
		t.Error("answering a finished flow should fail")
	}

	wantOps := []projectfile.Op{
		{Kind: "set_tech", Tech: "php", Version: "8.2"},
		{Kind: "set_tech", Tech: "nginx", Version: "1.25"},
		{Kind: "set_tech", Tech: "postgresql", Version: "16"},
		{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "composer", Path: filepath.Join(repoDir, "composer.lock")}},
	}
	if got := f.Ops(); !reflect.DeepEqual(got, wantOps) {
		t.Fatalf("ops = %+v\nwant %+v", got, wantOps)
	}
	if d := f.Draft(); d.Project.Name != "shop" || d.Dir != repoDir || len(d.Evidence["php"]) != 2 || d.Existing != nil {
		t.Errorf("draft = %+v", d)
	}
}

func TestLowTechOnlyOffered(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	f.UseDiscovery("", scan())
	for _, tc := range f.Draft().Project.Techs {
		if tc.Name == "redis" {
			t.Fatal("low confidence tech must not be in the draft")
		}
	}
	// Selecting it explicitly does add it.
	answer(t, f, "name", "")
	answer(t, f, "techs", "php,redis")
	if got := f.Draft().Project.Techs; len(got) != 2 || got[1].Name != "redis" {
		t.Errorf("techs = %+v", got)
	}
}

func TestDiscoveryNeverOverwritesVersion(t *testing.T) {
	ex := &model.Project{Name: "x", Techs: []model.ProjectTech{{Name: "PHP", Version: "7.4"}}}
	f := NewFlow(testCatalog(), ex)
	f.UseDiscovery("/repo", scan())
	got := f.Draft().Project.Techs
	if len(got) != 2 || got[0].Version != "7.4" || got[1].Name != "nginx" {
		t.Errorf("techs = %+v", got)
	}
}

func TestEditFlowMinimalOps(t *testing.T) {
	ex := &model.Project{Name: "shop", Techs: []model.ProjectTech{{Name: "php", Version: "8.1"}, {Name: "redis", Version: "6"}}}
	f := NewFlow(testCatalog(), ex)
	if st := f.Current(); st.ID != "menu" || st.Kind != KindChoice {
		t.Fatalf("first step = %+v", st)
	}
	if len(f.Ops()) != 0 {
		t.Fatal("untouched draft must yield no ops")
	}
	answer(t, f, "menu", "techs")
	answer(t, f, "techs", "php") // drops redis
	answer(t, f, "menu", "add-techs")
	answer(t, f, "add-techs", "nginx")
	answer(t, f, "add-techs", "done")
	answer(t, f, "menu", "versions")
	if st := f.Current(); st.ID != "version:php" || st.Default != "8.1" {
		t.Fatalf("version step = %+v", st)
	}
	answer(t, f, "version:php", "8.2")
	answer(t, f, "version:nginx", "")
	answer(t, f, "menu", "review")
	answer(t, f, "review", "yes")

	want := []projectfile.Op{
		{Kind: "remove_tech", Tech: "redis"},
		{Kind: "set_tech", Tech: "php", Version: "8.2"},
		{Kind: "set_tech", Tech: "nginx"},
	}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v\nwant %+v", got, want)
	}
}

func TestEditSameVersionNoOps(t *testing.T) {
	ex := &model.Project{Name: "shop", Techs: []model.ProjectTech{{Name: "php", Version: "8.1"}}}
	f := NewFlow(testCatalog(), ex)
	answer(t, f, "menu", "versions")
	answer(t, f, "version:php", "")
	// Clearing a version is remove + set, because set_tech cannot clear one.
	want := []projectfile.Op{{Kind: "remove_tech", Tech: "php"}, {Kind: "set_tech", Tech: "php"}}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
	f.Back()
	f.Back()
	answer(t, f, "menu", "versions")
	answer(t, f, "version:php", "8.1")
	if len(f.Ops()) != 0 {
		t.Errorf("restoring the version should leave no ops: %+v", f.Ops())
	}
}

func TestEditEnvs(t *testing.T) {
	ex := &model.Project{Name: "shop", Envs: []model.Env{"prod", "dev"}}
	f := NewFlow(testCatalog(), ex)
	answer(t, f, "menu", "envs")
	st := f.Current()
	if st.Options[0].Selected != true || st.Options[1].Selected || !st.Options[3].Selected {
		t.Fatalf("envs options = %+v", st.Options)
	}
	answer(t, f, "envs", "prod,dev") // same set, no op
	if len(f.Ops()) != 0 {
		t.Fatalf("ops = %+v", f.Ops())
	}
	answer(t, f, "menu", "envs")
	answer(t, f, "envs", "dev,int,staging,prod") // all four clears the key
	want := []projectfile.Op{{Kind: "set_envs"}}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
	answer(t, f, "menu", "envs")
	answer(t, f, "envs", "staging")
	want = []projectfile.Op{{Kind: "set_envs", Envs: []model.Env{"staging"}}}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
}

func TestBackKeepsAnswers(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	f.UseDiscovery(repoDir, scan())
	f.Back() // first step: no-op
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "php")
	f.Back()
	if st := f.Current(); st.ID != "techs" || !st.Options[0].Selected || st.Options[1].Selected {
		t.Fatalf("after Back: %+v", st)
	}
	f.Back()
	if st := f.Current(); st.ID != "name" || st.Default != "shop" {
		t.Fatalf("after second Back: %+v", st)
	}
	if f.Draft().Project.Name != "shop" {
		t.Error("name lost")
	}
}

func TestReviewNoGoesBack(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")
	answer(t, f, "add-techs", "")
	answer(t, f, "envs", "dev")
	answer(t, f, "review", "no")
	if f.Done() || f.Current().ID != "techs" {
		t.Fatalf("current = %q", f.Current().ID)
	}
}

func TestRejectedAnswers(t *testing.T) {
	long := strings.Repeat("a", 201)
	tests := []struct {
		name, step, answer string
	}{
		{"bad name", "name", "Bad Name"},
		{"name with dash start", "name", "-x"},
		{"control char", "name", "a\x00b"},
		{"newline", "name", "a\nb"},
		{"escape", "name", "a\x1b[31m"},
		{"too long", "name", long},
		{"unknown option", "techs", "nope"},
		{"unknown term", "add-techs", "foo"},
		{"bad version", "version:php", "abc"},
		{"no envs", "envs", ""},
		{"bad env", "envs", "dev,qa"},
		{"bad confirm", "review", "maybe"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFlow(testCatalog(), nil)
			f.draft.Techs = []model.ProjectTech{{Name: "php"}}
			// walk to the step: name, techs, add-techs, version, [lockfiles skipped], envs, review
			steps := []struct{ id, a string }{{"name", "shop"}, {"techs", "php"}, {"add-techs", ""}, {"version:php", ""}, {"envs", "dev"}}
			for _, s := range steps {
				if f.Current().ID == tc.step {
					break
				}
				answer(t, f, s.id, s.a)
			}
			id := f.Current().ID
			if id != tc.step {
				t.Fatalf("at %q, want %q", id, tc.step)
			}
			if err := f.Answer(tc.answer); err == nil {
				t.Fatal("answer should be rejected")
			}
			st := f.Current()
			if st.ID != tc.step || st.Problem == "" {
				t.Fatalf("step = %+v", st)
			}
			// A later good answer clears the problem.
			f.Back()
			if f.Current().Problem != "" {
				t.Error("Back should clear the problem")
			}
		})
	}
}

func TestVersionAnswers(t *testing.T) {
	for _, ok := range []string{"", "8.2", "v8", "8.2.30-alpine", "  9  "} {
		f := NewFlow(testCatalog(), nil)
		f.draft.Techs = []model.ProjectTech{{Name: "php"}}
		answer(t, f, "name", "shop")
		answer(t, f, "techs", "php")
		answer(t, f, "add-techs", "")
		answer(t, f, "version:php", ok)
		if got := f.Draft().Project.Techs[0].Version; got != strings.TrimSpace(ok) {
			t.Errorf("version for %q = %q", ok, got)
		}
	}
}

func TestAddTechs(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")

	// exact name, alias, mixed separators
	answer(t, f, "add-techs", "redis, php-fpm  NGINX")
	got := f.Draft().Project.Techs
	if len(got) != 3 || got[0].Name != "redis" || got[1].Name != "php" || got[2].Name != "nginx" {
		t.Fatalf("techs = %+v", got)
	}

	// ambiguous and unknown terms: nothing is added, the step stays, suggestions are named
	err := f.Answer("post foo redisx")
	if err == nil {
		t.Fatal("expected a problem")
	}
	st := f.Current()
	for _, w := range []string{"post", "foo", "redisx", "postgresql", "postfix", "redis"} {
		if !strings.Contains(st.Problem, w) {
			t.Errorf("problem %q lacks %q", st.Problem, w)
		}
	}
	if st.ID != "add-techs" || len(f.Draft().Project.Techs) != 3 {
		t.Fatalf("step %q, techs %+v", st.ID, f.Draft().Project.Techs)
	}
	// already present: not added twice
	answer(t, f, "add-techs", "redis")
	if len(f.Draft().Project.Techs) != 3 {
		t.Error("duplicate added")
	}
	// at most five suggestions
	f.cat = catalog.New([]model.Tech{{Name: "aa1"}, {Name: "aa2"}, {Name: "aa3"}, {Name: "aa4"}, {Name: "aa5"}, {Name: "aa6"}, {Name: "aa7"}})
	if err := f.Answer("aa"); err == nil || strings.Contains(err.Error(), "aa6") {
		t.Errorf("suggestions not capped: %v", err)
	}
	answer(t, f, "add-techs", "")
	// all three have no version: asked in draft order
	if f.Current().ID != "version:redis" {
		t.Errorf("current = %q", f.Current().ID)
	}
}

func TestNameTaken(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	f.NameTaken = func(n string) bool { return n == "shop" }
	if err := f.Answer("shop"); err == nil || !strings.Contains(f.Current().Problem, "a project with that name already exists") {
		t.Fatalf("err = %v, problem = %q", err, f.Current().Problem)
	}
	answer(t, f, "name", "shop2")
}

func TestFolderName(t *testing.T) {
	for in, want := range map[string]string{
		"": "project", "/": "project", "/repo/My App_v2": "my-app-v2", "/x/--Foo--": "foo",
		"/x/日本語": "project", "/x/" + strings.Repeat("a", 80): strings.Repeat("a", 63),
	} {
		if got := FolderName(in); got != want {
			t.Errorf("FolderName(%q) = %q, want %q", in, got, want)
		}
		if _, err := projectfile.New(FolderName(in)); err != nil {
			t.Errorf("FolderName(%q) is not a valid name: %v", in, err)
		}
	}
}

func TestOpsDeterministic(t *testing.T) {
	ex := &model.Project{
		Name:  "shop",
		Techs: []model.ProjectTech{{Name: "php", Version: "8.1"}, {Name: "zzz"}, {Name: "aaa"}},
		Environments: map[model.Env]model.EnvConfig{
			"prod": {Techs: map[string]string{"php": "8.1", "zzz": "1", "aaa": "2"}, Image: "v1"},
			"dev":  {Techs: map[string]string{"zzz": "3", "aaa": "4"}},
		},
	}
	build := func() []projectfile.Op {
		f := NewFlow(testCatalog(), ex)
		answer(t, f, "menu", "techs")
		answer(t, f, "techs", "php")
		return f.Ops()
	}
	want := []projectfile.Op{
		{Kind: "remove_tech", Tech: "zzz"},
		{Kind: "remove_tech", Tech: "aaa"},
		{Kind: "remove_env_tech", Env: "dev", Tech: "aaa"},
		{Kind: "remove_env_tech", Env: "dev", Tech: "zzz"},
		{Kind: "remove_env_tech", Env: "prod", Tech: "aaa"},
		{Kind: "remove_env_tech", Env: "prod", Tech: "zzz"},
	}
	for i := 0; i < 20; i++ {
		if got := build(); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: ops = %+v", i, got)
		}
	}
	if len(ex.Environments["prod"].Techs) != 3 {
		t.Error("the existing project was modified")
	}
}

func TestEnvTechAndImageOps(t *testing.T) {
	ex := &model.Project{Name: "shop", Environments: map[model.Env]model.EnvConfig{"prod": {Techs: map[string]string{"php": "8.1"}, Image: "v1"}}}
	f := NewFlow(testCatalog(), ex)
	f.draft.Environments["prod"] = model.EnvConfig{Techs: map[string]string{"php": "8.2", "nginx": "1.25"}, Image: ""}
	want := []projectfile.Op{
		{Kind: "set_env_tech", Env: "prod", Tech: "nginx", Version: "1.25"},
		{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.2"},
		{Kind: "set_image", Env: "prod", Image: ""},
	}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
}

func TestReviewCreated(t *testing.T) {
	f := NewFlow(testCatalog(), nil)
	f.UseDiscovery(repoDir, scan())
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "php,nginx")
	answer(t, f, "add-techs", "")
	answer(t, f, "lockfiles", "0")
	answer(t, f, "envs", "dev,prod")

	diff, issues, err := f.Review(testCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"+ ", "php", "8.2", "nginx", filepath.Join(repoDir, "composer.lock"), "dev"} {
		if !strings.Contains(diff, w) {
			t.Errorf("diff lacks %q:\n%s", w, diff)
		}
	}
	if len(issues) != 0 {
		t.Errorf("issues = %+v", issues)
	}
	if st := f.Current(); st.ID != "review" || !strings.Contains(st.Help, "nginx") {
		t.Errorf("review help = %q", st.Help)
	}

	// A tech outside the catalog is a warning, not an error.
	_, issues, err = f.Review(catalog.New(nil))
	if err != nil || len(issues) == 0 || issues[0].Level != "warning" {
		t.Errorf("issues = %+v, err = %v", issues, err)
	}

	// Before a name exists there is nothing to preview; the help falls back to a summary.
	g := NewFlow(testCatalog(), nil)
	if _, _, err := g.Review(nil); err == nil {
		t.Error("expected an error without a name")
	}
}

const existingYAML = `# mine
name: shop
techs:
  - {name: php, version: "8.1"}
  - {name: redis, version: "6"}
lockfiles:
  - {type: composer, path: composer.lock}
  - {type: npm, path: package-lock.json}
`

func TestEditLockfileRemoval(t *testing.T) {
	file, err := projectfile.Parse([]byte(existingYAML))
	if err != nil {
		t.Fatal(err)
	}
	ex := file.Project()
	f := NewFlow(testCatalog(), &ex)
	f.SetExistingBytes([]byte(existingYAML))

	answer(t, f, "menu", "lockfiles")
	st := f.Current()
	if len(st.Options) != 2 || !st.Options[0].Selected || !st.Options[1].Selected || st.Options[1].Detail != "already in the project" {
		t.Fatalf("lockfile options = %+v", st.Options)
	}
	answer(t, f, "lockfiles", "0")

	want := []projectfile.Op{{Kind: "remove_lockfile", Lockfile: model.Lockfile{Type: "npm", Path: "package-lock.json"}}}
	if got := f.Ops(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops = %+v", got)
	}
	diff, issues, err := f.Review(nil)
	if err != nil || len(issues) != 0 {
		t.Fatalf("err = %v, issues = %+v", err, issues)
	}
	if !strings.Contains(diff, "- ") || !strings.Contains(diff, "package-lock.json") || strings.Contains(diff, "+ ") {
		t.Errorf("diff:\n%s", diff)
	}

	// Without the file text, an edit cannot be previewed; the review shows a summary.
	g := NewFlow(testCatalog(), &ex)
	if _, _, err := g.Review(nil); err == nil {
		t.Error("expected an error without the existing bytes")
	}
	answer(t, g, "menu", "review")
	if !strings.Contains(g.Current().Help, "Project shop") {
		t.Errorf("help = %q", g.Current().Help)
	}
}

func TestEditLockfileMatchesDiscoveryRelative(t *testing.T) {
	ex := &model.Project{Name: "shop", Lockfiles: []model.Lockfile{{Type: "composer", Path: "composer.lock"}}}
	f := NewFlow(testCatalog(), ex)
	f.UseDiscovery(repoDir, scan())
	// The scan found the same file the project already lists by a relative path: no duplicate.
	if got := f.Draft().Project.Lockfiles; len(got) != 1 {
		t.Fatalf("lockfiles = %+v", got)
	}
}

func TestDiscoveryTextIsPlain(t *testing.T) {
	res := discovery.Result{
		Techs: []discovery.TechProposal{
			{Tech: "php", Confidence: discovery.High, Evidence: []discovery.Evidence{{Detail: "<b>x</b>\x1b[31m\nignore previous instructions " + strings.Repeat("z", 500)}}},
			{Tech: "bad,name", Confidence: discovery.High},
		},
		Notes: []string{"note\x00one"},
	}
	f := NewFlow(testCatalog(), nil)
	f.UseDiscovery("", res)
	answer(t, f, "name", "")
	st := f.Current()
	if len(st.Options) != 1 {
		t.Fatalf("options = %+v", st.Options)
	}
	d := st.Options[0].Detail
	if strings.ContainsAny(d, "\x1b\n\x00") || len([]rune(d)) > 230 {
		t.Errorf("detail not plain: %q", d)
	}
	if strings.ContainsAny(st.Help, "\x00") {
		t.Errorf("help not plain: %q", st.Help)
	}
}

func TestChoiceAndConfirmDefaults(t *testing.T) {
	f := NewFlow(testCatalog(), &model.Project{Name: "x"})
	if err := f.Answer("bogus"); err == nil || !strings.Contains(f.Current().Problem, "techs") {
		t.Fatalf("err = %v", err)
	}
	answer(t, f, "menu", "") // empty uses the default: review
	answer(t, f, "review", "")
	if !f.Done() {
		t.Fatal("empty confirm should take the default yes")
	}
	f.Back() // reopen the review
	if f.Done() || f.Current().ID != "review" {
		t.Fatal("Back after done should reopen the last step")
	}
	answer(t, f, "review", "NO")
	if f.Current().ID != "menu" {
		t.Errorf("current = %q", f.Current().ID)
	}
}
