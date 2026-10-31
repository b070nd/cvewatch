package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

// infraFake is a fake whose catalog knows base images, so a Dockerfile proposes technologies.
func infraFake(t *testing.T) *fake {
	t.Helper()
	b := newFake(t, nil)
	b.cfg.Techs = []model.Tech{
		{Name: "php", Title: "PHP", Category: "language", Detect: model.Detect{
			Versions: []model.VersionHint{{File: ".php-version", Pattern: `^\s*(\S+)`}}, Images: []string{"php"}}},
		{Name: "nginx", Title: "Nginx", Category: "web-server", Detect: model.Detect{Images: []string{"nginx"}}},
		{Name: "redis", Title: "Redis", Category: "cache", Detect: model.Detect{Images: []string{"redis"}}},
	}
	b.cfg.Catalog = catalog.New(b.cfg.Techs)
	return b
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (d *driver) toReview() {
	d.t.Helper()
	for i := 0; i < 14 && !strings.Contains(d.view(), "Save this project?"); i++ {
		d.press("enter")
	}
	d.want("Save this project?")
}

func TestPlusOffersWhereTheNewProjectComesFrom(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3")
	d.want("+ add", "- remove")
	d.press("+")
	d.want("Add a project", "From a folder", "From a Dockerfile or compose file", "Empty project")
	if got := crumbOf(d); got != "Projects › add project" {
		t.Errorf("crumb %q", got)
	}
	d.press("esc")
	d.wantNot("From a folder")
	d.press("+", "down", "down", "enter")
	d.want("New empty project", "Name")
	d.press("esc", "+", "down", "enter")
	d.want("Add a project from a Dockerfile, compose file or manifest", "File:")
	d.press("esc", "+", "enter")
	d.want("Scan a folder for a new project", "Folder:")
}

func TestPlusFromADockerfileProposesTheInfrastructureAndSaves(t *testing.T) {
	b := infraFake(t)
	app := filepath.Join(t.TempDir(), "webapp")
	writeFiles(t, app, map[string]string{
		"Dockerfile": "ARG PHP_VERSION=8.2\nFROM php:${PHP_VERSION}-fpm AS base\nFROM nginx:1.25\n",
		"notes.txt":  "x",
	})
	d := start(t, b, Options{})
	d.press("3", "+", "down", "enter")
	d.typ(app + pathSep + "Dock")
	d.want("Dockerfile", "1 file in")
	d.wantNot("notes.txt")
	d.press("tab")
	d.want("Dockerfile▏")
	d.want("a Dockerfile: a project is proposed from this file alone")
	d.press("enter")
	d.want("New project", "Project name", "> webapp", "ok: scanned")
	d.press("enter")
	d.want("Technologies", "Infrastructure", "[x] PHP", "[x] Nginx")
	d.press("enter")
	d.toReview()
	d.press("y")
	d.want("ok: created project webapp")
	f := projectFile(t, b, "webapp")
	if !strings.Contains(f, "php") || !strings.Contains(f, "nginx") {
		t.Fatalf("the base images are the technologies:\n%s", f)
	}
}

func TestTechnologiesStepGroupsInfrastructureApart(t *testing.T) {
	b := infraFake(t)
	site := filepath.Join(t.TempDir(), "site")
	writeFiles(t, site, map[string]string{".php-version": "8.2.1\n", "Dockerfile": "FROM nginx:1.25\nFROM redis:7\n"})
	d := start(t, b, Options{})
	d.press("3", "+", "enter")
	d.typ(site)
	d.press("enter", "enter")
	d.want("Technologies", "Infrastructure", "PHP", "Nginx", "Redis")
	v := d.view()
	php, head, nginx := strings.Index(v, "PHP"), strings.Index(v, "Infrastructure"), strings.Index(v, "Nginx")
	if !(php < head && head < nginx) {
		t.Fatalf("the application first, then the infrastructure:\n%s", v)
	}
	if !d.m.(*app).frm.grp {
		t.Fatal("grouped")
	}
	// the cursor and the ticks work on the regrouped rows
	d.press("down", " ")
	d.want("[ ] Nginx")
	d.toReview()
	d.press("y")
	d.want("ok: created project site")
	f := projectFile(t, b, "site")
	if !strings.Contains(f, "php") || !strings.Contains(f, "redis") || strings.Contains(f, "nginx") {
		t.Fatalf("unticked nginx is left out:\n%s", f)
	}
}

func TestMinusAsksAndOnlyThenDeletesTheProject(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down") // shop
	before := treeOf(t, root)
	d.press("-")
	d.want("Delete project: shop", "Consequences", "Delete shop?")
	d.press("esc")
	d.want("cancelled, nothing was changed", "> shop")
	d.press("-", "enter")
	d.want("Delete shop? Type its name to confirm")
	d.typ("sho")
	d.press("enter")
	d.want("problem: type the name of the project exactly")
	d.press("esc", "esc")
	if !sameTree(before, treeOf(t, root)) || b.writes != 0 {
		t.Fatal("cancelling must keep the project")
	}
	d.press("-", "enter")
	d.typ("shop")
	d.press("enter")
	d.want("ok: deleted shop")
	if d.exists(root, "config/projects/shop.yaml") {
		t.Fatal("deleted")
	}
	if got := strings.Join(rowNames(d), ","); got != "mw" {
		t.Fatalf("rows %s", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(dataOf(t, root), "project-backups", "shop*")); len(matches) == 0 {
		t.Fatal("moved to the backups")
	}
}

func TestMinusInsideAProjectAndTheOldKeysStillWork(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "enter", "-")
	d.want("Delete project: shop")
	d.press("esc", "esc")
	d.press("X")
	d.want("Delete project: shop")
	d.press("esc")
	d.press("N")
	d.want("New empty project")
	d.press("esc")
	d.press("-", "enter")
	d.typ("mw")
	d.press("enter")
	d.want("problem: type the name")
	d.wantNot("ok: deleted")
	if !d.exists(root, "config/projects/shop.yaml") {
		t.Fatal("the wrong name deletes nothing")
	}
}

const magentoShop = "# the shop\nname: shop\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: \"8.2\"}\n"

func TestProjectWhoseFileStemIsNotItsNameCanBeEditedAndDeleted(t *testing.T) {
	b, root := diskFake(t, map[string]string{
		"config/projects/shop.yaml": dropFile, "config/projects/mw.yaml": dropFile,
		"config/projects/magento2-shop.yaml": magentoShop,
	})
	d := start(t, b, Options{})
	d.press("3")
	d.want("> shop")
	p, ok := d.m.(*app).selectedProject()
	if !ok || !p.HasFile || filepath.Base(p.File) != "magento2-shop.yaml" {
		t.Fatalf("the row must know its file: %+v", p)
	}
	d.wantNot("not editable here")

	d.press("c", "home", "down", "down", "down", "down", "enter", "ctrl+u")
	d.typ("2026-04-01")
	d.press("enter")
	d.want("+ since: 2026-04-01")
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/magento2-shop.yaml"); !strings.Contains(got, "since: 2026-04-01") || !strings.Contains(got, "# the shop") {
		t.Fatalf("the edit lands in the real file:\n%s", got)
	}
	if d.exists(root, "config/projects/shop.yaml") {
		t.Fatal("no second file")
	}

	d.press("esc", "esc")
	d.press("-")
	d.want("Delete project: shop", "magento2-shop.yaml")
	d.press("enter")
	d.typ("shop")
	d.press("enter")
	d.want("ok: deleted shop")
	if d.exists(root, "config/projects/magento2-shop.yaml") {
		t.Fatal("the file of shop is gone")
	}
	if matches, _ := filepath.Glob(filepath.Join(dataOf(t, root), "project-backups", "*")); len(matches) == 0 {
		t.Fatal("moved to the backups")
	}
	if len(rowNames(d)) != 0 {
		t.Fatalf("rows %v", rowNames(d))
	}
}

func TestLockfileIsAddedByItsFileWithCompletionAndTypeFromTheName(t *testing.T) {
	b, root := diskFake(t, map[string]string{"repos/other/custom-deps.json": `{}`})
	d := start(t, b, Options{})
	d.press("3", "down", "c")
	d.toField(2)
	d.press("enter", "+")
	d.want("Add a lockfile to shop", "Lockfile:")
	other := filepath.Join(root, "repos", "other")
	d.typ(other + pathSep + "comp")
	d.want("composer lockfile", "1 file in")
	d.wantNot("custom-deps.json") // only lockfiles are offered
	d.press("tab")
	d.want("composer.lock▏", "a composer lockfile")
	d.press("enter")
	d.want("Add a composer lockfile to shop", "Env", "Dev", "repos/other/composer.lock")
	d.typ("prod")
	d.press("enter", "enter")
	d.want("Save this change?", "add composer lockfile repos/other/composer.lock")
	if got := d.opKinds(); len(got) != 1 || got[0] != "add_lockfile" {
		t.Fatalf("ops %v", got)
	}
	d.press("y")
	d.want("ok: saved shop")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "repos/other/composer.lock") || !strings.Contains(got, "prod") {
		t.Fatalf("lockfile:\n%s", got)
	}

	// a name that tells no type asks for it, in the existing list of types
	d.press("+")
	d.typ(filepath.Join(other, "custom-deps.json"))
	d.want("the type is not known from the name")
	d.press("enter")
	d.want("Type of custom-deps.json", "composer")
	if got := crumbOf(d); !strings.HasSuffix(got, "lockfile type") {
		t.Errorf("crumb %q", got)
	}
	d.press("down", "esc") // esc leaves it, nothing is added
	d.wantNot("Type of custom-deps.json")
	d.press("+")
	d.typ(filepath.Join(other, "custom-deps.json"))
	d.press("enter", "enter")
	d.want("lockfile to shop", "repos/other/custom-deps.json")
	d.press("esc")

	// a folder, a missing file: the reason is on the prompt
	d.press("+")
	d.typ(other)
	d.press("enter")
	d.want("problem:", "is a folder, not a lockfile")
	d.press("ctrl+u")
	d.typ(filepath.Join(other, "nothing.lock"))
	d.press("enter")
	d.want("problem: no such file")
}

func TestLockfileIsRemovedOnlyAfterTheAnswerYes(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "c")
	d.toField(2)
	d.press("enter", "-")
	d.want("Remove lockfile repos/shop/composer.lock from shop?")
	d.press("n")
	d.wantNot("Remove lockfile", "Save this change?")
	d.press("x", "esc")
	d.wantNot("Save this change?")
	d.press("-", "y")
	d.want("Save this change?", "remove lockfile repos/shop/composer.lock")
	d.press("esc")
	if b.writes != 0 || !strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "repos/shop/composer.lock") {
		t.Fatal("nothing is written before the last yes")
	}
	d.press("-", "y", "y")
	d.want("ok: saved shop: remove lockfile repos/shop/composer.lock")
	if strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "composer.lock") {
		t.Fatal("removed")
	}
}

func TestNewProjectFlowAddsAndRemovesLockfiles(t *testing.T) {
	b := newFake(t, nil)
	site := filepath.Join(t.TempDir(), "site")
	writeFiles(t, site, map[string]string{
		".php-version":                  "8.2.1\n",
		"web/package-lock.json":         `{"lockfileVersion":3,"packages":{"":{},"node_modules/express":{"version":"4.18.2"}}}`,
		"extra/composer.lock":           `{"packages":[]}`,
		"extra/custom-deps.unknownfile": `{}`,
	})
	d := start(t, b, Options{})
	d.press("3", "d")
	d.typ(filepath.Join(site, "web"))
	d.press("enter", "enter", "enter", "enter") // name, techs, add-techs, versions
	for i := 0; i < 4 && !strings.Contains(d.view(), "Inventory sources"); i++ {
		d.press("enter")
	}
	d.want("Inventory sources", "[x] npm", "+ add lockfile", "- remove")

	d.press("-")
	d.want("Remove lockfile npm")
	d.press("n")
	d.want("[x] npm")
	d.press("-", "y")
	d.want("[ ] npm", "left out")

	d.press("+")
	d.want("Add a lockfile to the project being set up", "Lockfile:")
	d.typ(filepath.Join(site, "extra") + pathSep + "comp")
	d.press("tab", "enter")
	d.want("[x] composer", "added composer lockfile composer.lock")
	d.wantNot("[x] npm")

	d.press("enter") // envs
	d.press("+")     // not on this step
	d.wantNot("Add a lockfile")
	d.toReview()
	d.want("{type: composer")
	d.wantNot("{type: npm")
	d.press("+")
	d.want("Add a lockfile to the project being set up")
	d.typ(filepath.Join(site, "web", "package-lock.json"))
	d.press("enter")
	d.want("{type: npm", "Save this project?")
	d.press("y")
	d.want("ok: created project web")
	f := projectFile(t, b, "web")
	if !strings.Contains(f, "composer.lock") || !strings.Contains(f, "package-lock.json") {
		t.Fatalf("both lockfiles are in the project:\n%s", f)
	}
}

func TestSelectingAProjectSetsTheScopeAndShowsItsSecurityIssues(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "down") // mw
	d.wantNot("scope: mw")
	d.press("enter")
	d.want("scope: mw", "Security issues", "1 open security issue: 1 high", "CVE-2026-1", "Tracked PHP bug")
	d.wantNot("CVE-2026-3")
	a := d.m.(*app)
	if a.scope != "mw" {
		t.Fatalf("scope %q", a.scope)
	}
	d.press("1")
	d.want("scope: mw")
	d.press("2")
	d.want("1 of 1 open issues")
	d.wantNot("CVE-2026-3")
	d.press("3")
	d.want("Security issues")

	d.press("s")
	if got := crumbOf(d); got != "Projects › mw › security issues" {
		t.Fatalf("crumb %q", got)
	}
	d.want("Security issues of mw", "> high", "CVE-2026-1")
	d.press("enter")
	d.want("[2 Findings (1)]", "CVE-2026-1")
	if got := crumbOf(d); !strings.HasPrefix(got, "Findings › CVE-2026-1") {
		t.Fatalf("crumb %q", got)
	}
	d.press("esc") // back comes to the list of the project's issues
	d.want("[3 Projects]", "Security issues of mw")
	if got := crumbOf(d); got != "Projects › mw › security issues" {
		t.Fatalf("crumb %q", got)
	}
	d.press("esc")
	d.want("c edits the fields")
	d.press("esc")
	d.want("PROJECT", "scope: mw")
	d.press("0")
	d.wantNot("scope: mw")
	if a.scope != "" {
		t.Fatal("0 clears the scope")
	}
}

func TestProjectWithoutProblemsOpensItsIssuesWithEnter(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "down", "enter", "enter")
	d.want("Security issues of mw", "> high")
	d.press("i")
	d.want("[2 Findings", "project:mw")
}

func TestProjectsKeysAreTheSameInTheTablesAndTheHelp(t *testing.T) {
	for _, md := range []*mode{mo.projects, mo.project} {
		var plus, minus, x, upperN *binding
		for i := range md.binds {
			b := &md.binds[i]
			switch {
			case b.has("+"):
				plus = b
			case b.has("-"):
				minus = b
			case b.has("X"):
				x = b
			case b.has("N"):
				upperN = b
			}
		}
		if plus == nil || minus == nil || plus.short == "" || minus.short == "" {
			t.Errorf("%s: + and - are in the footer", md.name)
		}
		if x == nil || !x.alias || upperN == nil || !upperN.alias {
			t.Errorf("%s: X and N stay as aliases", md.name)
		}
		h := strings.Join(helpLines(md, 100), "\n")
		for _, w := range []string{"add a project", "remove the project"} {
			if !strings.Contains(h, w) {
				t.Errorf("%s: help lacks %q", md.name, w)
			}
		}
	}
	for _, md := range []*mode{mo.fieldSub} {
		h := strings.Join(strings.Fields(strings.Join(helpLines(md, 100), " ")), " ") // the help wraps where it likes
		if !strings.Contains(h, "add an environment, a technology, or a lockfile by picking its file") || !strings.Contains(h, "remove the selected item after asking") {
			t.Errorf("%s: help lacks the new keys", md.name)
		}
	}
	h := strings.Join(helpLines(mo.formMulti, 100), "\n")
	if !strings.Contains(h, "add a lockfile") || !strings.Contains(h, "leave the selected lockfile out") {
		t.Error("the checklist of the form: help lacks the lockfile keys")
	}
	if !strings.Contains(strings.Join(helpLines(mo.formReview, 100), "\n"), "add a lockfile") {
		t.Error("the review: help lacks +")
	}
	if !strings.Contains(strings.Join(helpLines(mo.projectIssues, 100), "\n"), "open the selected issue") {
		t.Error("the issues of a project: help lacks enter")
	}
}

func TestFolderBoxOffersFilesAndSaysWhatItAccepts(t *testing.T) {
	root := folderTree(t)
	writeFiles(t, root, map[string]string{"Dockerfile": "FROM scratch\n", "docker-compose.yml": "services: {}\n"})
	b := newFolderBox()
	var names []string
	for _, e := range b.entries {
		names = append(names, e.Name)
	}
	if got := strings.Join(names[len(names)-2:], ","); got != "docker-compose.yml,Dockerfile" && got != "Dockerfile,docker-compose.yml" {
		t.Fatalf("files come after the folders: %v", names)
	}
	if len(b.files) != 2 {
		t.Fatalf("files %v", b.files)
	}
	b.setText("Dockerf")
	if len(b.entries) != 1 || !b.files[b.entries[0].Path] {
		t.Fatalf("entries %v", b.entries)
	}
	b.key(key("tab"))
	if b.text() != "Dockerfile" {
		t.Fatalf("a file is completed whole, without a separator: %q", b.text())
	}
	b.setText("")
	for range 10 {
		b.key(key("down"))
	}
	if b.sel() < 0 || !b.files[b.entries[b.sel()].Path] {
		t.Fatalf("the cursor reaches the files: %d", b.sel())
	}
	b.key(key("tab"))
	if strings.HasSuffix(b.text(), pathSep) {
		t.Fatalf("a file is not opened as a folder: %q", b.text())
	}
	b.setText("notes.txt")
	for _, want := range []string{"a file, not a folder", "Dockerfile", "compose file", "Kubernetes manifest", "lockfile"} {
		if !strings.Contains(b.status(), want) {
			t.Errorf("status %q lacks %q", b.status(), want)
		}
	}
	b.setText("Dockerfile")
	if !strings.Contains(b.status(), "a Dockerfile") {
		t.Errorf("status %q", b.status())
	}
	b.setText("zzz")
	if b.status() != "no such folder or file" {
		t.Errorf("status %q", b.status())
	}

	lb := newBox(boxLockfile, "Lockfile")
	for _, e := range lb.entries {
		if lb.files[e.Path] && e.Name != "package-lock.json" && e.Name != "composer.lock" {
			t.Errorf("only lockfiles are offered: %s", e.Name)
		}
	}
	lb.setText("Dockerfile")
	if !strings.Contains(lb.status(), "not known from the name") {
		t.Errorf("status %q", lb.status())
	}
	lb.setText("zzz.lock")
	if !strings.Contains(lb.status(), "no such file") {
		t.Errorf("status %q", lb.status())
	}
	lb.setText("shop")
	if !strings.Contains(lb.status(), "folder") {
		t.Errorf("status %q", lb.status())
	}
}
