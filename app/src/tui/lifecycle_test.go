package tui

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

const accessCfg = "# who may do what\naccess:\n  root: {projects: ['*'], write: true}\n  alice: {projects: [shop, mw], write: true}\n  bob: {projects: [shop]}\n"

// treeOf is every file under root with its content, to prove nothing changed.
func treeOf(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			b, _ := os.ReadFile(p)
			out[p] = string(b)
		}
		return nil
	})
	return out
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func findingsOfProject(t *testing.T, b *fake, project string) []model.Finding {
	t.Helper()
	state, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Finding
	for _, f := range ledger.New(state).Findings() {
		if f.Project == project {
			out = append(out, f)
		}
	}
	return out
}

// dataOf is the data folder of the configuration under root.
func dataOf(t *testing.T, root string) string {
	t.Helper()
	cfg, err := config.LoadLenient(root)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.DataDir
}

func rowNames(d *driver) []string {
	var out []string
	for _, p := range d.m.(*app).data.Projects {
		out = append(out, p.Name)
	}
	return out
}

func TestRenameShowsConsequencesBeforeAnyChangeThenLandsOnTheRenamedProject(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "root")
	b, root := diskFake(t, map[string]string{"config/config.yaml": accessCfg})
	d := start(t, b, Options{})
	d.press("3", "down") // shop
	before := treeOf(t, root)
	d.press("R")
	d.want("Rename project shop", "> New name: shop", "findings and access rules follow")
	d.press("ctrl+u")
	d.typ("shop")
	d.press("enter")
	d.want("problem: the new name is the same")
	d.press("ctrl+u")
	d.typ("mw")
	d.press("enter")
	d.want("problem:", "already exists", "> New name: mw")
	d.press("ctrl+u")
	d.typ("webshop")
	d.press("enter")
	d.want("Rename project: shop to webshop", "Consequences", "Findings: 3 findings (3 open)",
		"Access rules:", "alice: follows the new name, projects after: webshop, mw", "bob: follows the new name, projects after: webshop",
		"Files:", "create", "config/projects/shop.yaml -> config/projects/webshop.yaml", "backup", "rewrite", "config/config.yaml",
		"Warnings:", "3 findings move to \"webshop\"", "This is destructive", "Rename shop?")
	if got := crumbOf(d); got != "Projects › shop › rename" {
		t.Errorf("crumb %q", got)
	}
	if !sameTree(before, treeOf(t, root)) {
		t.Fatal("the consequences are shown before anything changes")
	}
	if b.writes != 0 {
		t.Fatal("previewing is a read")
	}
	d.press("enter")
	d.want("ok: renamed shop to webshop")
	if got := rowNames(d); strings.Join(got, ",") != "mw,webshop" {
		t.Fatalf("the list must show the new state: %v", got)
	}
	if got := selectedName(t, d); got != "webshop" {
		t.Fatalf("landed on %q", got)
	}
	if d.m.(*app).prj.life != nil || d.m.(*app).prj.deep {
		t.Fatal("back on the list")
	}
	if d.exists(root, "config/projects/shop.yaml") || !strings.Contains(fileAt(t, root, "config/projects/webshop.yaml"), "name: webshop") {
		t.Fatal("the file moved")
	}
	if !strings.Contains(fileAt(t, root, "config/projects/webshop.yaml"), "# the shop") {
		t.Fatal("the comments stay")
	}
	if !strings.Contains(fileAt(t, root, "config/config.yaml"), "webshop") || !strings.Contains(fileAt(t, root, "config/config.yaml"), "# who may do what") {
		t.Fatalf("access rules follow, comments stay:\n%s", fileAt(t, root, "config/config.yaml"))
	}
	if len(findingsOfProject(t, b, "shop")) != 0 || len(findingsOfProject(t, b, "webshop")) != 3 {
		t.Fatal("the findings moved")
	}
	if matches, _ := filepath.Glob(filepath.Join(dataOf(t, root), "project-backups", "*")); len(matches) == 0 {
		t.Fatal("the old file is backed up")
	}
	if log := readFile(t, filepath.Join(dataOf(t, root), "audit.log")); !strings.Contains(log, `"action":"project"`) || !strings.Contains(log, "renamed project to webshop") {
		t.Fatalf("audit:\n%s", log)
	}
	if b.writes != 1 {
		t.Fatalf("one write session, got %d", b.writes)
	}
}

func TestRenameInsideAProjectLandsInsideTheRenamedOne(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "enter", "R")
	d.press("ctrl+u")
	d.typ("webshop")
	d.press("enter")
	d.want("Rename project: shop to webshop")
	if got := crumbOf(d); got != "Projects › shop › rename" {
		t.Errorf("crumb %q", got)
	}
	d.press("y")
	d.want("ok: renamed shop to webshop", "webshop")
	a := d.m.(*app)
	if !a.prj.deep || selectedName(t, d) != "webshop" {
		t.Fatalf("deep %v on %q", a.prj.deep, selectedName(t, d))
	}
	if got := crumbOf(d); got != "Projects › webshop" {
		t.Errorf("crumb %q", got)
	}
	if !d.exists(root, "config/projects/webshop.yaml") {
		t.Fatal("renamed")
	}
}

func TestEscCancelsALifecycleChangeAndNothingChanges(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down")
	before := treeOf(t, root)
	for _, keys := range [][]string{{"X"}, {"Z"}, {"R", "ctrl+u"}, {"D"}} {
		d.press(keys[0])
		if len(keys) > 1 {
			d.typ("other")
			d.press("enter")
		} else if keys[0] == "D" {
			d.press("enter")
		}
		d.want("Consequences")
		d.press("esc")
		d.want("cancelled, nothing was changed", "PROJECT")
		d.wantNot("Consequences")
	}
	d.press("X", "q") // q works like esc
	d.wantNot("Consequences")
	d.press("X", "enter", "esc") // esc leaves the question for the name
	d.want("Consequences")
	d.press("esc")
	if !sameTree(before, treeOf(t, root)) || b.writes != 0 {
		t.Fatal("cancelling changed something")
	}
}

func TestDuplicateNeedsNoConfirmationOfItsOwnAndLandsOnTheCopy(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "D")
	d.want("Duplicate project shop", "> Name of the copy: shop-copy")
	d.press("enter")
	d.want("Duplicate project: shop as shop-copy", "Findings: 3 findings", "create", "Duplicate shop?")
	d.wantNot("destructive")
	d.press("enter")
	d.want("ok: duplicated shop as shop-copy")
	if got := selectedName(t, d); got != "shop-copy" {
		t.Fatalf("landed on %q", got)
	}
	if !d.exists(root, "config/projects/shop.yaml") || !strings.Contains(fileAt(t, root, "config/projects/shop-copy.yaml"), "name: shop-copy") {
		t.Fatal("both files exist")
	}
}

func TestDeleteNeedsTheTypedNameAndOptionallyClosesFindings(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "X")
	d.want("Delete project: shop", "Findings: 3 findings (3 open)", "[ ] close the open findings", "backup", "3 findings stay in the ledger unchanged", "Delete shop?")
	d.press("c")
	d.want("[x] close the open findings", "3 open findings are marked ignored")
	d.wantNot("3 findings stay in the ledger")
	d.press("c")
	d.want("[ ] close the open findings")
	d.press("c", "enter")
	d.want("Delete shop? Type its name to confirm", "> Name:")
	d.press("enter")
	d.want("problem: type the name of the project exactly")
	d.typ("sho")
	d.press("enter")
	d.want("problem: type the name of the project exactly", "sho")
	if !d.exists(root, "config/projects/shop.yaml") {
		t.Fatal("a wrong name deletes nothing")
	}
	d.typ("p")
	d.press("enter")
	d.want("ok: deleted shop", "PROJECT")
	if d.exists(root, "config/projects/shop.yaml") {
		t.Fatal("the file is gone from the projects")
	}
	if got := strings.Join(rowNames(d), ","); got != "mw" {
		t.Fatalf("rows %s", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(dataOf(t, root), "project-backups", "shop*")); len(matches) == 0 {
		t.Fatal("moved to the backups, not erased")
	}
	fs := findingsOfProject(t, b, "shop")
	if len(fs) != 3 {
		t.Fatalf("findings stay: %d", len(fs))
	}
	for _, f := range fs {
		if f.Status != model.StatusIgnored {
			t.Fatalf("close findings marks them ignored: %s", f.Status)
		}
	}
}

func TestDisableListsTheProjectAsDisabledAndEnableBringsItBack(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "Z")
	d.want("Disable project: shop", "rename", "config/projects/shop.yaml -> config/projects/shop.yaml.disabled", "Disable shop?")
	d.press("enter")
	d.want("ok: disabled shop", "shop", "disabled", "switched off")
	if d.exists(root, "config/projects/shop.yaml") || !d.exists(root, "config/projects/shop.yaml.disabled") {
		t.Fatal("renamed to .disabled")
	}
	if got := strings.Join(rowNames(d), ","); got != "mw,shop" {
		t.Fatalf("rows %s", got)
	}
	if got := selectedName(t, d); got != "shop" {
		t.Fatalf("landed on %q", got)
	}
	d.want("disabled: the file is switched off")
	// what cannot be done to a disabled project says so
	for _, k := range []string{"R", "D", "e", "c"} {
		d.press(k)
		d.want("error:", "disabled")
		d.press("esc")
	}
	d.press("Z")
	d.want("Enable project: shop", "Enable shop?")
	d.press("y")
	d.want("ok: enabled shop")
	if !d.exists(root, "config/projects/shop.yaml") || d.exists(root, "config/projects/shop.yaml.disabled") {
		t.Fatal("back to .yaml")
	}
	d.wantNot("switched off")

	// a disabled project can be deleted without enabling it first
	d.press("Z", "enter")
	d.press("X", "enter")
	d.typ("shop")
	d.press("enter")
	d.want("ok: deleted shop")
	if got := strings.Join(rowNames(d), ","); got != "mw" {
		t.Fatalf("rows %s", got)
	}
}

func TestLifecycleOfAccessControlledProjects(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "bob")
	b, root := diskFake(t, map[string]string{"config/config.yaml": accessCfg})
	d := start(t, b, Options{})
	d.press("3")
	if got := strings.Join(rowNames(d), ","); got != "shop" {
		t.Fatalf("bob sees %s", got)
	}
	before := treeOf(t, root)
	d.press("X")
	d.want("Delete project: shop", "Access rules:", "alice: loses the project", "bob: loses the project, no project left")
	d.press("enter")
	d.typ("shop")
	d.press("enter")
	d.want("error: access refused", "problem: access refused")
	d.press("esc")
	d.want("Consequences", "error: access refused")
	d.press("esc")
	if !sameTree(before, treeOf(t, root)) {
		t.Fatal("refused: nothing changed")
	}
}

func TestLifecycleFailureIsShownAndStaysUntilTheUserActs(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "R", "ctrl+u")
	d.typ("webshop")
	d.press("enter")
	d.want("Rename project: shop to webshop")
	// a file sits where the folder for the backups should be: the last step fails and the earlier ones are undone
	if err := os.MkdirAll(dataOf(t, root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataOf(t, root), "project-backups"), []byte("not a folder"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.press("enter")
	d.want("error: rename of shop failed", "put back", "Rename project: shop to webshop", "Rename shop?")
	if !d.exists(root, "config/projects/shop.yaml") || d.exists(root, "config/projects/webshop.yaml") || len(findingsOfProject(t, b, "shop")) != 3 {
		t.Fatal("nothing changed")
	}
	// moving around keeps the error; an action ends the message but the screen keeps the reason
	d.press("down")
	d.want("error: rename of shop failed")
	d.press("esc")
	d.want("cancelled", "PROJECT")
	d.wantNot("put back")
}

func TestLifecycleRefusalByTheCheckAtApplyTimeStaysOnScreen(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "R", "ctrl+u")
	d.typ("webshop")
	d.press("enter")
	if err := os.WriteFile(filepath.Join(root, "config", "projects", "webshop.yaml"), []byte("name: webshop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.press("enter")
	d.want("error: a project named \"webshop\" already exists", "Rename project: shop to webshop")
	d.press("down")
	d.want("already exists")
}

func TestLifecyclePreviewErrorsAreShownAsErrors(t *testing.T) {
	b, _ := diskFake(t, map[string]string{"config/projects/bad.yaml": "name: bad\ntechs: [oops\n"})
	d := start(t, b, Options{})
	d.press("3", "down", "down", "R")
	d.want("error: the file of bad does not load")
	d.press("X")
	d.want("Delete project: bad", "does not parse")
}

func TestNewEmptyProjectNeedsNoFolder(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "N")
	d.want("New empty project", "> Name", "Environments")
	d.press("enter", "enter")
	d.want("problem: give the project a name")
	d.press("shift+tab")
	d.typ("mw")
	d.press("enter", "enter")
	d.want("problem:", "already exists")
	d.press("shift+tab", "ctrl+u")
	d.typ("blog")
	d.press("tab")
	d.typ("qa")
	d.press("enter")
	d.want("not an environment", "blog", "qa")
	d.press("ctrl+u")
	d.typ("dev, prod")
	d.press("enter")
	d.want("New project: blog", "create project blog", "Save this change?", "name: blog")
	if d.exists(root, "config/projects/blog.yaml") {
		t.Fatal("not before the user says yes")
	}
	d.press("y")
	d.want("ok: saved blog")
	if got := fileAt(t, root, "config/projects/blog.yaml"); !strings.Contains(got, "name: blog") || !strings.Contains(got, "prod") {
		t.Fatalf("file:\n%s", got)
	}
	if got := selectedName(t, d); got != "blog" {
		t.Fatalf("landed on %q", got)
	}
}

func TestLifecycleScreensFitSmallTerminals(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "root")
	b, _ := diskFake(t, map[string]string{"config/config.yaml": accessCfg, "config/projects/off.yaml.disabled": "name: off\n"})
	d := start(t, b, Options{})
	for _, size := range [][2]int{{30, 8}, {40, 10}, {70, 16}, {120, 40}} {
		d.send(tea_window(size[0], size[1]))
		for _, keys := range [][]string{{"3", "down"}, {"R", "ctrl+u"}, {"x", "y", "z", "enter"}, {"esc"}, {"X"}, {"enter"}, {"esc", "esc"}, {"D", "enter"}, {"esc"}, {"j", "j", "j"}, {"Z"}, {"esc"}} {
			d.press(keys...)
			lines := strings.Split(d.view(), "\n")
			if len(lines) > size[1] {
				t.Fatalf("%dx%d: %d lines after %v", size[0], size[1], len(lines), keys)
			}
			for _, l := range lines {
				if width(l) > size[0] {
					t.Fatalf("%dx%d: a line is %d cells after %v: %q", size[0], size[1], width(l), keys, l)
				}
			}
		}
		d.press("esc", "esc", "esc")
	}
}

func TestStaleListIsReloadedAfterAnExternalChange(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "Z")
	// the file is switched on again behind the TUI's back, so the confirmation fails and the list reloads
	os.Rename(filepath.Join(root, "config", "projects", "shop.yaml"), filepath.Join(root, "config", "projects", "shop.yaml.disabled"))
	d.press("enter")
	d.want("error:")
	d.press("esc", "r")
	d.want("shop", "disabled")
}
