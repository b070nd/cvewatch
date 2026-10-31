package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const setCfg = "# global settings\ninterval: 4h   # daemon period\nhttp:\n  timeout: 30s   # per request\n  retries: 3\nslack:\n  min_severity: low\n"

// setStart opens the Settings screen over a configuration folder on disk.
func setStart(t *testing.T, files map[string]string) (*driver, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	all := map[string]string{"config/config.yaml": setCfg}
	for k, v := range files {
		all[k] = v
	}
	b, root := diskFake(t, all)
	d := start(t, b, Options{})
	d.screen("settings")
	return d, root
}

// toSetting puts the cursor on the setting at path, as a jump to it would.
func (d *driver) toSetting(path string) {
	d.t.Helper()
	d.m.(*app).focusSetting(path)
}

const setFeeds = "# my feeds\nsources:\n  - id: acme   # the vendor\n    type: rss\n    url: https://x.example/feed?token=SEKRET123\n    headers:\n      Authorization: Bearer SEKRET456\n"

func cfgOf(t *testing.T, root string) string { return fileAt(t, root, "config/config.yaml") }

// wantLine wants one line of the screen that has all the parts.
func (d *driver) wantLine(parts ...string) {
	d.t.Helper()
	for _, l := range strings.Split(d.view(), "\n") {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return
		}
	}
	d.t.Errorf("no line has %q:\n%s", parts, d.view())
}

// wantSel wants the selected row of a list to have the text.
func (d *driver) wantSel(text string) {
	d.t.Helper()
	for _, l := range strings.Split(d.view(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), ">") && strings.Contains(l, text) {
			return
		}
	}
	d.t.Errorf("the selected row lacks %q:\n%s", text, d.view())
}

// saveSetting runs the edit that is on screen through the review to the file.
func (d *driver) saveSetting(label string) {
	d.t.Helper()
	d.want("Change settings: "+label, "Save these settings changes?", "Changes apply from the next daemon cycle (up to 4h away).")
	d.press("y")
	d.want("saved: " + label)
}

// edit puts the cursor on a setting and types a new value for it.
func (d *driver) edit(path, value string) {
	d.t.Helper()
	d.toSetting(path)
	d.press("enter", "ctrl+u")
	d.typ(value)
	d.press("enter")
}

func TestSettingsScreenListsTheSections(t *testing.T) {
	d, _ := setStart(t, nil)
	d.want("▸[S]ettings", "Configuration: config.yaml, techs.yaml and the files in sources/", "SECTION", "PROBLEMS")
	d.wantLine("Core", "1 set")
	d.wantLine("HTTP", "2 set")
	d.wantLine("Notify", "1 set")
	d.wantLine("Policy", "0 set")
	for _, s := range []string{"Sources", "Tech catalog", "Access"} {
		d.wantLine(s, "0 set")
	}
	d.wantNot("(!)")
	d.press("down", "enter")
	d.want("Settings › HTTP", "Timeout", "30s", "Retries", "duration", "int")
	d.wantLine("User agent", "cvewatch/1.0", "string") // a default, not in the file
	d.press("esc")
	d.want("SECTION")
}

func TestSettingsFieldTypesEditEndToEndAndKeepComments(t *testing.T) {
	d, root := setStart(t, nil)
	d.edit("http.timeout", "45s")
	d.saveSetting("set Timeout to 45s")
	if got := cfgOf(t, root); !strings.Contains(got, "timeout: 45s") || !strings.Contains(got, "# per request") || !strings.Contains(got, "# global settings") {
		t.Fatalf("duration:\n%s", got)
	}
	d.edit("http.retries", "5")
	d.saveSetting("set Retries to 5")
	d.edit("http.rate", "2.5")
	d.saveSetting("set Rate to 2.5")
	d.edit("http.user_agent", "watch/2")
	d.saveSetting("set User agent to watch/2")
	d.toSetting("enrich.epss")
	d.press(" ")
	d.saveSetting("turn on EPSS lookups")
	d.toSetting("slack.min_severity")
	d.press("enter", "down")
	d.press("enter")
	d.saveSetting("set Slack minimum severity to medium")
	d.edit("slack.webhook_env", "MY_HOOK")
	d.saveSetting("set Slack webhook variable to MY_HOOK")
	got := cfgOf(t, root)
	for _, want := range []string{"retries: 5", "rate: 2.5", "user_agent: watch/2", "epss: true", "min_severity: medium", "webhook_env: MY_HOOK", "interval: 4h   # daemon period"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	d.toSetting("enrich.epss")
	d.want("Core")
	d.wantLine("EPSS", "true", "bool")
	d.press("enter")
	d.saveSetting("turn off EPSS lookups")
	if got := cfgOf(t, root); !strings.Contains(got, "epss: false") {
		t.Fatalf("toggle back:\n%s", got)
	}
}

func TestSettingsListsAndMaps(t *testing.T) {
	d, root := setStart(t, nil)
	d.toSetting("notify.email.to")
	d.press("enter")
	d.want("Settings › Notify › to", "+ add to Email to")
	d.press("a")
	d.typ("a@b.c")
	d.press("enter")
	d.saveSetting("add a@b.c to Email to")
	d.press("a")
	d.typ("d@e.f")
	d.press("enter")
	d.saveSetting("add d@e.f to Email to")
	d.wantLine("a@b.c")
	d.wantLine("d@e.f")
	d.press("home", "down") // the second address
	d.press("enter", "ctrl+u")
	d.typ("g@h.i")
	d.press("enter")
	d.want("Save these settings changes?")
	d.press("y")
	d.press("home", "x")
	d.want("Save these settings changes?")
	d.press("y")
	if got := cfgOf(t, root); !strings.Contains(got, "to: [g@h.i]") {
		t.Fatalf("list:\n%s", got)
	}

	d.toSetting("notify.digest.channels")
	d.press("enter", "a")
	d.want("Choose a value for Digest channels")
	d.press("down", "enter")
	d.saveSetting("add webhook to Digest channels")
	if got := cfgOf(t, root); !strings.Contains(got, "channels: [webhook]") {
		t.Fatalf("enum list:\n%s", got)
	}

	d.toSetting("http.host_rates")
	d.press("enter", "a")
	d.typ("example.org")
	d.press("enter")
	d.typ("0.5")
	d.press("enter")
	d.saveSetting("add example.org to Host rates")
	d.wantLine("example.org", "0.5")
	if got := cfgOf(t, root); !strings.Contains(got, "example.org: 0.5") {
		t.Fatalf("map:\n%s", got)
	}
	d.press("home", "x")
	d.press("y")
	if got := cfgOf(t, root); strings.Contains(got, "example.org") {
		t.Fatalf("map item stays:\n%s", got)
	}
}

func TestSettingsSecretsAreNeverShown(t *testing.T) {
	d, root := setStart(t, map[string]string{"sources/custom.yaml": setFeeds})
	d.toSetting("sources")
	d.want("acme", "type=rss")
	d.wantNot("SEKRET")
	d.press("enter")
	d.toSetting("sources.[id=acme].url")
	d.wantLine("URL", "(set)")
	d.press("enter")
	d.want("never shown", "empty removes the value")
	d.wantNot("SEKRET", "x.example")
	d.typ("https://y.example/?k=NEWSECRET")
	d.wantNot("NEWSECRET", "y.example") // masked while typed
	d.press("enter")
	d.want("(set, changed)")
	d.wantNot("SEKRET", "NEWSECRET", "x.example", "y.example")
	d.press("y")
	d.wantNot("SEKRET", "NEWSECRET")
	if got := fileAt(t, root, "sources/custom.yaml"); !strings.Contains(got, "NEWSECRET") || strings.Contains(got, "SEKRET123") || !strings.Contains(got, "# the vendor") {
		t.Fatalf("file:\n%s", got)
	}
	// the headers are secrets too
	d.toSetting("sources.[id=acme].headers")
	d.press("enter")
	d.wantLine("Authorization", "(set)")
	d.wantNot("SEKRET")
	d.press("enter")
	d.want("never shown")
	d.typ("Bearer HDRSECRET")
	d.wantNot("HDRSECRET")
	d.press("enter")
	d.want("(set, changed)")
	d.wantNot("HDRSECRET", "SEKRET456")
	d.press("y")
	if log := readFile(t, filepath.Join(dataOf(t, root), "audit.log")); strings.Contains(log, "SECRET") || strings.Contains(log, "SEKRET") {
		t.Fatalf("a secret reached the audit log:\n%s", log)
	}
}

func TestSettingsValidationErrorsKeepTheTypedText(t *testing.T) {
	d, root := setStart(t, nil)
	d.toSetting("http.retries")
	d.press("enter", "ctrl+u")
	d.typ("lots")
	d.press("enter")
	d.want("> Retries: lots", "problem: set http.retries: must be a whole number")
	d.press("backspace", "backspace", "backspace", "backspace")
	d.typ("-2")
	d.press("enter")
	d.want("> Retries: -2", "problem:", "http.retries")
	d.press("esc")
	d.wantNot("problem:")
	if got := cfgOf(t, root); got != setCfg {
		t.Fatalf("nothing was written:\n%s", got)
	}
	d.toSetting("http.timeout")
	d.press("enter", "ctrl+u")
	d.typ("soon")
	d.press("enter")
	d.want("> Timeout: soon", "problem:")
}

func TestSettingsUnsetRestoresTheDefault(t *testing.T) {
	d, root := setStart(t, nil)
	d.toSetting("http.timeout")
	d.press("d")
	d.want("Change settings: restore the default of Timeout (30s)", "-   timeout: 30s")
	d.press("y")
	if got := cfgOf(t, root); strings.Contains(got, "timeout") || !strings.Contains(got, "retries: 3") {
		t.Fatalf("file:\n%s", got)
	}
	d.wantLine("Timeout", "30s")
	d.press("d") // nothing set any more
	d.wantNot("Change settings")
	d.toSetting("http.retries")
	d.press("enter", "ctrl+u", "enter") // empty text restores it too
	d.want("restore the default of Retries (3)")
}

func TestSettingsAddAndRemoveRecords(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "root")
	d, root := setStart(t, map[string]string{"config/config.yaml": setCfg + accessCfg, "sources/custom.yaml": setFeeds})

	// a policy rule
	d.toSetting("policy.rules")
	d.press("a")
	d.typ("crit")
	d.press("enter")
	d.typ("72h")
	d.press("enter")
	d.typ("24h")
	d.press("enter")
	d.saveSetting("add crit to Rules")
	d.wantLine("crit", "owner_within=24h", "fix_within=72h")
	d.press("home", "enter")
	d.want("Settings › Policy › crit", "Owner within", "24h")
	d.press("esc")
	d.press("home", "x")
	d.want("Save these settings changes?", "-")
	d.press("y")
	if got := cfgOf(t, root); strings.Contains(got, "crit") {
		t.Fatalf("rule stays:\n%s", got)
	}

	// a feed
	d.toSetting("sources")
	d.press("a")
	d.typ("two")
	d.press("enter")
	d.typ("rss")
	d.press("enter")
	d.typ("https://z.example/f")
	d.press("enter")
	d.saveSetting("add two to Feeds")
	got := fileAt(t, root, "sources/custom.yaml")
	if !strings.Contains(got, "id: two") || !strings.Contains(got, "# the vendor") {
		t.Fatalf("feed:\n%s", got)
	}
	d.wantNot("z.example")
	d.press("home", "down", "x")
	d.press("y")
	if got := fileAt(t, root, "sources/custom.yaml"); strings.Contains(got, "id: two") || !strings.Contains(got, "acme") {
		t.Fatalf("feed removed:\n%s", got)
	}

	// a tech of the catalog
	d.toSetting("techs")
	d.press("a")
	d.typ("zope")
	d.press("enter")
	d.typ("zope, plone")
	d.press("enter", "enter", "enter")
	d.saveSetting("add zope to Technologies")
	if got := fileAt(t, root, "config/techs.yaml"); !strings.Contains(got, "name: zope") || !strings.Contains(got, "plone") {
		t.Fatalf("tech:\n%s", got)
	}

	// an actor
	d.toSetting("access")
	d.press("a")
	d.typ("dave")
	d.press("enter")
	d.typ("shop")
	d.press("enter")
	d.press("enter")
	d.saveSetting("add dave to Access rules")
	if got := cfgOf(t, root); !strings.Contains(got, "dave:") || !strings.Contains(got, "root:") {
		t.Fatalf("actor:\n%s", got)
	}
}

const (
	setBroken = "interval: 4h\nhttp:\n  retries: lots\n  timeout: 30s\nintervall: 5\n"
	setSyntax = "interval: 4h\nhttp: [\n  timeout\n"
)

func lastLine(d *driver) string {
	lines := strings.Split(d.view(), "\n")
	return lines[len(lines)-1]
}

func TestSettingsOpensWithABrokenConfiguration(t *testing.T) {
	noEditor(t)
	d, root := setStart(t, map[string]string{"config/config.yaml": setBroken})
	d.want("[S]ettings (!)", "error config.yaml line 3: http.retries", "error config.yaml line 5: intervall")
	d.wantLine("Core", "1 err")
	d.wantLine("HTTP", "1 err")
	// the other screens show the load error as before
	d.screen("overview")
	d.want("Press r to try again, or q to quit.")
	d.screen("health")
	d.want("Press r to try again, or q to quit.")
	d.screen("settings")
	// a problem goes to its field, or to the section when it names no field
	d.press("end", "enter")
	d.want("Settings › Core", "config.yaml line 5: field intervall", "press E to edit the file")
	d.press("esc", "end", "up", "enter")
	d.want("Settings › HTTP", "> ! Retries", "lots")
	d.want("error config.yaml line 3: http.retries")
	// E says what it cannot do without an editor, then opens the file at the line
	d.press("E")
	d.want("no editor found", "set tui.editor", "the file is")
	a := d.m.(*app)
	id, file, line, why := a.set.editorTarget()
	if why != "" || id != "config" || line != 3 || file != filepath.Join(root, "config", "config.yaml") {
		t.Fatalf("target %q %q %d %q", id, file, line, why)
	}
	if got := editorArgv("vim", file, line); strings.Join(got, " ") != "vim +3 "+file {
		t.Fatalf("argv %v", got)
	}
	useEditorEnv(t, "linux", map[string]string{"EDITOR": "true"})
	before := d.b.(*fake).settings
	cmd := a.openSettingsEditor()
	if cmd == nil {
		t.Fatal("with $EDITOR set the file is opened")
	}
	// the editor comes back with a repaired file
	if err := os.WriteFile(file, []byte("interval: 4h\nhttp:\n  retries: 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.send(opMsg{id: a.pend.ops[0].id, msg: editedMsg{}})
	if d.b.(*fake).settings == before {
		t.Fatal("the settings are read again after the editor")
	}
	d.wantNot("(!)", "lots")
	d.wantLine("Retries", "4")
}

func TestSettingsWithASyntaxErrorShowsItAndKeepsTheFileSafe(t *testing.T) {
	d, root := setStart(t, map[string]string{"config/config.yaml": setSyntax})
	d.want("[S]ettings (!)", "error config.yaml line 1: did not find expected")
	d.press("end", "enter")
	d.want("Settings › Core", "error: config.yaml line 1:", "press E to edit the file")
	d.press("enter")
	d.want("the settings cannot be changed")
	if got := cfgOf(t, root); got != setSyntax {
		t.Fatalf("the broken file is left alone:\n%s", got)
	}
}

func TestSettingsAreClosedToAnActorWhoMaySeeOnlyAFewProjects(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "bob")
	d, root := setStart(t, map[string]string{"config/config.yaml": accessCfg})
	before := treeOf(t, root)
	d.want("Settings are not available to you", "access:")
	d.wantNot("SECTION", "(!)")
	d.press("E")
	d.want("error: the settings are not available to you")
	d.press("enter", "a", "x", "d", " ")
	d.wantNot("Change settings")
	d.screen("projects")
	d.want("PROJECT")
	if !sameTree(before, treeOf(t, root)) {
		t.Fatal("nothing changed")
	}
}

func TestSettingsAreReadOnlyForAnActorWithoutWriteAccess(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "carol")
	d, root := setStart(t, map[string]string{"config/config.yaml": setCfg + accessCfg + "  carol: {projects: ['*']}\n"})
	before := treeOf(t, root)
	d.want("SECTION", "read-only:")
	d.press("down", "enter")
	d.want("Settings › HTTP", "read-only:", "Timeout", "30s")
	d.press("enter")
	d.want("error: the settings cannot be changed: tui:carol may not change the settings")
	d.wantNot("Change settings", "Change User agent")
	d.toSetting("http.timeout")
	d.press("d")
	d.want("error: the settings cannot be changed")
	d.wantNot("Change settings")
	d.press("E")
	d.want("error: the files cannot be changed here")
	d.toSetting("enrich.epss")
	d.press(" ")
	d.want("error: the settings cannot be changed")
	if !sameTree(before, treeOf(t, root)) {
		t.Fatal("nothing changed")
	}
}

func TestSettingsNeverLockTheActorOut(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "root")
	d, root := setStart(t, map[string]string{"config/config.yaml": setCfg + accessCfg})
	before := cfgOf(t, root)
	d.toSetting("access")
	d.press("home") // root, the first rule
	d.wantLine("> ", "root")
	d.press("x")
	d.want("error:", "without write access")
	d.wantNot("Save these settings changes?")
	if cfgOf(t, root) != before {
		t.Fatal("the rules are left alone")
	}
	// another actor can go
	d.press("home", "down", "x")
	d.want("Save these settings changes?", "alice")
	d.press("y")
	if got := cfgOf(t, root); strings.Contains(got, "alice") || !strings.Contains(got, "root:") {
		t.Fatalf("rules:\n%s", got)
	}
}

func TestSettingsAreAuditedByPathNeverByValue(t *testing.T) {
	d, root := setStart(t, map[string]string{"sources/custom.yaml": setFeeds})
	d.edit("http.user_agent", "private-agent-string")
	d.press("y")
	d.toSetting("sources.[id=acme].url")
	d.press("enter")
	d.typ("https://q.example/?t=ZZSECRET")
	d.press("enter", "y")
	log := readFile(t, filepath.Join(dataOf(t, root), "audit.log"))
	if !strings.Contains(log, "edited settings") || !strings.Contains(log, "http.user_agent") || !strings.Contains(log, "tui:") {
		t.Fatalf("audit:\n%s", log)
	}
	if strings.Contains(log, "private-agent-string") || strings.Contains(log, "ZZSECRET") {
		t.Fatalf("values reached the audit log:\n%s", log)
	}
}

func TestSettingsBreadcrumbAndBackKeys(t *testing.T) {
	d, _ := setStart(t, nil)
	if got := crumbOf(d); got != "Settings" {
		t.Fatalf("root %q", got)
	}
	d.press("down", "enter")
	if got := crumbOf(d); got != "Settings › HTTP" {
		t.Fatalf("section %q", got)
	}
	d.toSetting("http.timeout")
	d.press("enter")
	if got := crumbOf(d); got != "Settings › HTTP › timeout" {
		t.Fatalf("prompt %q", got)
	}
	d.press("ctrl+u")
	d.typ("1m")
	d.press("enter")
	if got := crumbOf(d); got != "Settings › HTTP › timeout › review" {
		t.Fatalf("review %q", got)
	}
	d.press("esc") // cancels the change, still in the section
	d.want("cancelled, nothing was saved")
	if got := crumbOf(d); got != "Settings › HTTP" {
		t.Fatalf("after cancel %q", got)
	}
	for _, back := range []string{"left", "backspace", "h", "q", "esc"} {
		d.press(back)
		if got := crumbOf(d); got != "Settings" {
			t.Fatalf("%s: %q", back, got)
		}
		d.press("home", "down", "enter")
		d.want("Settings › HTTP")
	}
	d.press("esc")
	d.toSetting("policy.rules")
	d.press("a")
	d.typ("crit")
	d.press("enter")
	d.typ("72h")
	d.press("enter")
	d.typ("24h")
	d.press("enter", "y")
	d.press("home", "enter")
	if got := crumbOf(d); got != "Settings › Policy › crit" {
		t.Fatalf("record %q", got)
	}
	d.press("esc")
	if got := crumbOf(d); got != "Settings › Policy" {
		t.Fatalf("record back %q", got)
	}
	d.press("home", "enter")
	d.click(len("Settings › ")+1, 1) // the section
	if got := crumbOf(d); got != "Settings › Policy" {
		t.Fatalf("crumb click %q", got)
	}
	d.click(2, 1) // the screen
	if got := crumbOf(d); got != "Settings" {
		t.Fatalf("crumb click %q", got)
	}
}

func TestSettingsMouse(t *testing.T) {
	d, _ := setStart(t, nil)
	a := d.m.(*app)
	row := func(n int) int { return bodyTop + setHead + n }
	d.click(5, row(1))
	if a.set.top.at() != 1 || len(a.set.nav) != 0 {
		t.Fatalf("a click selects: at %d, %d levels", a.set.top.at(), len(a.set.nav))
	}
	d.click(5, row(1))
	d.want("Settings › HTTP")
	d.click(5, row(2)) // Retries
	if a.set.level().vp.at() != 2 || a.set.review != nil || a.prm != nil {
		t.Fatal("a click only selects")
	}
	d.click(5, row(2))
	d.want("> Retries:")
	d.press("esc")
	d.wheel(false, 10, 6)
	if a.set.level().vp.at() != 2+wheelStep(false) {
		t.Fatalf("the wheel moves the selection: %d", a.set.level().vp.at())
	}
	d.wheel(true, 10, 6)
	if a.set.level().vp.at() != 2 {
		t.Fatalf("wheel up: %d", a.set.level().vp.at())
	}
	d.click(5, row(40)) // below the rows: nothing
	d.wantNot("Change settings")
}

func TestSettingsTabsCycleAndJumpByLetter(t *testing.T) {
	d, _ := setStart(t, nil)
	d.want("▸[S]ettings")
	d.press("tab")
	d.want("▸[O]verview")
	d.press("shift+tab")
	d.want("▸[S]ettings")
	d.press("right")
	d.want("▸[O]verview")
	d.press("left")
	d.want("▸[S]ettings")
	for _, k := range []string{"O", "F", "P", "H", "S"} {
		d.press(k)
	}
	d.want("▸[S]ettings")
	d.press("down", "enter", "S")
	d.want("▸[S]ettings") // the level is kept
	d.want("Settings › HTTP")
	d.screen("findings")
	d.screen("settings")
	d.want("Settings › HTTP")
	d.press("?")
	d.want("O F P H S")
}

func TestSettingsFilterAtTheRootAndInASection(t *testing.T) {
	d, _ := setStart(t, nil)
	d.press("/")
	d.want("filter:")
	d.typ("retr")
	d.want("FIELD", "Retries", "Retry delay")
	d.wantNot("Timeout", "SECTION")
	d.press("enter") // keeps it
	d.want("filter: retr")
	d.press("down", "enter")
	d.want("Settings › HTTP")
	d.wantSel("Retry delay")
	d.press("esc") // back one level, the filter is gone
	d.wantNot("filter: retr")
	d.press("home", "down", "enter")
	d.press("/")
	d.typ("429")
	d.want("429 threshold", "429 cooldown")
	d.wantNot("Timeout", "Retries")
	d.press("esc")
	d.want("Timeout")
	d.wantNot("filter:")
	d.press("/")
	d.typ("zzzz")
	d.want("nothing matches")
}

func TestSettingsJumpBoxReachesASetting(t *testing.T) {
	d, _ := setStart(t, nil)
	d.screen("overview")
	d.press(":")
	d.want("Go to an issue or a project, or a setting")
	d.typ("retry delay")
	d.want("Retry delay", "setting HTTP")
	d.press("enter")
	d.want("▸[S]ettings", "Settings › HTTP")
	d.wantSel("Retry delay")
	d.press("esc")
	d.want("▸[O]verview")
	d.press("ctrl+g")
	d.typ("http.max_body")
	d.press("enter")
	d.wantSel("Max body")
	d.press("left")
	d.want("▸[O]verview")
	// a jump from inside Settings comes back to the place it started at
	d.screen("settings")
	d.press("esc", "ctrl+g")
	d.typ("slack.min_severity")
	d.press("enter")
	d.want("Settings › Notify")
	d.wantSel("Slack minimum severity")
}

func TestSettingsOnSmallTerminals(t *testing.T) {
	d, _ := setStart(t, map[string]string{"sources/custom.yaml": setFeeds})
	for _, size := range [][2]int{{30, 8}, {40, 12}, {60, 14}, {80, 24}, {120, 40}} {
		d.send(tea_window(size[0], size[1]))
		steps := [][]string{{"down", "enter"}, {"enter"}, {"esc", "/"}, {"x", "esc"}, {"esc", "end", "enter"}, {"enter"}, {"esc", "esc", "esc"}, {"enter"}, {"d", "esc"}, {"E"}, {"esc", "esc"}, {"?"}, {"?"}}
		for _, keys := range steps {
			d.press(keys...)
			lines := strings.Split(d.view(), "\n")
			if len(lines) > size[1] {
				t.Fatalf("%dx%d: %d lines after %v:\n%s", size[0], size[1], len(lines), keys, d.view())
			}
			for _, l := range lines {
				if width(l) > size[0] {
					t.Fatalf("%dx%d: a line is %d cells after %v: %q", size[0], size[1], width(l), keys, l)
				}
			}
		}
		d.press("esc", "esc", "esc", "esc")
		d.toSetting("sources.[id=acme].url")
		d.press("enter")
		d.typ("https://q.example/")
		d.press("enter")
		for _, l := range strings.Split(d.view(), "\n") {
			if width(l) > size[0] {
				t.Fatalf("%dx%d: review line is %d cells: %q", size[0], size[1], width(l), l)
			}
		}
		d.press("esc", "esc", "esc", "esc")
	}
}

func TestSettingsFootersFitAndEveryStateHasHelp(t *testing.T) {
	d, _ := setStart(t, map[string]string{"sources/custom.yaml": setFeeds})
	d.send(tea_window(80, 24))
	check := func(label, want string) {
		t.Helper()
		foot := lastLine(d)
		if width(foot) > 80 {
			t.Errorf("%s: footer is %d cells: %q", label, width(foot), foot)
		}
		if !strings.Contains(foot, want) {
			t.Errorf("%s: footer lacks %q: %q", label, want, foot)
		}
	}
	check("sections", "enter open")
	d.press("down", "enter")
	check("fields", "enter edit")
	d.toSetting("http.timeout")
	check("a set field", "d default")
	d.press("enter")
	check("prompt", "enter confirm")
	d.press("ctrl+u")
	d.typ("1m")
	d.press("enter")
	check("review", "enter/y save")
	d.press("?")
	d.want("Keys in the preview of a settings change", "save the change to the settings files")
	d.press("?", "esc")
	d.toSetting("slack.min_severity")
	d.press("enter")
	check("picker", "enter choose")
	d.press("esc")
	d.press("/")
	check("filter", "f1 help")
	d.press("?")
	d.press("f1")
	d.want("Keys while typing a filter of the settings")
	d.press("f1", "esc")
	d.toSetting("sources")
	check("items", "a add")
	d.press("?")
	d.want("Keys in a section of the settings", "remove the selected item", "restore the default")
	d.press("?")
	d.press("home", "?")
	d.press("?")
	for _, md := range []*mode{mo.settings, mo.setFields, mo.setFilter, mo.setReview} {
		h := strings.Join(helpLines(md, 80), "\n")
		if !strings.Contains(h, md.title) || !strings.Contains(h, "Everywhere") && md.name != "settings filter" && md.name != "settings review" {
			t.Errorf("%s: help lacks its heading", md.name)
		}
	}
}

func TestScreenTableDrivesTheTabsAndKeys(t *testing.T) {
	d, _ := setStart(t, nil)
	seen := map[string]bool{}
	for i, sc := range screens {
		if sc.name == "" || sc.key == "" || seen[sc.key] {
			t.Errorf("screen %d: name %q key %q", i, sc.name, sc.key)
		}
		seen[sc.key] = true
		if sc.modes == nil || sc.body == nil || sc.layout == nil {
			t.Errorf("%s lacks its behaviour", sc.name)
		}
		d.press(sc.key)
		if !strings.HasPrefix(strings.ToUpper(sc.name), sc.key) {
			t.Errorf("%s: the key %s is not its first letter", sc.name, sc.key)
		}
		d.want("▸[" + sc.key + "]" + sc.name[1:])
		if got := crumbOf(d); !strings.HasPrefix(got, sc.name) {
			t.Errorf("%s: crumb %q", sc.name, got)
		}
	}
	if len(seen) != int(numScreens) {
		t.Fatalf("%d keys for %d screens", len(seen), numScreens)
	}
}
