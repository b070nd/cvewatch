package tui

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// richIssue adds to CVE-2026-1 what a feed and a team leave on a real one:
// an advisory and a fix link, KEV and EPSS, affected ranges, installed
// versions and a piece of evidence with a link.
func richIssue(l *ledger.Ledger) {
	v := l.Vuln("CVE-2026-1")
	v.Refs = append(v.Refs,
		model.Ref{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test/CVE-2026-1", Title: "NVD entry"},
		model.Ref{Source: "evil", Kind: model.RefArticle, URL: "https://evil.test/x", Title: "red \x1b]52;c;AAAA\x07 team"},
	)
	v.Fixes[0].URL = "https://fix.test/8.2.9"
	v.ReportPath = filepath.Join("alerts", "2026", "2026-10-01-php-cve-2026-1.md")
	v.KEV = &model.KEV{DateAdded: t0.Add(24 * time.Hour), DueDate: t0.Add(96 * time.Hour), Ransomware: true, Action: "Apply updates."}
	v.EPSS = &model.EPSS{Score: 0.5, Percentile: 0.97}
	v.Affected = []model.Affected{{Ecosystem: "composer", Name: "example/framework", Ranges: []model.Range{{Min: "8.0", Max: "8.2.30", MaxExcl: true}}, Fixed: "8.2.30"}}
	l.Mutate("CVE-2026-1|shop|prod", func(f *model.Finding) {
		f.Installed = []model.Installed{{Name: "php", Version: "8.2.10", Via: "tech"}}
		f.Evidence = []model.Evidence{{Time: t0, Actor: "bob", Note: "deployed in release 42", URL: "https://ci.test/run/42"}}
	})
}

// richDriver opens CVE-2026-1 on a wide terminal with a fake desktop.
func richDriver(t *testing.T) (*driver, *fakeDesktop, *fake) {
	t.Helper()
	b := newFake(t, seed(t, richIssue))
	d := start(t, b, Options{})
	d.send(tea_window(150, 70))
	fd := d.app().sys.(*fakeDesktop)
	d.screen("findings")
	d.press("enter") // KEV puts it first
	return d, fd, b
}

func TestDetailShowsKEVEPSSInstalledAffectedAndReferences(t *testing.T) {
	d, _, _ := richDriver(t)
	d.want(
		"exploitation: on the CISA KEV list since 2026-10-02, CISA remediation due 2026-10-05, known ransomware use; EPSS 50% (percentile 97)",
		"priority: known exploited (CISA KEV), CISA remediation due 2026-10-05; high severity; open in prod",
		"installed: php@8.2.10",
		"Affected versions", "composer example/framework: >=8.0, <8.2.30 (first fixed 8.2.30)",
		"References", "1. advisory  nvd  NVD entry", "https://nvd.test/CVE-2026-1",
		"2. fix", "https://fix.test/8.2.9", "3. article", "5. evidence",
		"report file: alerts"+string(filepath.Separator)+"2026", "Evidence", "shop/prod 2026-10-01 bob: deployed in release 42", "https://ci.test/run/42",
		"History", "first seen by cvewatch")
	if raw := d.m.View(); strings.Contains(raw, "\x07") || strings.Contains(raw, "\x1b]") {
		t.Fatal("a feed title carried a terminal escape sequence to the screen")
	}
}

func TestSelectingALinkOpensAndCopiesIt(t *testing.T) {
	d, fd, _ := richDriver(t)
	d.press("enter") // nothing is selected yet
	d.press("c")
	if len(fd.opened)+len(fd.copied) != 0 {
		t.Fatalf("no link was selected: %v %v", fd.opened, fd.copied)
	}
	d.press("l")
	d.want(">  1. advisory")
	if got := crumbOf(d); got != "Findings › CVE-2026-1 › mw:prod › References 1/5" {
		t.Errorf("breadcrumb %q", got)
	}
	d.press("enter")
	if !reflect.DeepEqual(fd.opened, []string{"https://nvd.test/CVE-2026-1"}) {
		t.Fatalf("opened %v", fd.opened)
	}
	d.want("ok: opened https://nvd.test/CVE-2026-1 in the browser")
	d.press("l", "c")
	if !reflect.DeepEqual(fd.copied, []string{"https://fix.test/8.2.9"}) {
		t.Fatalf("copied %v", fd.copied)
	}
	d.want("ok: copied https://fix.test/8.2.9 to the clipboard (faketool)")
	d.press("L", "L") // back to the first, then around to the last
	if got := crumbOf(d); !strings.HasSuffix(got, "References 5/5") {
		t.Errorf("L wraps around: %q", got)
	}
	d.press("l")
	if got := crumbOf(d); !strings.HasSuffix(got, "References 1/5") {
		t.Errorf("l wraps around: %q", got)
	}
}

func TestLinkSelectionScrollsThePageToTheLink(t *testing.T) {
	d, _, _ := richDriver(t)
	d.send(tea_window(100, 14))
	d.want("CVE-2026-1  high")
	d.press("L")
	d.want("5. evidence", "https://ci.test/run/42")
	d.wantNot("exploitation:")
	d.press("l")
	d.want("1. advisory", "https://nvd.test/CVE-2026-1")
	d.wantNot("Fix evidence")
}

func TestEscUnselectsTheLinkBeforeLeavingThePage(t *testing.T) {
	d, _, _ := richDriver(t)
	d.press("l")
	d.press("esc")
	d.want("Findings › CVE-2026-1 › mw:prod")
	d.wantNot("References 1/5")
	d.want("Tracked PHP bug")
	d.press("esc")
	d.want("3 of 3 open issues")
}

func TestCopyWithoutAClipboardToolShowsTheLink(t *testing.T) {
	d, fd, _ := richDriver(t)
	fd.copyErr = errNoClipboard
	d.press("l", "c")
	d.want("ok: no clipboard tool here; the link is https://nvd.test/CVE-2026-1")
	fd.copyErr = errors.New("exit status 1")
	d.press("c")
	d.want("error: could not copy the link (exit status 1); it is https://nvd.test/CVE-2026-1")
}

func TestOpenFailureIsReported(t *testing.T) {
	d, fd, _ := richDriver(t)
	fd.openErr = errors.New("xdg-open is not installed")
	d.press("l", "enter")
	d.want("error: xdg-open is not installed")
}

func TestClickingALinkSelectsItAndASecondClickOpensIt(t *testing.T) {
	d, fd, _ := richDriver(t)
	y := -1
	for i, l := range strings.Split(d.view(), "\n") {
		if strings.Contains(l, "2. fix") {
			y = i
		}
	}
	if y < 0 {
		t.Fatal("no link line")
	}
	d.click(8, y)
	if got := crumbOf(d); !strings.HasSuffix(got, "References 2/5") || len(fd.opened) != 0 {
		t.Fatalf("first click selects: %q %v", got, fd.opened)
	}
	d.click(8, y+1) // the address line belongs to the same link
	if !reflect.DeepEqual(fd.opened, []string{"https://fix.test/8.2.9"}) {
		t.Fatalf("second click opens: %v", fd.opened)
	}
}

func TestEvidencePackViewIsInTheFrameAndScrolls(t *testing.T) {
	d, _, _ := richDriver(t)
	d.send(tea_window(80, 14))
	d.press("v")
	d.want("# Evidence pack: CVE-2026-1")
	if got := crumbOf(d); got != "Findings › CVE-2026-1 › mw:prod › evidence pack" {
		t.Errorf("breadcrumb %q", got)
	}
	d.want("cvewatch", "up/down scroll", "esc, left back")
	d.press("pgdown")
	d.wantNot("# Evidence pack: CVE-2026-1")
	d.press("G")
	d.wantNot("| Field | Value |")
	d.press("home")
	d.want("# Evidence pack: CVE-2026-1")
	d.press("esc")
	d.want("Tracked PHP bug")
	if got := crumbOf(d); got != "Findings › CVE-2026-1 › mw:prod" {
		t.Errorf("back on the page: %q", got)
	}
	d.press("esc")
	d.want("3 of 3 open issues")
}

func TestEvidencePackErrorGoesBackToThePage(t *testing.T) {
	d, _, _ := richDriver(t)
	cmd := d.hold(key("v")) // the read is still in flight
	if d.app().fnd.det.doc == nil || !d.app().fnd.det.doc.loading {
		t.Fatal("the view opens at once and says it is loading")
	}
	d.want("Loading the evidence pack...")
	d.send(opMsg{id: d.app().pend.ops[0].id, msg: evidenceMsg{id: "CVE-2026-1", err: errors.New("boom")}})
	if d.app().fnd.det.doc != nil {
		t.Fatal("a failed read closes the view")
	}
	d.want("error: evidence pack: boom")
	d.finish(cmd)
}

func TestReportViewShowsTheMarkdownInTheFrame(t *testing.T) {
	d, _, _ := richDriver(t)
	d.send(tea_window(60, 16))
	d.press("R")
	d.want("# CVE-2026-1")
	if got := crumbOf(d); got != "Findings › CVE-2026-1 › mw:prod › report" {
		t.Errorf("breadcrumb %q", got)
	}
	d.press("G")
	d.want("cvewatch fix CVE-2026-1")
	d.press("g", "pgdown")
	d.wantNot("# CVE-2026-1 —")
	d.press("esc")
	d.want("Tracked PHP bug")
	d.press("R", "left")
	d.want("Tracked PHP bug")
	d.press("R", "h")
	d.want("Tracked PHP bug")
	d.press("R", "q")
	d.want("Tracked PHP bug")
}

func TestReportViewFollowsARefreshAndKeepsItsPlace(t *testing.T) {
	d, _, _ := richDriver(t)
	d.send(tea_window(60, 16))
	d.press("R", "pgdown")
	at := d.app().fnd.det.doc.vp.at()
	d.press("r")
	if d.app().fnd.det.doc == nil || d.app().fnd.det.doc.vp.at() != at {
		t.Fatal("a refresh must not close or rewind the report")
	}
}

func TestBreadcrumbInTheViewsCanBeClicked(t *testing.T) {
	d, _, _ := richDriver(t)
	d.press("v")
	d.click(len("Findings › "), 1) // the issue id
	d.want("Tracked PHP bug")
	d.wantNot("Evidence pack: CVE-2026-1")
	d.press("R")
	d.click(2, 1) // Findings
	d.want("3 of 3 open issues")
}

func TestAddEvidencePromptAttachesAndKeepsTextOnRefusal(t *testing.T) {
	d, _, b := richDriver(t)
	d.press("down", "+") // shop/prod
	d.want("Add evidence to CVE-2026-1 in shop/prod", "Note", "Link")
	d.press("enter", "enter") // both empty
	d.want("problem: evidence needs a note or a link")
	d.press("shift+tab")
	d.typ("rolled out")
	d.press("enter")
	d.typ("ftp://files.test/x")
	d.press("enter")
	d.want("problem: the evidence link must be a plain http(s) URL", "rolled out", "ftp://files.test/x")
	if d.app().prm == nil {
		t.Fatal("the prompt must stay open")
	}
	d.press("ctrl+u")
	d.typ("https://ci.test/run/43")
	d.press("enter")
	if d.app().prm != nil {
		t.Fatalf("saved, so the prompt closes: %+v", d.app().prm)
	}
	d.want("ok: evidence added to CVE-2026-1 in shop/prod (1 finding)", "rolled out", "https://ci.test/run/43", "shop/prod evidence: rolled out (by "+actor()+")")
	var got []model.Evidence
	b.Read(func(s *ops.Session) error {
		got = s.Ledger.FindingsOf("CVE-2026-1")[1].Evidence
		return nil
	})
	if len(got) != 2 || got[1].Note != "rolled out" || got[1].URL != "https://ci.test/run/43" || got[1].Actor != actor() {
		t.Fatalf("evidence in the ledger: %+v", got)
	}
}

func TestAddEvidenceEscCancelsWithoutWriting(t *testing.T) {
	d, _, b := richDriver(t)
	d.press("+")
	d.typ("never saved")
	d.press("esc")
	if d.app().prm != nil || b.writes != 0 {
		t.Fatalf("prompt %v, writes %d", d.app().prm, b.writes)
	}
	d.want("Findings › CVE-2026-1 › mw:prod")
}

func TestDetailKeysAreInTheFooterAndTheHelp(t *testing.T) {
	d, _, _ := richDriver(t)
	foot := func() string { lines := strings.Split(d.view(), "\n"); return lines[len(lines)-1] }
	if f := foot(); !strings.Contains(f, "add evidence") || !strings.Contains(f, "links") || strings.Contains(f, "open link") {
		t.Errorf("footer without a link: %q", f)
	}
	d.press("l")
	if f := foot(); !strings.Contains(f, "open link") || !strings.Contains(f, "copy link") {
		t.Errorf("footer with a link: %q", f)
	}
	d.press("?")
	d.want("Keys in an issue", "open the selected link in the browser", "copy the selected link to the clipboard",
		"show the evidence pack", "show the full report", "add evidence (a note, a link or both)", "select the next or previous link")
	d.press("esc", "v")
	d.press("?")
	d.want("Keys in the report and the evidence pack")
}

func TestDetailPagesFitNarrowAndTinyTerminals(t *testing.T) {
	for _, sz := range [][2]int{{30, 8}, {32, 10}, {40, 12}, {60, 20}} {
		w, h := sz[0], sz[1]
		d, _, _ := richDriver(t)
		d.send(tea_window(w, h))
		fits := func(label string) {
			t.Helper()
			v := d.view()
			lines := strings.Split(v, "\n")
			if len(lines) > h {
				t.Errorf("%dx%d %s: %d lines", w, h, label, len(lines))
			}
			for _, l := range lines {
				if width(l) > w {
					t.Errorf("%dx%d %s: a line is %d cells: %q", w, h, label, width(l), l)
				}
			}
		}
		fits("page")
		d.press("l", "L", "L")
		fits("link selected")
		for _, k := range []string{"G", "pgup", "home"} {
			d.press(k)
			fits("scrolled " + k)
		}
		d.press("esc", "esc", "v")
		fits("evidence pack")
		d.press("G", "esc", "R")
		fits("report")
		d.press("G")
		fits("report end")
		d.press("esc", "+")
		fits("prompt")
	}
}

func TestOpenAndCopyArgvPerSystem(t *testing.T) {
	const u = "https://a.test/x?a=1&b=2"
	for goos, want := range map[string][]string{
		"darwin":  {"open", u},
		"linux":   {"xdg-open", u},
		"freebsd": {"xdg-open", u},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", u},
	} {
		if got := openArgv(goos, u); !reflect.DeepEqual(got, want) {
			t.Errorf("open on %s: %v, want %v", goos, got, want)
		}
	}
	have := func(names ...string) func(string) bool {
		return func(n string) bool {
			for _, x := range names {
				if x == n {
					return true
				}
			}
			return false
		}
	}
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	for _, c := range []struct {
		name string
		goos string
		have func(string) bool
		env  func(string) string
		want []string
	}{
		{"mac", "darwin", have(), env(), []string{"pbcopy"}},
		{"windows", "windows", have(), env(), []string{"clip"}},
		{"wayland", "linux", have("wl-copy", "xclip"), env("WAYLAND_DISPLAY", "wayland-0"), []string{"wl-copy"}},
		{"x11", "linux", have("wl-copy", "xclip"), env(), []string{"xclip", "-selection", "clipboard"}},
		{"xsel", "linux", have("xsel"), env(), []string{"xsel", "--clipboard", "--input"}},
		{"wl-copy without a wayland session", "linux", have("wl-copy"), env(), []string{"wl-copy"}},
		{"wsl", "linux", have("clip.exe"), env(), []string{"clip.exe"}},
		{"nothing", "linux", have(), env(), nil},
	} {
		if got := clipboardArgv(c.goos, c.have, c.env); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSysDesktopRunsTheChosenCommands(t *testing.T) {
	var started [][]string
	var piped [][]string
	var stdin []string
	s := &sysDesktop{
		goos: "linux", have: func(n string) bool { return n == "xdg-open" || n == "xclip" }, env: func(string) string { return "" },
		start: func(argv []string) error { started = append(started, argv); return nil },
		pipe: func(argv []string, in string) error {
			piped = append(piped, argv)
			stdin = append(stdin, in)
			return nil
		},
	}
	if err := s.Open("https://a.test/"); err != nil || !reflect.DeepEqual(started, [][]string{{"xdg-open", "https://a.test/"}}) {
		t.Fatalf("open: %v %v", started, err)
	}
	tool, err := s.Copy("https://a.test/")
	if err != nil || tool != "xclip" || !reflect.DeepEqual(piped, [][]string{{"xclip", "-selection", "clipboard"}}) || stdin[0] != "https://a.test/" {
		t.Fatalf("copy: %q %v %v %v", tool, piped, stdin, err)
	}
	s.have = func(string) bool { return false }
	if err := s.Open("https://a.test/"); err == nil || !strings.Contains(err.Error(), "xdg-open is not installed") {
		t.Fatalf("a missing launcher must say so: %v", err)
	}
	if _, err := s.Copy("x"); !errors.Is(err, errNoClipboard) {
		t.Fatalf("no tool: %v", err)
	}
	s.have = func(string) bool { return true }
	s.pipe = func([]string, string) error { return errors.New("exit status 1") }
	if _, err := s.Copy("x"); err == nil || errors.Is(err, errNoClipboard) || !strings.Contains(err.Error(), "xclip") {
		t.Fatalf("a failing tool is not a missing one: %v", err)
	}
}

func TestWrapDocKeepsIndentationAndCleansText(t *testing.T) {
	got := wrapDoc("# Title\n\n  - item one two three four five\n\x1b[31mred\x1b[0m\t|x", 14)
	want := []string{"# Title", "", "  - item one", "    two three", "    four five", "red |x"}
	// the heading is bold, which is not drawn without a terminal
	if plain := ansi.ReplaceAllString(strings.Join(got, "\n"), ""); plain != strings.Join(want, "\n") {
		t.Fatalf("wrapped:\n%s\nwant:\n%s", plain, strings.Join(want, "\n"))
	}
}
