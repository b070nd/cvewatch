package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// bg runs the commands of a model the way Bubble Tea does, each on its own
// goroutine, so that a test can look at the screen while a fetch is running.
type bg struct {
	d   *driver
	out chan tea.Msg
}

func newBG(d *driver) *bg { return &bg{d: d, out: make(chan tea.Msg, 64)} }

func (g *bg) spawn(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	go func() {
		switch msg := cmd().(type) {
		case nil:
		case tea.BatchMsg:
			for _, c := range msg {
				g.spawn(c)
			}
		default:
			g.out <- msg
		}
	}()
}

// press sends keys and starts what they ask for.
func (g *bg) press(keys ...string) {
	for _, k := range keys {
		g.send(key(k))
	}
}

func (g *bg) screen(name string) { g.d.t.Helper(); g.press(screenKey(g.d.t, name)) }

func (g *bg) send(msg tea.Msg) {
	var cmd tea.Cmd
	g.d.m, cmd = g.d.m.Update(msg)
	g.spawn(cmd)
}

// until feeds the model what its commands return until ok is true.
func (g *bg) until(what string, ok func() bool) {
	g.d.t.Helper()
	deadline := time.After(10 * time.Second)
	for !ok() {
		select {
		case msg := <-g.out:
			g.send(msg)
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			g.d.t.Fatalf("timed out waiting for %s:\n%s", what, g.d.view())
		}
	}
}

func (g *bg) untilView(part string) {
	g.d.t.Helper()
	g.until(part, func() bool { return strings.Contains(g.d.view(), part) })
}

// quiet drains what is left, so that a test ends with nothing running.
func (g *bg) quiet() {
	for {
		select {
		case msg := <-g.out:
			g.send(msg)
		case <-time.After(100 * time.Millisecond):
			return
		}
	}
}

func noThrottle(t *testing.T) {
	t.Helper()
	old := fetchThrottle
	fetchThrottle = 0
	t.Cleanup(func() { fetchThrottle = old })
}

func (f *fake) fetched() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func (f *fake) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func TestFetchShowsProgressInTheHeaderAndClearsIt(t *testing.T) {
	noThrottle(t)
	b := newFake(t, nil)
	step := make(chan struct{})
	b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		progress(pipeline.Progress{Phase: pipeline.PhaseFetch, Total: 3})
		<-step
		progress(pipeline.Progress{Phase: pipeline.PhaseFetch, Total: 3, Done: 1, Source: "a"})
		progress(pipeline.Progress{Phase: pipeline.PhaseFetch, Total: 3, Done: 2, Source: "b", Failed: true})
		<-step
		progress(pipeline.Progress{Phase: pipeline.PhaseSave})
		<-step
		progress(pipeline.Progress{Phase: pipeline.PhaseAlert})
		<-step
		return pipeline.Result{New: 4, Findings: 2, Failed: []string{"b: timeout"}}, nil
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	g.untilView("fetch 0/3")
	d.wantNot("error")
	reads := b.readCount()
	step <- struct{}{}
	g.untilView("fetch 2/3")
	d.screen("findings") // the screens keep working while it runs
	d.want("▸[F]indings")
	step <- struct{}{}
	g.untilView("saving")
	step <- struct{}{}
	g.untilView("alerting")
	step <- struct{}{}
	g.until("the end of the fetch", func() bool { return strings.Contains(d.view(), "fetched: 4 new, 2 findings, 1 source failed") })
	g.quiet()
	d.wantNot("alerting", "fetch 2/3")
	d.want("1 source failed")
	if got := b.readCount(); got <= reads {
		t.Errorf("the snapshot was not read again after the fetch: %d reads before, %d after", reads, got)
	}
}

func TestFetchFailedSourcesAreShownOnClick(t *testing.T) {
	b := newFake(t, nil)
	b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{Failed: []string{"hn: connection refused", "nvd: 500"}}, nil
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	g.untilView("fetched: 0 new, 0 findings, 2 sources failed")
	g.quiet()
	head := strings.Split(d.view(), "\n")[0]
	i := strings.Index(head, "2 sources failed")
	if i < 0 {
		t.Fatalf("no progress cell in the header: %q", head)
	}
	d.click(width(head[:i])+1, 0)
	d.want("Sources that failed", "hn: connection refused", "nvd: 500")
	d.press("enter")
	d.wantNot("2 sources failed") // looked at, so the cell goes
	d.click(1, 0)                 // a click elsewhere on the header does not open it again
	d.wantNot("Sources that failed")
}

func TestFetchHardErrorIsStickyAndBusyIsNeutral(t *testing.T) {
	b := newFake(t, nil)
	b.cfg.TUI.Fetch = time.Hour
	var err error
	b.fetchFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, err
	}
	d := start(t, b, Options{})
	g := newBG(d)

	err = fmt.Errorf("opening the store: %w", ErrBusy)
	g.send(tuiMsg{set: b.cfg.TUI})
	g.press("u")
	g.untilView("another cvewatch")
	g.quiet()
	d.wantNot("error")
	d.want("will retry in 1h")
	if d.app().fet.job != nil || d.app().fet.cell() != "" {
		t.Error("a busy store left the progress cell")
	}
	if d.app().flashErr {
		t.Error("busy is not an error")
	}

	err = errors.New("disk full")
	g.press("u")
	g.untilView("error: fetch failed: disk full")
	g.quiet()
	d.press("down") // moving around keeps the error
	d.want("fetch failed: disk full")
}

func TestFetchBusyWithoutAPeriodSaysHowToRetry(t *testing.T) {
	b := newFake(t, nil)
	b.fetchFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, ErrBusy
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	g.untilView("press u to try again")
	g.quiet()
}

func TestFetchNeverRunsTwiceAtOnce(t *testing.T) {
	b := newFake(t, nil)
	release := make(chan struct{})
	b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		<-release
		return pipeline.Result{}, nil
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	g.until("the fetch", func() bool { return b.fetched() == 1 })
	g.press("u")
	d.want("already running")
	g.send(fetchDueMsg{}) // the timer finding one running does not start another either
	g.press("u")
	time.Sleep(50 * time.Millisecond)
	if n := b.fetched(); n != 1 {
		t.Fatalf("%d fetches started, want 1", n)
	}
	close(release)
	g.until("the end", func() bool { return d.app().fet.job == nil })
	g.press("u") // free again
	g.until("the second fetch", func() bool { return b.fetched() == 2 })
	g.quiet()
}

func TestQuitCancelsTheFetch(t *testing.T) {
	b := newFake(t, nil)
	started := make(chan struct{})
	ended := make(chan error, 1)
	b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		close(started)
		<-ctx.Done()
		ended <- ctx.Err()
		return pipeline.Result{}, ctx.Err()
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	<-started
	g.press("q")
	if d.app().ctx.Err() == nil {
		t.Error("quitting left the context of the fetch open")
	}
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("fetch ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fetch was not cancelled")
	}
	g.quiet()
	d.wantNot("fetch failed")
	d.app().waitFetch(time.Second)
}

func TestCtrlCCancelsTheFetchAndAFetchAfterQuitDoesNotStart(t *testing.T) {
	b := newFake(t, nil)
	b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		<-ctx.Done()
		return pipeline.Result{}, ctx.Err()
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	g.until("the fetch", func() bool { return b.fetched() == 1 })
	g.press("ctrl+c")
	g.until("the end", func() bool { return d.app().fet.job == nil })
	g.press("u")
	g.quiet()
	if n := b.fetched(); n != 1 {
		t.Errorf("a fetch started after quitting: %d", n)
	}
}

func TestFetchStartsWithTheProgramAndRepeatsEveryPeriod(t *testing.T) {
	b := newFake(t, nil)
	b.cfg.TUI.Fetch = time.Hour
	b.fetchFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{New: 1}, nil
	}
	d := start(t, b, Options{Fetch: time.Hour})
	g := newBG(d)
	g.spawn(d.m.Init())
	g.until("the first fetch", func() bool { return b.fetched() == 1 && d.app().fet.job == nil })
	if !hasTimer(d, fetchDueMsg{}) {
		t.Fatal("no timer for the next fetch")
	}
	d.timers = nil
	g.send(fetchDueMsg{})
	g.until("the second fetch", func() bool { return b.fetched() == 2 && d.app().fet.job == nil })
	if !hasTimer(d, fetchDueMsg{}) {
		t.Error("the timer was not set again")
	}
	g.quiet()
}

func TestFetchDoesNotStartByItselfWhenThePeriodIsZero(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	g := newBG(d)
	g.spawn(d.m.Init())
	g.quiet()
	if n := b.fetched(); n != 0 {
		t.Fatalf("%d fetches without a period", n)
	}
	if hasTimer(d, fetchDueMsg{}) {
		t.Error("a timer is set though the period is 0")
	}
	g.send(fetchDueMsg{})
	g.quiet()
	if n := b.fetched(); n != 0 {
		t.Errorf("the timer fetched with a period of 0: %d", n)
	}
	// a period set in the Settings screen starts the timer when it is read
	g.send(tuiMsg{set: config.TUI{Refresh: 5 * time.Second, Fetch: time.Minute}})
	if !hasTimer(d, fetchDueMsg{}) {
		t.Error("a new period did not set the timer")
	}
	g.press("u")
	g.until("the manual fetch", func() bool { return b.fetched() == 1 })
	g.quiet()
}

func hasTimer(d *driver, want tea.Msg) bool {
	for _, m := range d.timers {
		if m == want {
			return true
		}
	}
	return false
}

func TestRefreshPeriodComesFromTheSettings(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	g := newBG(d)
	if got := d.app().refreshEvery(); got != time.Hour {
		t.Fatalf("the option gives %v", got)
	}
	b.cfg.TUI = config.TUI{Refresh: 7 * time.Second}
	g.press("r")
	g.until("the setting", func() bool { return d.app().refreshEvery() == 7*time.Second })
	b.cfg.TUI = config.TUI{} // an unreadable file gives nothing: the period stays
	g.press("r")
	g.quiet()
	if got := d.app().refreshEvery(); got != 7*time.Second {
		t.Errorf("an empty setting changed the period to %v", got)
	}
	if got := (&app{}).refreshEvery(); got != 30*time.Second {
		t.Errorf("default period %v", got)
	}
}

func TestTickReadsAgainAndKeepsTicking(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.app().tui.Refresh = 10 * time.Millisecond
	reads := b.readCount()
	_, cmd := d.m.Update(tickMsg{})
	d.app().tui.Refresh = time.Hour // so that the tick that comes is the last one
	g := newBG(d)
	g.spawn(cmd)
	ticked := false
	for !ticked || b.readCount() == reads {
		select {
		case msg := <-g.out:
			_, ticked = msg.(tickMsg)
			if !ticked {
				g.send(msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no tick again (ticked %v, reads %d to %d)", ticked, reads, b.readCount())
		}
	}
}

func TestFetchKeyIsOnEveryMainScreenAndInTheHelp(t *testing.T) {
	for _, screen := range []string{"O", "F", "P", "H", "S"} {
		b := newFake(t, nil)
		b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
			return pipeline.Result{}, nil
		}
		d := start(t, b, Options{})
		g := newBG(d)
		g.press(screen, "u")
		g.until("the fetch from screen "+screen, func() bool { return b.fetched() == 1 })
		g.quiet()
		g.press("?")
		d.want("fetch the feeds in the background")
		g.press("esc")
	}
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.send(tea_window(200, 40))
	d.want("u update")
}

func TestFetchCellFitsANarrowHeader(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.send(tea_window(40, 20))
	d.app().fet.job = newFetchJob(func() {})
	d.app().fet.prog = pipeline.Progress{Phase: pipeline.PhaseFetch, Total: 12, Done: 3}
	head := strings.Split(d.view(), "\n")[0]
	if width(head) > 40 {
		t.Errorf("header is %d cells: %q", width(head), head)
	}
	d.app().fet.job = nil
}

func TestProgressReportsNeverBlockAndAreThrottled(t *testing.T) {
	j := newFetchJob(func() {})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100000; i++ {
			j.report(pipeline.Progress{Phase: pipeline.PhaseFetch, Done: i, Total: 100000})
		}
		j.report(pipeline.Progress{Phase: pipeline.PhaseSave})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("report blocked with nobody reading")
	}
	wakes := len(j.sig)
	if wakes != 1 {
		t.Errorf("%d wake-ups waiting, want 1", wakes)
	}
	if p, _ := j.snapshot(); p.Phase != pipeline.PhaseSave {
		t.Errorf("the latest step is %v", p)
	}
	// within one phase the interface hears of at most a few steps a second
	j = newFetchJob(func() {})
	woke := 0
	for i := 0; i < 1000; i++ {
		j.report(pipeline.Progress{Phase: pipeline.PhaseFetch, Done: i, Total: 1000})
		select {
		case <-j.sig:
			woke++
		default:
		}
	}
	if woke > 2 {
		t.Errorf("%d wake-ups in one burst", woke)
	}
}

func TestSettingsNoteForTheTUIPeriods(t *testing.T) {
	rv := &setReview{edits: []confdoc.Edit{{Path: "tui.refresh"}, {Path: "tui.fetch"}}}
	if !rv.tuiOnly() || !strings.Contains(rv.note("4h"), "next re-read") {
		t.Errorf("tui settings: %q", rv.note("4h"))
	}
	rv.edits = append(rv.edits, confdoc.Edit{Path: "interval"})
	if rv.tuiOnly() || !strings.Contains(rv.note("4h"), "daemon cycle") {
		t.Errorf("mixed settings: %q", rv.note("4h"))
	}
}

func TestSavingATUIPeriodSaysItAppliesOnTheNextReRead(t *testing.T) {
	d, root := setStart(t, nil)
	d.edit("tui.refresh", "20s")
	d.want("Change settings: set TUI refresh to 20s", "Changes apply on the next re-read of the interface.")
	d.press("y")
	d.want("saved: set TUI refresh to 20s", "applies on the next re-read")
	if !strings.Contains(cfgOf(t, root), "20s") {
		t.Errorf("not saved:\n%s", cfgOf(t, root))
	}
	if got := d.app().refreshEvery(); got != 20*time.Second {
		t.Errorf("the saved period was not picked up: %v", got)
	}
}
