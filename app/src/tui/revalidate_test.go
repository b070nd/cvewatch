package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/store"
)

var sinceDay = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

// outOfDate changes what the shop is judged by after the fake was marked judged.
func outOfDate(b *fake) { b.cfg.Projects[0].Since = sinceDay }

// emptyLedger has no records, so judging them again changes nothing.
func emptyLedger(t *testing.T) store.Storage {
	t.Helper()
	st := store.NewMemory()
	if err := st.Save(ledger.New(ledger.State{}).State()); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAFreshLedgerDoesNotRevalidate(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("projects")
	d.wantNot("shop*", "revalidating")
	if b.backfilled() != 0 {
		t.Fatalf("%d back-fills for files that were judged", b.backfilled())
	}
	sn := d.m.(*app).data
	if !sn.StaleKnown || sn.Stale.Stale {
		t.Fatalf("staleness %+v known %v", sn.Stale, sn.StaleKnown)
	}
}

func TestAStaleSnapshotRunsTheBackfillByItselfAndReportsIt(t *testing.T) {
	noThrottle(t)
	b := newFake(t, nil)
	step := make(chan struct{})
	b.backfillFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		<-step
		progress(pipeline.Progress{Phase: pipeline.PhaseFetch, Total: 2})
		progress(pipeline.Progress{Phase: pipeline.PhaseFetch, Total: 2, Source: "nvd", Chunk: 2, Chunks: 9})
		<-step
		return pipeline.Result{Backfilled: []string{"nvd"}, Revalidation: &pipeline.Revalidation{
			Applied: true, NewFindings: 4, Closed: 11, Reopened: 2, Projects: []string{"shop"}}}, nil
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.screen("projects")
	outOfDate(b)
	g.press("r")
	g.untilView("revalidating")
	d.want("shop*", "changes not judged yet: V revalidates")
	step <- struct{}{}
	g.untilView("back-fill 2/9")
	g.press("u")
	d.want("revalidating already")
	step <- struct{}{}
	g.untilView("revalidated shop: 4 new, 11 closed by since 2026-10-15, 2 reopened, back-filled nvd")
	g.quiet()
	if b.backfilled() != 1 || b.fetched() != 0 {
		t.Fatalf("back-fills %d, fetches %d", b.backfilled(), b.fetched())
	}
	if d.m.(*app).fet.job != nil {
		t.Fatal("the job is over")
	}
}

func TestTheBackfillTriesOnceForTheSameFilesAndAgainWhenTheyChange(t *testing.T) {
	b := newFake(t, nil)
	b.backfillFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, nil // leaves the findings as stale as they were
	}
	d := start(t, b, Options{})
	outOfDate(b)
	d.press("r")
	d.press("r", "r")
	if b.backfilled() != 1 {
		t.Fatalf("%d back-fills for the same files", b.backfilled())
	}
	d.m.(*app).stl.invalidate()
	d.m.(*app).tried = "" // what an operation that saved a file does
	d.press("r")
	if b.backfilled() != 2 {
		t.Fatalf("%d back-fills after the files changed", b.backfilled())
	}
}

func TestABusyStoreRetriesQuietlyOnTheNextRead(t *testing.T) {
	b := newFake(t, nil)
	busy := true
	b.backfillFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		if busy {
			return pipeline.Result{}, ErrBusy
		}
		return pipeline.Result{Revalidation: &pipeline.Revalidation{Applied: true, Projects: []string{"shop"}, Closed: 1}}, nil
	}
	d := start(t, b, Options{})
	outOfDate(b)
	d.press("r")
	d.want("in use by another cvewatch")
	d.wantNot("error:")
	busy = false
	d.press("r")
	d.want("revalidated shop: 1 closed by since 2026-10-15")
	if b.backfilled() != 2 {
		t.Fatalf("%d back-fills", b.backfilled())
	}
}

func TestAFetchInProgressHoldsTheBackfillBack(t *testing.T) {
	noThrottle(t)
	b := newFake(t, nil)
	release := make(chan struct{})
	b.fetchFn = func(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
		<-release
		return pipeline.Result{}, nil
	}
	b.backfillFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, nil
	}
	d := start(t, b, Options{})
	g := newBG(d)
	g.press("u")
	g.until("the fetch", func() bool { return b.fetched() == 1 })
	outOfDate(b)
	g.press("r")
	g.quiet()
	if b.backfilled() != 0 {
		t.Fatal("one job at a time: the back-fill waits for the fetch")
	}
	close(release)
	g.until("the back-fill after the fetch", func() bool { return b.backfilled() == 1 })
	g.quiet()
}

func TestRevalidatingForRealJudgesTheFindingsAgain(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.want("3 of 3 open issues")
	outOfDate(b) // the shop now only looks at what was published from the 15th
	d.press("V")
	d.want("Revalidate", "3 closed by since", "y or enter: revalidate")
	if nt := d.m.(*app).nt; nt == nil || !strings.Contains(nt.text, "shop: 3 closed by since 2026-10-15") {
		t.Fatalf("notice %+v", nt)
	}
	d.press("y")
	if f := d.m.(*app).flash; f != "revalidated shop: 3 closed by since 2026-10-15" {
		t.Fatalf("flash %q", f)
	}
	if b.backfilled() != 1 {
		t.Fatalf("%d back-fills", b.backfilled())
	}
	a := d.m.(*app)
	if len(a.data.Issues) != 1 || a.data.Stale.Stale {
		t.Fatalf("%d issues left, stale %+v", len(a.data.Issues), a.data.Stale)
	}
	d.screen("projects")
	d.wantNot("shop*")
}

func TestVAnswersNothingToRevalidate(t *testing.T) {
	b := newFake(t, emptyLedger(t))
	d := start(t, b, Options{})
	for _, scr := range []string{"O", "F", "P", "H", "S"} {
		d.press(scr, "V")
		d.want("nothing to revalidate")
		if d.m.(*app).nt != nil {
			t.Fatal("nothing to ask")
		}
	}
	d.screen("projects")
	d.press("enter", "V")
	d.want("nothing to revalidate")
	if b.backfilled() != 0 {
		t.Fatal("nothing ran")
	}
}

func TestVPreviewCanBeDeclined(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	outOfDate(b)
	d.screen("projects")
	d.press("V")
	d.want("closed by since", "esc: cancel")
	d.press("esc")
	if d.m.(*app).nt != nil || b.backfilled() != 0 {
		t.Fatal("esc leaves the preview without applying it")
	}
}

func TestVIsInTheHelpOfTheRootScreensAndOfAProject(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(200, 60))
	for _, scr := range []string{"O", "F", "P", "H", "S"} {
		d.press(scr, "?")
		d.want("revalidate now")
		d.press("esc")
	}
	d.screen("projects")
	d.press("enter", "?")
	d.want("revalidate now")
}

func TestInputStampFollowsTheFilesTheJudgementDependsOn(t *testing.T) {
	root := t.TempDir()
	dir := config.ProjectsDir(root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "shop.yaml")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lock := filepath.Join(root, "composer.lock")
	if err := os.WriteFile(lock, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Bundle{Root: root}
	cfg.Projects = append(cfg.Projects, model.Project{Name: "shop", Lockfiles: []model.Lockfile{{Type: "composer", Path: lock}}})

	write("name: shop\n")
	one := inputStamp(cfg)
	if one != inputStamp(cfg) {
		t.Fatal("the stamp of unchanged files differs")
	}
	write("name: shop\nsince: 2024-01-01\n")
	two := inputStamp(cfg)
	if two == one {
		t.Fatal("an edited project file keeps the stamp")
	}
	if err := os.WriteFile(lock, []byte(`{"packages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if inputStamp(cfg) == two {
		t.Fatal("an edited lockfile keeps the stamp")
	}
}

func TestEditingTheFileOutsideStartsTheRevalidation(t *testing.T) {
	b := newFake(t, nil)
	b.disk = b.cfg.Root
	writeProjectFile(t, b.cfg.Root, "shop", "name: shop\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: nginx}\n")
	writeProjectFile(t, b.cfg.Root, "mw", "name: mw\nenvs: [prod]\n")
	if cfg, err := config.LoadLenient(b.disk); err != nil {
		t.Fatal(err)
	} else {
		markJudged(t, cfg, b.st)
	}
	b.backfillFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{Revalidation: &pipeline.Revalidation{Applied: true, Projects: []string{"shop"}, NewFindings: 1}}, nil
	}
	d := start(t, b, Options{})
	if b.backfilled() != 0 {
		t.Fatal("judged files start nothing")
	}
	writeProjectFile(t, b.cfg.Root, "shop", "name: shop\nsince: 2026-10-15\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: nginx}\n")
	d.m.(*app).stl.invalidate() // the files are read again at once, not after the minutes the memo trusts them
	d.press("r")
	d.want("revalidated shop: 1 new")
	if b.backfilled() != 1 {
		t.Fatalf("%d back-fills", b.backfilled())
	}
}
