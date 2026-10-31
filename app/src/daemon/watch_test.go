package daemon

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func put(t *testing.T, root, rel, body string, mod time.Time) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
}

var t0 = time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)

func TestSnapshotAndChanged(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "interval: 4h\n", t0)
	put(t, root, "config/techs.yaml", "techs: []\n", t0)
	put(t, root, "config/projects/shop.yaml", "name: shop\n", t0)
	put(t, root, "sources/s.yaml", "sources: []\n", t0)
	put(t, root, "data/state.json", "{}", t0) // not configuration
	before := snapshot(root)
	if want := []string{"config/config.yaml", "config/projects/shop.yaml", "config/techs.yaml", "sources/s.yaml"}; !slices.Equal(slices.Sorted(mapKeys(before)), want) {
		t.Fatalf("watched = %v", slices.Sorted(mapKeys(before)))
	}
	if got := changed(before, snapshot(root)); len(got) != 0 {
		t.Fatalf("nothing happened: %v", got)
	}

	put(t, root, "config/projects/shop.yaml", "name: shop\n", t0.Add(time.Minute)) // a new mtime
	put(t, root, "config/techs.yaml", "techs: [a]\n", t0)                          // a new size under the same mtime
	put(t, root, "config/projects/api.yaml", "name: api\n", t0)                    // a new file
	if err := os.Remove(filepath.Join(root, "sources", "s.yaml")); err != nil {    // a removed file
		t.Fatal(err)
	}
	put(t, root, "data/state.json", "{\"x\":1}", t0.Add(time.Hour))
	want := []string{"config/projects/api.yaml", "config/projects/shop.yaml", "config/techs.yaml", "sources/s.yaml"}
	if got := changed(before, snapshot(root)); !slices.Equal(got, want) {
		t.Fatalf("changed = %v, want %v", got, want)
	}
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// fakeClock moves only when something sleeps, and runs hook after each sleep.
type fakeClock struct {
	now   time.Time
	hook  func(now time.Time)
	slept []time.Duration
}

func (f *fakeClock) Now() time.Time { return f.now }

func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	f.slept = append(f.slept, d)
	f.now = f.now.Add(d)
	if f.hook != nil {
		f.hook(f.now)
	}
	return true
}

func TestWaitPollsAndReportsChangesOnce(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/projects/shop.yaml", "name: shop\n", t0)
	w := newWatcher(root)
	clk := &fakeClock{now: t0}
	edited := false
	clk.hook = func(now time.Time) {
		if !edited && now.Sub(t0) >= 40*time.Second { // the file changes between the third and fourth poll
			edited = true
			put(t, root, "config/projects/shop.yaml", "name: shop\ntechs: [{name: php}]\n", now)
		}
	}
	var calls [][]string
	ok := wait(context.Background(), clk, t0.Add(2*time.Minute), w, func(files []string) time.Time { calls = append(calls, files); return time.Time{} })
	if !ok || len(calls) != 1 || !slices.Equal(calls[0], []string{"config/projects/shop.yaml"}) {
		t.Fatalf("ok=%v calls=%v", ok, calls)
	}
	if !clk.now.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("wait must end at the deadline, ended at %v", clk.now)
	}
	if clk.slept[0] != pollEvery {
		t.Errorf("first sleep = %v, want %v", clk.slept[0], pollEvery)
	}
	if !slices.Contains(clk.slept, settle) {
		t.Errorf("a change is given %v to settle: %v", settle, clk.slept)
	}
}

func TestWaitMergesASaveInSeveralSteps(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/projects/a.yaml", "name: a\n", t0)
	w := newWatcher(root)
	clk := &fakeClock{now: t0}
	step := 0
	clk.hook = func(now time.Time) {
		switch step {
		case 0:
			put(t, root, "config/projects/a.yaml", "name: a\ntechs: []\n", now)
		case 1: // during the settle time a second file lands
			put(t, root, "config/projects/b.yaml", "name: b\n", now)
		}
		step++
	}
	var calls [][]string
	wait(context.Background(), clk, t0.Add(time.Minute), w, func(files []string) time.Time { calls = append(calls, files); return time.Time{} })
	if len(calls) != 1 || !slices.Equal(calls[0], []string{"config/projects/a.yaml", "config/projects/b.yaml"}) {
		t.Fatalf("calls = %v", calls)
	}
}

func TestWaitStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if wait(ctx, &fakeClock{now: t0}, t0.Add(time.Hour), newWatcher(t.TempDir()), func([]string) time.Time { t.Fatal("no change expected"); return time.Time{} }) {
		t.Fatal("a cancelled context must end the wait")
	}
}

func TestWaitSleepsOnlyUntilTheDeadline(t *testing.T) {
	clk := &fakeClock{now: t0}
	wait(context.Background(), clk, t0.Add(20*time.Second), newWatcher(t.TempDir()), nil)
	if len(clk.slept) != 2 || clk.slept[0] != pollEvery || clk.slept[1] != 5*time.Second {
		t.Fatalf("slept = %v", clk.slept)
	}
}
