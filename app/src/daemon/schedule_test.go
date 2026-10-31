package daemon

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// schedRoot is a configuration whose every feed is disabled, so a cycle
// leaves the machine for nothing, with a project per kind of schedule.
func schedRoot(t *testing.T, update string) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, "config/config.yaml", "interval: 4h\ndata_dir: data\nalerts_dir: alerts\n"+update, t0)
	put(t, root, "config/projects/shop.yaml", "name: shop\n", t0)
	put(t, root, "config/projects/blog.yaml", "name: blog\nupdate:\n  every: 1h\n", t0)
	put(t, root, "config/projects/lab.yaml", "name: lab\nupdate:\n  auto: false\n", t0)
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var off strings.Builder
	off.WriteString("sources:\n")
	for _, s := range cfg.Sources {
		off.WriteString("  - {id: " + s.ID + ", type: " + s.Type + ", url: 'https://feeds.invalid/" + s.ID + "', disabled: true}\n")
	}
	put(t, root, filepath.Join("sources", "off.yaml"), off.String(), t0)
	return root
}

func lastUpdates(t *testing.T, root string) map[string]time.Time {
	t.Helper()
	s, err := ops.Open(root, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return map[string]time.Time{"shop": s.Ledger.LastUpdate("shop"), "blog": s.Ledger.LastUpdate("blog"), "lab": s.Ledger.LastUpdate("lab")}
}

func TestACycleUpdatesTheDueProjectsAndSleepsUntilTheNextIsDue(t *testing.T) {
	root := schedRoot(t, "")
	before := time.Now()
	sleep := cycle(context.Background(), root, quietLog(), before)
	got := lastUpdates(t, root)
	if got["shop"].Before(before) || got["blog"].Before(before) || !got["lab"].IsZero() {
		t.Fatalf("shop and blog are updated, the paused lab is not: %v", got)
	}
	if sleep > time.Hour || sleep < 59*time.Minute {
		t.Fatalf("the next to be due is blog, in an hour: %s", sleep)
	}

	s, err := ops.Open(root, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := s.Status(); err != nil || !rep.Daemon.Alive() || rep.Daemon.NextRun.Before(before.Add(59*time.Minute)) {
		t.Fatalf("the heartbeat tells when the next cycle is: %+v %v", rep.Daemon, err)
	}
	s.Close()

	// nothing is due now: the cycle changes nothing and waits for the same moment
	sleep = cycle(context.Background(), root, quietLog(), before)
	again := lastUpdates(t, root)
	if !again["shop"].Equal(got["shop"]) || !again["blog"].Equal(got["blog"]) {
		t.Errorf("nothing was due, nothing is updated: %v", again)
	}
	if sleep > time.Hour || sleep < 59*time.Minute {
		t.Errorf("sleep = %s", sleep)
	}
}

func TestACycleWithScheduledUpdatesOffUpdatesNothingAndWaitsTheInterval(t *testing.T) {
	root := schedRoot(t, "update:\n  auto: false\n")
	sleep := cycle(context.Background(), root, quietLog(), time.Now())
	for name, at := range lastUpdates(t, root) {
		if !at.IsZero() {
			t.Errorf("%s was updated though scheduled updates are off", name)
		}
	}
	if sleep != 4*time.Hour {
		t.Errorf("sleep = %s", sleep)
	}
}

func TestACycleNeverSleepsLessThanAMinute(t *testing.T) {
	root := schedRoot(t, "")
	cycle(context.Background(), root, quietLog(), time.Now())
	s, err := ops.Open(root, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	s.Ledger.SetLastUpdate("blog", time.Now().Add(-time.Hour+10*time.Second)) // due in 10 seconds
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if sleep := cycle(context.Background(), root, quietLog(), time.Now()); sleep < minSleep {
		t.Fatalf("sleep = %s", sleep)
	}
}

func TestWaitTakesAnEarlierDeadlineFromTheChange(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/projects/shop.yaml", "name: shop\n", t0)
	w := newWatcher(root)
	clk := &fakeClock{now: t0}
	edited := false
	clk.hook = func(now time.Time) {
		if !edited && now.Sub(t0) >= 10*time.Second {
			edited = true
			put(t, root, "config/projects/shop.yaml", "name: shop\ntechs: []\n", now)
		}
	}
	due := t0.Add(2 * time.Minute)
	ok := wait(context.Background(), clk, t0.Add(time.Hour), w, func([]string) time.Time { return due })
	if !ok || !clk.now.Equal(due) {
		t.Fatalf("ok=%v, ended at %v, want %v", ok, clk.now, due)
	}

	// a later time than the deadline changes nothing
	clk = &fakeClock{now: t0}
	edited = false
	clk.hook = func(now time.Time) {
		if !edited && now.Sub(t0) >= 10*time.Second {
			edited = true
			put(t, root, "config/projects/shop.yaml", "name: shop\ntechs: [{name: php}]\n", now)
		}
	}
	end := t0.Add(time.Minute)
	wait(context.Background(), clk, end, newWatcher(root), func([]string) time.Time { return t0.Add(time.Hour) })
	if !clk.now.Equal(end) {
		t.Errorf("the deadline stays: %v", clk.now)
	}
}

func TestReloadReturnsWhenTheNextProjectIsDue(t *testing.T) {
	root := schedRoot(t, "")
	at := reload(context.Background(), root, quietLog(), []string{"config/projects/shop.yaml"})
	if at.IsZero() || at.After(time.Now().Add(time.Second)) {
		t.Fatalf("projects that were never updated are due now: %v", at)
	}
	cycle(context.Background(), root, quietLog(), time.Now())
	at = reload(context.Background(), root, quietLog(), nil)
	if d := time.Until(at); d > time.Hour || d < 59*time.Minute {
		t.Fatalf("blog is due in an hour: %v", d)
	}
}
