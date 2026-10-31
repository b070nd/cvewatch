package daemon

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
)

const (
	pollEvery = 15 * time.Second // how often the configuration files are looked at
	settle    = 2 * time.Second  // wait after a change so a save in several steps is seen whole
)

// stamp is all that is looked at of a file: no content is read.
type stamp struct {
	mod  time.Time
	size int64
}

// snapshot stats the files the configuration is made of: config.yaml,
// techs.yaml, every project file and every source file. Keys are slash paths
// relative to root.
func snapshot(root string) map[string]stamp {
	out := map[string]stamp{}
	add := func(path string) {
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			rel, _ := filepath.Rel(root, path)
			out[filepath.ToSlash(rel)] = stamp{fi.ModTime(), fi.Size()}
		}
	}
	add(config.SettingsPath(root))
	add(config.TechsPath(root))
	for _, dir := range []string{config.ProjectsDir(root), config.SourcesDir(root)} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			add(filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// changed lists the files added, removed or modified between two snapshots, sorted.
func changed(prev, cur map[string]stamp) []string {
	set := map[string]bool{}
	for name, s := range cur {
		if old, ok := prev[name]; !ok || old != s {
			set[name] = true
		}
	}
	for name := range prev {
		if _, ok := cur[name]; !ok {
			set[name] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// watcher remembers the last snapshot of a configuration folder.
type watcher struct {
	root string
	last map[string]stamp
}

func newWatcher(root string) *watcher { return &watcher{root: root, last: snapshot(root)} }

// poll returns what changed since the previous call and remembers the new state.
func (w *watcher) poll() []string {
	cur := snapshot(w.root)
	files := changed(w.last, cur)
	w.last = cur
	return files
}

// clock is time as wait sees it, so tests need not sleep.
type clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) bool // false when ctx ended first
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// wait sleeps until the given time, looking at the files every pollEvery, and
// calls onChange with the changed files as soon as there are some. It returns
// false when ctx ended.
func wait(ctx context.Context, clk clock, until time.Time, w *watcher, onChange func(files []string)) bool {
	for clk.Now().Before(until) {
		if !clk.Sleep(ctx, min(pollEvery, until.Sub(clk.Now()))) {
			return false
		}
		files := w.poll()
		if len(files) == 0 {
			continue
		}
		if !clk.Sleep(ctx, settle) {
			return false
		}
		files = slices.Compact(slices.Sorted(slices.Values(append(files, w.poll()...))))
		onChange(files)
	}
	return ctx.Err() == nil
}
