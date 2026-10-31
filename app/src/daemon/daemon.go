// Package daemon runs refresh cycles on the project schedule. It owns the loop
// so front ends hold no behaviour: it wakes when the first project is due (at
// the latest after the configured interval, so that configuration changes are
// looked at), refreshes the projects that are due, records a heartbeat (so
// status can tell whether it is alive) and, when enabled, rewrites the
// dashboard page. Sessions are short, so viewers and other commands are only
// blocked while a cycle runs.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

const (
	minSleep = time.Minute    // the least between two cycles, so a cycle that cannot finish never spins
	retryMin = model.MinEvery // the least after a cycle that failed
)

// Run cycles until ctx ends. A failing cycle is logged and the next one is
// still scheduled. Between cycles it watches the configuration files; when one
// changes it re-judges everything and fetches what the change newly needs
// right away, and looks again at when something is due, instead of waiting
// for the next cycle.
func Run(ctx context.Context, root string, log *slog.Logger) error {
	started := time.Now()
	w := newWatcher(root)
	for {
		sleep := cycle(ctx, root, log, started)
		log.Info("sleeping", "for", sleep)
		onChange := func(files []string) time.Time { return reload(ctx, root, log, files) }
		if !wait(ctx, realClock{}, time.Now().Add(sleep), w, onChange) {
			return nil
		}
	}
}

// reload applies a configuration change between cycles: it revalidates and
// fetches only the windows the change needs, not every source. It returns when
// the next project is due now, so a new project or a shorter period does not
// wait for the cycle that was planned; zero when that is not known.
func reload(ctx context.Context, root string, log *slog.Logger, files []string) time.Time {
	log.Info("configuration changed, revalidating", "files", strings.Join(files, ","))
	s, err := ops.Open(root, log)
	if err != nil {
		log.Error("reload failed; it will be tried again when a file changes", "err", err)
		return time.Time{}
	}
	defer s.Close()
	res, err := s.Backfill(ctx, progressLog(log))
	logResult(log, "reload done", res)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("reload failed", "err", err)
	}
	if s.Cfg.Dashboard.Enabled {
		if _, err := s.WriteDashboard(); err != nil {
			log.Warn("dashboard not written", "err", err)
		}
	}
	return s.Now().Add(s.Schedule().Wake(s.Now(), s.Cfg.Interval))
}

func logResult(log *slog.Logger, msg string, res pipeline.Result) {
	log.Info(msg, "projects", strings.Join(res.Updated, ","), "items", res.Items, "new", res.New, "merged", res.Merged, "findings", res.Findings,
		"reconciled", res.Reconciled, "enriched", res.Enriched, "alerted", res.Alerted, "digests", res.Digests,
		"failed_sources", len(res.Failed), "backfilled", strings.Join(res.Backfilled, ","))
}

// progressLog reports long fetches, such as a back-fill in chunks, once per chunk.
func progressLog(log *slog.Logger) func(pipeline.Progress) {
	return func(p pipeline.Progress) {
		if p.Phase == pipeline.PhaseFetch && p.Chunk > 0 {
			log.Info("fetching", "source", p.Source, "chunk", p.Chunk, "of", p.Chunks)
		}
	}
}

// cycle runs one refresh of the projects that are due and returns how long to
// wait before the next one is.
func cycle(ctx context.Context, root string, log *slog.Logger, started time.Time) time.Duration {
	interval := 4 * time.Hour
	s, err := ops.Open(root, log)
	if err != nil {
		log.Error("cycle failed", "err", err) // busy store or bad config: try again next time
		if cfg, cerr := config.Load(root); cerr == nil {
			return retryAfter(cfg)
		}
		return interval
	}
	defer s.Close()
	interval = s.Cfg.Interval

	res, err := s.RefreshScheduled(ctx, progressLog(log))
	failed := err != nil && !errors.Is(err, context.Canceled)
	switch {
	case failed:
		logResult(log, "cycle done", res)
		log.Error("cycle failed", "err", err)
	case len(res.Updated) > 0:
		logResult(log, "cycle done", res)
	default:
		log.Info("nothing due", "scheduled", s.Cfg.Update.Auto)
	}
	wake := max(s.Schedule().Wake(s.Now(), interval), minSleep)
	if failed {
		wake = max(wake, min(retryMin, interval))
	}
	if err := s.Beat(started, s.Now().Add(wake)); err != nil {
		log.Warn("heartbeat not recorded", "err", err)
	}
	if s.Cfg.Dashboard.Enabled {
		if path, err := s.WriteDashboard(); err != nil {
			log.Warn("dashboard not written", "err", err)
		} else {
			log.Debug("dashboard written", "path", path)
		}
	}
	return wake
}

// retryAfter is how long to wait after a cycle that could not even open the
// data: the shortest period of a project that is scheduled, at most the interval.
func retryAfter(cfg *config.Bundle) time.Duration {
	wait := cfg.Interval
	if cfg.Update.Auto {
		for _, p := range cfg.Projects {
			if p.AutoUpdate() {
				wait = min(wait, p.Every(cfg.Interval))
			}
		}
	}
	return wait
}
