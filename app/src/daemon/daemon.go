// Package daemon runs refresh cycles on the configured interval. It owns the
// loop so front ends hold no behaviour: after every cycle it records a
// heartbeat (so status can tell whether it is alive) and, when enabled,
// rewrites the dashboard page. Sessions are short, so viewers and other
// commands are only blocked while a cycle runs.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// Run cycles until ctx ends. A failing cycle is logged and the next one is
// still scheduled. Between cycles it watches the configuration files; when one
// changes it re-judges everything and fetches what the change newly needs
// right away, instead of waiting for the next interval.
func Run(ctx context.Context, root string, log *slog.Logger) error {
	started := time.Now()
	w := newWatcher(root)
	for {
		interval := cycle(ctx, root, log, started)
		log.Info("sleeping", "for", interval)
		onChange := func(files []string) { reload(ctx, root, log, files) }
		if !wait(ctx, realClock{}, time.Now().Add(interval), w, onChange) {
			return nil
		}
	}
}

// reload applies a configuration change between cycles: it revalidates and
// fetches only the windows the change needs, not every source.
func reload(ctx context.Context, root string, log *slog.Logger, files []string) {
	log.Info("configuration changed, revalidating", "files", strings.Join(files, ","))
	s, err := ops.Open(root, log)
	if err != nil {
		log.Error("reload failed; it will be tried again when a file changes", "err", err)
		return
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
}

func logResult(log *slog.Logger, msg string, res pipeline.Result) {
	log.Info(msg, "items", res.Items, "new", res.New, "merged", res.Merged, "findings", res.Findings,
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

// cycle runs one refresh and returns how long to wait before the next.
func cycle(ctx context.Context, root string, log *slog.Logger, started time.Time) time.Duration {
	interval := 4 * time.Hour
	s, err := ops.Open(root, log)
	if err != nil {
		log.Error("cycle failed", "err", err) // busy store or bad config: try again next time
		if cfg, cerr := config.Load(root); cerr == nil {
			interval = cfg.Interval
		}
		return interval
	}
	defer s.Close()
	interval = s.Cfg.Interval

	res, err := s.RefreshWith(ctx, progressLog(log))
	logResult(log, "cycle done", res)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("cycle failed", "err", err)
	}
	if err := s.Beat(started, s.Now().Add(interval)); err != nil {
		log.Warn("heartbeat not recorded", "err", err)
	}
	if s.Cfg.Dashboard.Enabled {
		if path, err := s.WriteDashboard(); err != nil {
			log.Warn("dashboard not written", "err", err)
		} else {
			log.Debug("dashboard written", "path", path)
		}
	}
	return interval
}
