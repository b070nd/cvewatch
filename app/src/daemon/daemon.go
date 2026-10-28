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
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// Run cycles until ctx ends. A failing cycle is logged and the next one is
// still scheduled.
func Run(ctx context.Context, root string, log *slog.Logger) error {
	started := time.Now()
	for {
		interval := cycle(ctx, root, log, started)
		log.Info("sleeping", "for", interval)
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return nil
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

	res, err := s.Refresh(ctx)
	log.Info("cycle done", "items", res.Items, "new", res.New, "merged", res.Merged, "findings", res.Findings,
		"reconciled", res.Reconciled, "enriched", res.Enriched, "alerted", res.Alerted, "digests", res.Digests,
		"failed_sources", len(res.Failed))
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
