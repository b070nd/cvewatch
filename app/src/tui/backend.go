package tui

import (
	"context"
	"log/slog"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/store"
)

// Backend is everything the TUI needs from the monitor. Read hands the
// function a lock-free read-only snapshot, so the TUI never blocks the daemon.
// Write opens a short write session for one change and closes it again.
// Both run fn on the calling goroutine; the TUI calls them from tea.Cmds.
type Backend interface {
	Read(fn func(*ops.Session) error) error
	Write(fn func(*ops.Session) error) error
	// Settings opens the configuration documents without loading the
	// configuration, so the Settings screen works while config.yaml is broken.
	Settings(fn func(*ops.SettingsSession) error) error
	// Fetch fetches the feeds once, like a daemon cycle, under a write
	// session. progress may be nil and is called from several goroutines, one
	// at a time. It returns store.ErrBusy when another process, such as the
	// daemon in a cycle, holds the data; the caller retries later.
	Fetch(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error)
	// Update is Fetch for the project schedule: the feeds are fetched once, but
	// only the projects that are due are judged and alerted, and nothing is
	// fetched when none is. It returns store.ErrBusy like Fetch.
	Update(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error)
	// Backfill re-judges the findings if the configuration changed, then polls
	// only the sources that owe a back-fill (see ops.Session.Backfill). It
	// returns store.ErrBusy like Fetch.
	Backfill(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error)
	// TUISettings reads the tui section of config.yaml afresh. It never fails:
	// a broken or missing file gives the defaults.
	TUISettings() config.TUI
}

// ErrBusy is what Fetch returns while another process holds the data.
var ErrBusy = store.ErrBusy

type backend struct {
	root string
	log  *slog.Logger
}

// NewBackend returns a Backend over the configuration and state under root.
// A project file that does not load is only listed in Cfg.Broken.
// Every session acts as "tui:<user>", so the audit log shows who changed what
// and access rules still name people. The logger must not write to the
// terminal the TUI draws on; nil discards.
func NewBackend(root string, log *slog.Logger) Backend {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &backend{root: root, log: log}
}

func actor() string { return "tui:" + audit.Actor() }

func (b *backend) Read(fn func(*ops.Session) error) error {
	s, err := ops.OpenReadOnlyRepair(b.root, b.log)
	if err != nil {
		return err
	}
	defer s.Close()
	s.Actor = actor()
	return fn(s)
}

func (b *backend) Write(fn func(*ops.Session) error) error {
	s, err := ops.OpenRepair(b.root, b.log)
	if err != nil {
		return err
	}
	defer s.Close()
	s.Actor = actor()
	return fn(s)
}

func (b *backend) Settings(fn func(*ops.SettingsSession) error) error {
	ss, err := ops.OpenSettings(b.root)
	if err != nil {
		return err
	}
	ss.Actor = actor()
	return fn(ss)
}

func (b *backend) Fetch(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
	s, err := ops.OpenRepair(b.root, b.log)
	if err != nil {
		return pipeline.Result{}, err
	}
	defer s.Close()
	s.Actor = actor()
	return s.RefreshWith(ctx, progress)
}

func (b *backend) Update(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
	s, err := ops.OpenRepair(b.root, b.log)
	if err != nil {
		return pipeline.Result{}, err
	}
	defer s.Close()
	s.Actor = actor()
	return s.RefreshScheduled(ctx, progress)
}

func (b *backend) Backfill(ctx context.Context, progress func(ops.RefreshProgress)) (pipeline.Result, error) {
	s, err := ops.OpenRepair(b.root, b.log)
	if err != nil {
		return pipeline.Result{}, err
	}
	defer s.Close()
	s.Actor = actor()
	return s.Backfill(ctx, progress)
}

func (b *backend) TUISettings() config.TUI { return config.LoadTUI(b.root) }
