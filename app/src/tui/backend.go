package tui

import (
	"log/slog"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// Backend is everything the TUI needs from the monitor. Read hands the
// function a lock-free read-only snapshot, so the TUI never blocks the daemon.
// Write opens a short write session for one change and closes it again.
// Both run fn on the calling goroutine; the TUI calls them from tea.Cmds.
type Backend interface {
	Read(fn func(*ops.Session) error) error
	Write(fn func(*ops.Session) error) error
}

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
