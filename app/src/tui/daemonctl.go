package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/daemon"
)

// DaemonControl starts and stops the background daemon of the data this TUI
// shows.
type DaemonControl interface {
	Running() (daemon.Info, bool)
	Start() (daemon.Info, error)
	Stop() error
}

// A Backend that can also run the daemon says so by having this method.
type daemonBackend interface{ Daemon() DaemonControl }

type fileDaemon struct{ root string }

func (b *backend) Daemon() DaemonControl { return fileDaemon{b.root} }

func (d fileDaemon) dataDir() (string, error) {
	cfg, err := config.Load(d.root)
	if err != nil {
		return "", err
	}
	return cfg.DataDir, nil
}

func (d fileDaemon) Running() (daemon.Info, bool) {
	dir, err := d.dataDir()
	if err != nil {
		return daemon.Info{}, false
	}
	return daemon.Running(dir)
}

func (d fileDaemon) Start() (daemon.Info, error) {
	dir, err := d.dataDir()
	if err != nil {
		return daemon.Info{}, err
	}
	exe, err := daemon.Executable()
	if err != nil {
		return daemon.Info{}, err
	}
	return daemon.Start(exe, d.root, dir)
}

func (d fileDaemon) Stop() error {
	dir, err := d.dataDir()
	if err != nil {
		return err
	}
	return daemon.Stop(dir, 30*time.Second)
}

type daemonDoneMsg struct {
	started bool
	info    daemon.Info
	err     error
}

func (m *app) daemonControl() DaemonControl {
	if b, ok := m.b.(daemonBackend); ok {
		return b.Daemon()
	}
	return nil
}

// daemonKey asks whether to stop the daemon when one runs, else whether to
// start one.
func (m *app) daemonKey() tea.Cmd {
	ctl := m.daemonControl()
	if ctl == nil {
		m.fail("the daemon cannot be started or stopped from here")
		return nil
	}
	if info, ok := ctl.Running(); ok {
		m.cfm = &confirm{ask: fmt.Sprintf("Stop the daemon (pid %d)? Nothing refreshes by itself until it is started again.", info.PID),
			yes: func(m *app) tea.Cmd {
				m.note("stopping the daemon; it finishes what it is doing first")
				return func() tea.Msg { return daemonDoneMsg{err: ctl.Stop()} }
			}}
		return nil
	}
	m.cfm = &confirm{ask: "Start the daemon in the background? It refreshes the projects on their schedule and keeps running after you quit; its log is data/daemon.log.",
		yes: func(m *app) tea.Cmd {
			m.note("starting the daemon")
			return func() tea.Msg { info, err := ctl.Start(); return daemonDoneMsg{started: true, info: info, err: err} }
		}}
	return nil
}

func (m *app) daemonDone(msg daemonDoneMsg) tea.Cmd {
	switch {
	case msg.err != nil:
		m.fail(msg.err.Error())
	case msg.started:
		m.say(fmt.Sprintf("the daemon runs (pid %d)", msg.info.PID))
	default:
		m.say("the daemon stopped")
	}
	return m.refresh(reList | reDetail)
}

func bindDaemon() binding {
	return binding{keys: ks("d"), help: "start the daemon in the background, or stop it when it runs: it refreshes the projects on their schedule", short: "daemon", prio: 2,
		do: plain((*app).daemonKey)}
}
