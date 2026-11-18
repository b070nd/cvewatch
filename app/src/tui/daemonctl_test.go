package tui

import (
	"errors"
	"testing"

	"github.com/b070nd/cvewatch/app/src/daemon"
)

type stubDaemon struct {
	running       bool
	starts, stops int
	startErr      error
}

func (s *stubDaemon) Running() (daemon.Info, bool) { return daemon.Info{PID: 4242}, s.running }
func (s *stubDaemon) Start() (daemon.Info, error) {
	s.starts++
	if s.startErr != nil {
		return daemon.Info{}, s.startErr
	}
	s.running = true
	return daemon.Info{PID: 4242}, nil
}
func (s *stubDaemon) Stop() error { s.stops++; s.running = false; return nil }

type withDaemon struct {
	*fake
	ctl *stubDaemon
}

func (w withDaemon) Daemon() DaemonControl { return w.ctl }

func TestDKeyStartsTheDaemonAfterAskingAndStopsItWhenItRuns(t *testing.T) {
	ctl := &stubDaemon{}
	d := start(t, withDaemon{newFake(t, nil), ctl}, Options{})
	d.screen("health")
	d.want("d starts the daemon")

	d.press("d")
	d.want("Start the daemon in the background?")
	d.press("n")
	if ctl.starts != 0 {
		t.Fatal("no means no")
	}

	d.press("d", "y")
	if ctl.starts != 1 {
		t.Fatalf("starts = %d", ctl.starts)
	}
	d.want("the daemon runs (pid 4242)")

	d.press("d")
	d.want("Stop the daemon (pid 4242)?")
	d.press("y")
	if ctl.stops != 1 || ctl.running {
		t.Fatalf("stops = %d, running = %v", ctl.stops, ctl.running)
	}
	d.want("the daemon stopped")
}

func TestDKeyShowsWhyTheDaemonDidNotStart(t *testing.T) {
	ctl := &stubDaemon{startErr: errors.New("a daemon is already running")}
	d := start(t, withDaemon{newFake(t, nil), ctl}, Options{})
	d.screen("health")
	d.press("d", "y")
	d.want("a daemon is already running")
}

func TestDKeyOnABackendWithoutDaemonControlSaysSo(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("health")
	d.press("d")
	d.want("cannot be started or stopped from here")
}
