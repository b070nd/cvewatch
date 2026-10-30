package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

var fetchSpin = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// fetchThrottle is the least time between two progress events that reach the
// interface in the same phase; a new phase always gets through.
var fetchThrottle = 250 * time.Millisecond

type (
	tuiMsg           struct{ set config.TUI }
	fetchDueMsg      struct{}
	fetchProgressMsg struct{ job *fetchJob }
	fetchDoneMsg     struct {
		job *fetchJob
		res pipeline.Result
		err error
	}
)

// fetchJob is one run in the background. report is called from the pipeline's
// goroutines and never waits: it keeps the latest step and wakes wait.
type fetchJob struct {
	cancel   context.CancelFunc
	sig      chan struct{} // holds at most one wake-up
	finished chan struct{} // closed when Backend.Fetch has returned

	mu     sync.Mutex
	latest pipeline.Progress
	failed []string
	sentAt time.Time
	sentPh pipeline.Phase
}

func newFetchJob(cancel context.CancelFunc) *fetchJob {
	return &fetchJob{cancel: cancel, sig: make(chan struct{}, 1), finished: make(chan struct{})}
}

func (j *fetchJob) report(p pipeline.Progress) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.latest = p
	if p.Failed {
		j.failed = append(j.failed, p.Source)
	}
	now := time.Now()
	if !j.sentAt.IsZero() && p.Phase == j.sentPh && now.Sub(j.sentAt) < fetchThrottle {
		return
	}
	j.sentAt, j.sentPh = now, p.Phase
	select {
	case j.sig <- struct{}{}:
	default:
	}
}

func (j *fetchJob) snapshot() (pipeline.Progress, []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.latest, append([]string(nil), j.failed...)
}

// wait is the command that delivers the next progress event; it ends quietly
// when the run is over.
func (j *fetchJob) wait() tea.Cmd {
	return func() tea.Msg {
		select {
		case <-j.sig:
			return fetchProgressMsg{job: j}
		case <-j.finished:
			return nil
		}
	}
}

type fetchState struct {
	job    *fetchJob // the run in progress; nil when none
	prog   pipeline.Progress
	spin   int
	failed []string // sources that failed in the last run, until they are looked at
	armed  bool     // the timer of the next run is set
}

// cell is the header text for the run in progress, or for the failures of the
// last one; empty when there is nothing to tell.
func (s *fetchState) cell() string {
	if s.job == nil {
		switch n := len(s.failed); {
		case n == 1:
			return "1 source failed"
		case n > 1:
			return fmt.Sprintf("%d sources failed", n)
		}
		return ""
	}
	spin := fetchSpin[s.spin%len(fetchSpin)]
	switch s.prog.Phase {
	case pipeline.PhaseProcess:
		return "matching " + spin
	case pipeline.PhaseEnrich:
		return "enriching " + spin
	case pipeline.PhaseSave:
		return "saving " + spin
	case pipeline.PhaseAlert:
		return "alerting " + spin
	}
	if s.prog.Total > 0 {
		return fmt.Sprintf("fetch %d/%d %s", s.prog.Done, s.prog.Total, spin)
	}
	return "fetch " + spin
}

func tuiCmd(b Backend) tea.Cmd {
	return func() tea.Msg { return tuiMsg{set: b.TUISettings()} }
}

// refreshEvery is the period of the re-read.
func (m *app) refreshEvery() time.Duration {
	if m.tui.Refresh > 0 {
		return m.tui.Refresh
	}
	return 30 * time.Second
}

// armFetch sets the timer of the next fetch when the setting asks for one.
func (m *app) armFetch() tea.Cmd {
	if m.fet.armed || m.tui.Fetch <= 0 || m.after == nil {
		return nil
	}
	m.fet.armed = true
	return m.after(m.tui.Fetch, fetchDueMsg{})
}

// fetchBegin starts a fetch in the background unless one is running. The
// interface keeps reading the ledger meanwhile; the run holds the store only
// inside Backend.Fetch.
func (m *app) fetchBegin(auto bool) tea.Cmd {
	if m.fet.job != nil {
		if !auto {
			m.note("a fetch is already running")
		}
		return nil
	}
	if m.ctx.Err() != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	j := newFetchJob(cancel)
	m.fet.job, m.fet.prog, m.fet.spin, m.fet.failed = j, pipeline.Progress{Phase: pipeline.PhaseFetch}, 0, nil
	b := m.b
	run := func() tea.Msg {
		defer close(j.finished)
		res, err := b.Fetch(ctx, j.report)
		cancel()
		return fetchDoneMsg{job: j, res: res, err: err}
	}
	return tea.Batch(run, j.wait())
}

func (m *app) fetchUpdate(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tuiMsg:
		if msg.set.Refresh > 0 {
			m.tui.Refresh = msg.set.Refresh
		}
		m.tui.Fetch = msg.set.Fetch
		return m.armFetch()
	case fetchDueMsg:
		m.fet.armed = false
		if m.tui.Fetch <= 0 {
			return nil
		}
		return tea.Batch(m.fetchBegin(true), m.armFetch())
	case fetchProgressMsg:
		if msg.job != m.fet.job {
			return nil
		}
		m.fet.prog, _ = msg.job.snapshot()
		m.fet.spin++
		return msg.job.wait()
	case fetchDoneMsg:
		return m.fetchDone(msg)
	}
	return nil
}

func (m *app) fetchDone(msg fetchDoneMsg) tea.Cmd {
	if msg.job != m.fet.job {
		return nil
	}
	m.fet.job, m.fet.prog = nil, pipeline.Progress{}
	switch {
	case errors.Is(msg.err, ErrBusy):
		if m.tui.Fetch > 0 {
			m.note("the data is in use by another cvewatch; will retry in " + formatSpan(m.tui.Fetch))
		} else {
			m.note("the data is in use by another cvewatch; press F to try again")
		}
		return nil
	case msg.err != nil && (m.ctx.Err() != nil || errors.Is(msg.err, context.Canceled)):
		return nil
	case msg.err != nil:
		m.fail("fetch failed: " + msg.err.Error())
		return m.refresh(reList | reDetail)
	}
	m.fet.failed = msg.res.Failed
	note := fmt.Sprintf("fetched: %d new, %d findings", msg.res.New, msg.res.Findings)
	switch n := len(msg.res.Failed); {
	case n == 1:
		note += ", 1 source failed"
	case n > 1:
		note += fmt.Sprintf(", %d sources failed", n)
	}
	m.say(note)
	return m.refresh(reList | reDetail)
}

// fetchClick opens the details when the progress cell in the header is clicked.
func (m *app) fetchClick(msg tea.MouseMsg) (tea.Cmd, bool) {
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft || msg.Y != 0 || m.top().modal {
		return nil, false
	}
	w, _ := m.size()
	_, _, from, to := m.headerParts(w)
	if to <= from || msg.X < from || msg.X >= to {
		return nil, false
	}
	m.nt = m.fetchDetails()
	return nil, true
}

func (m *app) fetchDetails() *notice {
	if j := m.fet.job; j != nil {
		_, failed := j.snapshot()
		text := "The feeds are being fetched in the background; the screens keep working. " + strings.TrimSpace(m.fet.cell()) + "."
		if len(failed) > 0 {
			text += " Failed so far: " + strings.Join(failed, ", ") + "."
		}
		return &notice{title: "Fetching the feeds", text: text}
	}
	failed := m.fet.failed
	m.fet.failed = nil
	return &notice{title: "Sources that failed", text: strings.Join(failed, "; ")}
}

// quit leaves the program and stops the fetch that runs.
func (m *app) quit() tea.Cmd {
	m.stop()
	return tea.Quit
}

// waitFetch gives a cancelled fetch a moment to release the data.
func (m *app) waitFetch(d time.Duration) {
	if j := m.fet.job; j != nil {
		select {
		case <-j.finished:
		case <-time.After(d):
		}
	}
}
