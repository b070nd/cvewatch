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

// jobKind says what a background job does: fetch the feeds, or judge the
// findings again and fetch only what that needs.
type jobKind uint8

const (
	jobFetch jobKind = iota
	jobBackfill
)

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
	kind     jobKind
	auto     bool // started by the program, not by a key
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
	if s.job.kind == jobBackfill && s.prog.Phase == "" {
		return "revalidating " + spin
	}
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
	switch {
	case s.prog.Chunks > 0 && s.prog.Chunk > 0:
		return fmt.Sprintf("back-fill %d/%d %s", s.prog.Chunk, s.prog.Chunks, spin)
	case s.prog.Chunk > 0:
		return fmt.Sprintf("back-fill %d %s", s.prog.Chunk, spin)
	case s.prog.Total > 0 && s.job.kind == jobBackfill:
		return fmt.Sprintf("back-fill %d/%d %s", s.prog.Done, s.prog.Total, spin)
	case s.prog.Total > 0:
		return fmt.Sprintf("fetch %d/%d %s", s.prog.Done, s.prog.Total, spin)
	case s.job.kind == jobBackfill:
		return "back-fill " + spin
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
func (m *app) fetchBegin(auto bool) tea.Cmd { return m.jobBegin(jobFetch, auto) }

// jobBegin starts a fetch or a back-fill; there is one job at a time and the
// header cell shows it.
func (m *app) jobBegin(kind jobKind, auto bool) tea.Cmd {
	if j := m.fet.job; j != nil {
		switch {
		case auto:
		case j.kind == jobBackfill:
			m.note("revalidating already; the header shows the progress")
		default:
			m.note("a fetch is already running")
		}
		return nil
	}
	if m.ctx.Err() != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	j := newFetchJob(cancel)
	j.kind, j.auto = kind, auto
	first := pipeline.Progress{Phase: pipeline.PhaseFetch}
	if kind == jobBackfill {
		first = pipeline.Progress{} // judging again comes first and reports nothing
	}
	m.fet.job, m.fet.prog, m.fet.spin, m.fet.failed = j, first, 0, nil
	b := m.b
	run := func() tea.Msg {
		defer close(j.finished)
		var res pipeline.Result
		var err error
		if kind == jobBackfill {
			res, err = b.Backfill(ctx, j.report)
		} else {
			res, err = b.Fetch(ctx, j.report)
		}
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
	if msg.job.kind == jobBackfill {
		return m.backfillDone(msg)
	}
	m.stl.invalidate() // the cycle judged the findings again first
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
	if rv := msg.res.Revalidation; rv != nil && rv.Applied {
		note += "; revalidated " + m.revalWords(*rv, 0)
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
		if j.kind == jobBackfill {
			return &notice{title: "Revalidating", text: "The findings are being judged again against the projects, technologies and since dates, and the sources reach back for what that needs; the screens keep working. " + strings.TrimSpace(m.fet.cell()) + "."}
		}
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
