package tui

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// staleTTL is how long a worked-out staleness is trusted when the files have
// not changed: another process (the daemon) may have revalidated meanwhile.
const staleTTL = 2 * time.Minute

// staleMemo keeps the staleness of the last snapshot, which reads the
// lockfiles and so is not worked out on every re-read. A nil memo works out
// the staleness every time.
type staleMemo struct {
	mu    sync.Mutex
	stamp string
	st    ops.Staleness
	at    time.Time
	ok    bool
}

func (c *staleMemo) invalidate() {
	if c != nil {
		c.mu.Lock()
		c.ok = false
		c.mu.Unlock()
	}
}

func (c *staleMemo) staleness(s *ops.Session, stamp string) (ops.Staleness, bool) {
	if c != nil {
		c.mu.Lock()
		if c.ok && c.stamp == stamp && time.Since(c.at) < staleTTL {
			st := c.st
			c.mu.Unlock()
			return st, true
		}
		c.mu.Unlock()
	}
	st, err := s.Stale()
	if err != nil {
		return ops.Staleness{}, false
	}
	if c != nil {
		c.mu.Lock()
		c.stamp, c.st, c.at, c.ok = stamp, st, time.Now(), true
		c.mu.Unlock()
	}
	return st, true
}

// inputStamp names the state of the files the judgement depends on: the
// settings, the technologies, the project files and their lockfiles. It only
// looks at sizes and times, so it is cheap on every re-read.
func inputStamp(cfg *config.Bundle) string {
	paths := []string{config.SettingsPath(cfg.Root), config.TechsPath(cfg.Root)}
	dir := config.ProjectsDir(cfg.Root)
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, p := range cfg.Projects {
		for _, l := range p.Lockfiles {
			paths = append(paths, l.Path)
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	h := fnv.New64a()
	for _, p := range paths {
		fmt.Fprintf(h, "%s|", p)
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(h, "%d|%d", fi.Size(), fi.ModTime().UnixNano())
		}
		fmt.Fprint(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// markUnjudged flags the project rows whose changes the findings were not
// judged against yet; a changed horizon concerns all of them.
func (sn *snapshot) markUnjudged() {
	if !sn.StaleKnown || !sn.Stale.Stale || sn.Stale.Never {
		return
	}
	for i := range sn.Projects {
		p := &sn.Projects[i]
		p.Unjudged = !p.Disabled && p.Broken == "" && (sn.Stale.Horizon || slices.Contains(sn.Stale.Projects, p.Name))
	}
}

// autoDue is whether the snapshot calls for a revalidation without being
// asked: the findings were judged against other files, or a back-fill is owed.
// A ledger that never recorded a judgement (new, or from before) is left to
// the next fetch and to V, so opening the program does not start a download.
func (sn *snapshot) autoDue() bool {
	return sn != nil && sn.StaleKnown && ((sn.Stale.Stale && !sn.Stale.Never) || len(sn.Stale.BackfillPending) > 0)
}

// autoBackfill starts the quiet job that judges the findings again when a
// snapshot says they are out of date, once for each state of the files; a
// job already running, or an earlier attempt on the same files, leaves it.
func (m *app) autoBackfill() tea.Cmd {
	sn := m.data
	if !sn.autoDue() || m.tried == sn.Stamp || m.fet.job != nil || m.ctx.Err() != nil {
		return nil
	}
	m.tried = sn.Stamp
	return m.jobBegin(jobBackfill, true)
}

// sinceOf is the since date the projects share, empty when they differ or have none.
// The dates a preview read from the files win over the snapshot, which may be older.
func (m *app) sinceOf(projects []string) string {
	var dates []string
	add := func(name, since string) {
		if since != "" && slices.Contains(projects, name) && !slices.Contains(dates, since) {
			dates = append(dates, since)
		}
	}
	if m.sinces != nil {
		for name, since := range m.sinces {
			add(name, since)
		}
	} else if m.data != nil {
		for _, p := range m.data.Projects {
			add(p.Name, p.Since)
		}
	}
	if len(dates) == 1 {
		return dates[0]
	}
	return ""
}

// revalWords is what a revalidation did or would do, in words:
// "shop: 4 new, 11 closed by since 2024-01-01, 2 reopened". extra counts
// findings created by the items a back-fill fetched.
func (m *app) revalWords(rv pipeline.Revalidation, extra int) string {
	var parts []string
	if n := rv.NewFindings + extra; n > 0 {
		parts = append(parts, fmt.Sprintf("%d new", n))
	}
	if rv.Closed > 0 {
		s := fmt.Sprintf("%d closed by since", rv.Closed)
		if d := m.sinceOf(rv.Projects); d != "" {
			s += " " + d
		}
		parts = append(parts, s)
	}
	if rv.Reopened > 0 {
		parts = append(parts, fmt.Sprintf("%d reopened", rv.Reopened))
	}
	if rv.Reconciled > 0 {
		parts = append(parts, fmt.Sprintf("%d rechecked", rv.Reconciled))
	}
	if len(parts) == 0 {
		parts = append(parts, "no finding changed")
	}
	return revalWho(rv.Projects) + ": " + strings.Join(parts, ", ")
}

func revalWho(projects []string) string {
	switch n := len(projects); {
	case n == 0:
		return "findings"
	case n > 3:
		return fmt.Sprintf("%d projects", n)
	}
	return strings.Join(projects, ", ")
}

// backfillDone ends the job that judged the findings again and fetched what
// the change needs. It reports like fetchDone: a busy store is tried again by
// the next re-read, a cancel is silent.
func (m *app) backfillDone(msg fetchDoneMsg) tea.Cmd {
	m.stl.invalidate()
	defer func() { m.sinces = nil }()
	switch {
	case errors.Is(msg.err, ErrBusy):
		m.tried = ""
		m.note("the data is in use by another cvewatch; revalidation will try again")
		return nil
	case msg.err != nil && (m.ctx.Err() != nil || errors.Is(msg.err, context.Canceled)):
		return nil
	case msg.err != nil:
		m.fail("revalidation failed: " + msg.err.Error())
		return m.refresh(reList | reDetail)
	}
	m.fet.failed = msg.res.Failed
	rv := msg.res.Revalidation
	if rv == nil {
		rv = &pipeline.Revalidation{}
	}
	quiet := msg.job.auto && rv.NewFindings+rv.Closed+rv.Reopened+rv.Reconciled+msg.res.Findings == 0 && len(msg.res.Backfilled) == 0 && len(msg.res.Failed) == 0
	if quiet { // nothing to report of a run nobody asked for
		return m.refresh(reList | reDetail)
	}
	note := "revalidated " + m.revalWords(*rv, msg.res.Findings)
	if n := len(msg.res.Backfilled); n > 0 {
		note += ", back-filled " + strings.Join(msg.res.Backfilled, ", ")
	}
	if n := len(msg.res.Failed); n > 0 {
		note += ", " + plural(n, "source", "sources") + " failed"
	}
	m.say(note)
	return m.refresh(reList | reDetail)
}

// ---- V: revalidate now ----

type revalPreviewMsg struct {
	rv     pipeline.Revalidation
	st     ops.Staleness
	sinces map[string]string // the since date of each project as the files have it now
	err    error
}

func revalPreviewCmd(b Backend) tea.Cmd {
	return func() tea.Msg {
		var out revalPreviewMsg
		out.err = b.Read(func(s *ops.Session) (e error) {
			if out.rv, e = s.Revalidate(false); e != nil {
				return e
			}
			out.sinces = map[string]string{}
			for _, p := range s.Cfg.Projects {
				if !p.Since.IsZero() {
					out.sinces[p.Name] = p.Since.Format("2006-01-02")
				}
			}
			out.st, e = s.Stale()
			return e
		})
		return out
	}
}

// revalidateNow previews what judging the findings again would change.
func (m *app) revalidateNow() tea.Cmd {
	if j := m.fet.job; j != nil {
		if j.kind == jobBackfill {
			m.note("revalidating already; the header shows the progress")
		} else {
			m.note("a fetch is running; revalidate when it is done")
		}
		return nil
	}
	return m.start("checking...", "revalidate", 0, nil, revalPreviewCmd(m.b))
}

func (m *app) revalPreviewed(msg revalPreviewMsg) outcome {
	if msg.err != nil {
		return outcome{err: msg.err}
	}
	m.sinces = msg.sinces
	rv := msg.rv
	changes := rv.NewFindings + rv.Closed + rv.Reopened + rv.Reconciled
	owes := msg.st.Stale || len(msg.st.BackfillPending) > 0
	switch {
	case changes == 0 && !owes:
		return outcome{note: "nothing to revalidate"}
	case changes == 0: // only what the findings were judged against is out of date
		return outcome{then: m.jobBegin(jobBackfill, false)}
	}
	text := "Judging every stored record again against the current projects, technologies and since dates: " + m.revalWords(rv, 0) + "."
	if len(rv.Changes) > 0 {
		var ids []string
		for _, c := range rv.Changes[:min(len(rv.Changes), 4)] {
			ids = append(ids, c.Action+" "+c.ID)
		}
		text += " " + strings.Join(ids, ", ")
		if more := len(rv.Changes) - 4; more > 0 {
			text += fmt.Sprintf(" and %d more", more)
		}
		text += "."
	}
	if !rv.Backfill.IsZero() {
		text += " The sources then fetch back to " + day(rv.Backfill) + "."
	}
	m.nt = &notice{title: "Revalidate", text: text, yes: func(m *app) tea.Cmd { return m.jobBegin(jobBackfill, false) }, yesWord: "revalidate"}
	return outcome{}
}

func bindRevalidate() binding {
	return binding{keys: ks("V"), help: "revalidate now: judge the findings again after a preview (y or enter applies)", short: "revalidate", prio: 5,
		do: plain((*app).revalidateNow)}
}
