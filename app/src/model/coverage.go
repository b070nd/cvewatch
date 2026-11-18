package model

import "time"

// A source's coverage is the part of history its fetches reached and where
// the next one starts. FeedState holds it, and these methods are the only
// arithmetic on it: the window a fetch asks for, a finished fetch, a stopped
// one, and a back-fill a change of the configuration owes.

// Window is where the next fetch starts and whether that is an owed back-fill
// reaching further back than the last run. A first fetch reaches lookback back.
func (st FeedState) Window(now time.Time, lookback time.Duration) (since time.Time, backfill bool) {
	since = st.LastRun
	if since.IsZero() {
		since = now.Add(-lookback)
	}
	if !st.Backfill.IsZero() && st.Backfill.Before(since) {
		return st.Backfill, true
	}
	return since, false
}

// Fetched is the state after a fetch of the window from `from` succeeded:
// it ran now, a back-fill it owed is paid, and covered reaches the earlier
// of from and what was covered before.
func (st FeedState) Fetched(v Validators, from, now time.Time) FeedState {
	covered := from
	if !st.Covered.IsZero() && st.Covered.Before(covered) {
		covered = st.Covered
	}
	return FeedState{Validators: v, LastRun: now, Covered: covered}
}

// Stopped is the state after a fetch of the window from `from` stopped with
// the windows before resume finished: the next fetch goes on at resume. A
// back-fill that is not reached yet stays owed from resume on.
func (st FeedState) Stopped(from, resume time.Time) FeedState {
	if !st.Backfill.IsZero() && resume.Before(st.LastRun) {
		st.Backfill = resume
	} else {
		st.LastRun, st.Backfill = resume, time.Time{}
	}
	if st.Covered.IsZero() || from.Before(st.Covered) && !resume.Before(st.Covered) {
		st.Covered = from
	}
	return st
}

// Owe marks that the next fetch must reach back to from, unless the source
// already covered it. It reports whether the source owes the back-fill.
func (st *FeedState) Owe(from time.Time) bool {
	if from.IsZero() || !st.Covered.IsZero() && !from.Before(st.Covered) {
		return false
	}
	if st.Backfill.IsZero() || from.Before(st.Backfill) {
		st.Backfill = from
	}
	return true
}

// Owes reports whether a back-fill is pending.
func (st FeedState) Owes() bool { return !st.Backfill.IsZero() }
