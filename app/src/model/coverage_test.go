package model

import (
	"testing"
	"time"
)

func TestCoverageOfASourceAcrossFetches(t *testing.T) {
	now := day
	week := 7 * 24 * time.Hour
	var st FeedState
	if since, back := st.Window(now, week); !since.Equal(now.Add(-week)) || back {
		t.Fatalf("first fetch reaches the lookback: %v %v", since, back)
	}
	st = st.Fetched(Validators{ETag: "x"}, now.Add(-week), now)
	if !st.LastRun.Equal(now) || !st.Covered.Equal(now.Add(-week)) || st.Validators.ETag != "x" {
		t.Fatalf("fetched: %+v", st)
	}

	// a change needs history back to January: owed, and the next window reaches it
	jan := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !st.Owe(jan) || !st.Owes() {
		t.Fatalf("owed: %+v", st)
	}
	if since, back := st.Window(now.Add(time.Hour), week); !since.Equal(jan) || !back {
		t.Fatalf("back-fill window: %v %v", since, back)
	}
	// it stops in March: the rest stays owed from there
	mar := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	st = st.Stopped(jan, mar)
	if !st.Backfill.Equal(mar) || !st.LastRun.Equal(now) || !st.Covered.Equal(now.Add(-week)) {
		t.Fatalf("stopped: %+v", st)
	}
	// it finishes: paid, and covered reaches January
	st = st.Fetched(Validators{}, jan, now.Add(2*time.Hour))
	if st.Owes() || !st.Covered.Equal(jan) {
		t.Fatalf("finished: %+v", st)
	}
	// what is covered is never owed again
	if st.Owe(mar) || st.Owes() {
		t.Fatalf("covered is not owed: %+v", st)
	}
}

func TestAStoppedRunWithoutABackfillResumesWhereItStopped(t *testing.T) {
	st := FeedState{LastRun: day.Add(-time.Hour)}
	resume := day.Add(-30 * time.Minute)
	st = st.Stopped(day.Add(-time.Hour), resume)
	if !st.LastRun.Equal(resume) || st.Owes() {
		t.Fatalf("%+v", st)
	}
}
