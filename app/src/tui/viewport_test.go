package tui

import "testing"

func list(n, room int) *viewport {
	v := &viewport{}
	v.refit(n, nil)
	v.fit(room)
	return v
}

func TestViewportMovesAndStopsAtTheEnds(t *testing.T) {
	v := list(30, 10)
	for _, c := range []struct {
		key  string
		want int
	}{{"down", 1}, {"j", 2}, {"up", 1}, {"k", 0}, {"up", 0}} {
		v.handle(c.key)
		if v.at() != c.want {
			t.Fatalf("after %q at %d, want %d", c.key, v.at(), c.want)
		}
	}
	for _, c := range []struct {
		key  string
		want int
	}{
		{"pgdown", 9}, // a page is the room minus one row, so one row stays in view
		{"pgdown", 18},
		{"end", 29},
		{"pgdown", 29},
		{"pgup", 20},
		{"home", 0},
		{"G", 29},
		{"g", 0},
		{"pgup", 0},
	} {
		if !v.handle(c.key) || v.at() != c.want {
			t.Fatalf("%s: at %d, want %d", c.key, v.at(), c.want)
		}
	}
	if v.handle("x") || v.handle("enter") || v.at() != 0 {
		t.Fatal("other keys are not for the viewport")
	}
}

func TestViewportWindowFollowsTheCursorWithoutWritingBack(t *testing.T) {
	v := list(30, 10)
	before := *v
	for _, cur := range []int{0, 9, 10, 25, 29} {
		v.cur = cur
		start, end := v.window(10)
		if cur < start || cur >= end || end-start != 10 {
			t.Fatalf("cursor %d outside the window %d..%d", cur, start, end)
		}
	}
	if v.n != before.n || v.off != before.off || v.room != before.room {
		t.Fatal("window changed the viewport")
	}

	// the window moves the least it must: going down, the cursor stays on the
	// last row; going back up, the window waits until the cursor leaves it
	v = list(30, 10)
	for range 15 {
		v.handle("down")
		v.fit(10)
	}
	if start, _ := v.window(10); start != 6 {
		t.Fatalf("cursor 15 at the bottom of the window, start %d", start)
	}
	for range 5 {
		v.handle("up")
		v.fit(10)
	}
	if start, _ := v.window(10); start != 6 {
		t.Fatalf("moving up inside the window must not scroll, start %d", start)
	}
	for range 5 {
		v.handle("up")
		v.fit(10)
	}
	if start, _ := v.window(10); start != 5 {
		t.Fatalf("cursor 5 above the window, start %d", start)
	}
}

func TestViewportWindowShortList(t *testing.T) {
	v := list(3, 10)
	v.handle("end")
	if s, e := v.window(10); s != 0 || e != 3 {
		t.Fatalf("window %d..%d", s, e)
	}
	v = list(0, 10)
	v.handle("down")
	v.handle("pgdown")
	if s, e := v.window(10); v.at() != 0 || s != 0 || e != 0 {
		t.Fatalf("empty: at %d window %d..%d", v.at(), s, e)
	}
	if s, e := list(5, 1).window(0); e-s != 1 {
		t.Fatalf("a window is at least one row: %d..%d", s, e)
	}
}

func TestViewportFollowsItsRowByIdentity(t *testing.T) {
	ids := func(rows []string) func(int) string { return func(i int) string { return rows[i] } }
	rows := []string{"a", "b", "c", "d", "e"}
	v := &viewport{}
	v.refit(len(rows), ids(rows))
	v.handle("down")
	v.handle("down")
	if v.id() != "c" {
		t.Fatalf("id %q", v.id())
	}

	rows = []string{"x", "a", "b", "c", "e"} // rows came in before it
	v.refit(len(rows), ids(rows))
	if v.at() != 3 || v.id() != "c" {
		t.Fatalf("at %d id %q: the cursor must follow c", v.at(), v.id())
	}

	rows = []string{"x", "a"} // its row is gone: stay near, inside the list
	v.refit(len(rows), ids(rows))
	if v.at() != 1 || v.id() != "a" {
		t.Fatalf("at %d id %q", v.at(), v.id())
	}

	v.refit(0, ids(nil))
	if v.at() != 0 || v.id() != "" {
		t.Fatalf("empty: at %d id %q", v.at(), v.id())
	}
	rows = []string{"p", "q"}
	v.refit(len(rows), ids(rows))
	if v.at() != 0 || v.id() != "p" {
		t.Fatalf("rows came back: at %d id %q", v.at(), v.id())
	}
}

func TestViewportMovingUpdatesTheIdentity(t *testing.T) {
	rows := []string{"a", "b", "c"}
	v := &viewport{}
	v.refit(3, func(i int) string { return rows[i] })
	v.handle("end")
	if v.id() != "c" {
		t.Fatalf("id %q", v.id())
	}
	v.reset(3)
	if v.at() != 0 || v.id() != "" {
		t.Fatalf("reset: at %d id %q", v.at(), v.id())
	}
}

func TestViewportWithNoSelection(t *testing.T) {
	v := &viewport{lo: -1}
	v.reset(4)
	if v.at() != -1 {
		t.Fatalf("starts on nothing, at %d", v.at())
	}
	v.handle("down")
	v.handle("down")
	if v.at() != 1 {
		t.Fatalf("at %d", v.at())
	}
	v.handle("up")
	v.handle("up")
	v.handle("up")
	if v.at() != -1 {
		t.Fatalf("up from the first row leaves nothing selected, at %d", v.at())
	}
	for range 10 {
		v.handle("down")
	}
	if v.at() != 3 {
		t.Fatalf("at %d", v.at())
	}
	v.reset(0)
	v.handle("down")
	if v.at() != -1 {
		t.Fatalf("no rows: at %d", v.at())
	}
	if s, e := v.window(3); s != 0 || e != 0 {
		t.Fatalf("window %d..%d", s, e)
	}
}

func TestViewportScrollingText(t *testing.T) {
	v := scrolling()
	v.refit(50, nil)
	v.fit(10)
	for _, c := range []struct {
		key        string
		start, end int
	}{
		{"down", 1, 11},
		{"pgdown", 10, 20},
		{"end", 40, 50},
		{"down", 40, 50},
		{"pgup", 31, 41},
		{"k", 30, 40},
		{"home", 0, 10},
		{"G", 40, 50},
		{"g", 0, 10},
	} {
		v.handle(c.key)
		if s, e := v.window(10); s != c.start || e != c.end {
			t.Fatalf("%s: window %d..%d, want %d..%d", c.key, s, e, c.start, c.end)
		}
	}

	v.handle("end")
	v.refit(25, nil) // the text got shorter
	v.fit(10)
	if s, e := v.window(10); s != 15 || e != 25 {
		t.Fatalf("shorter text: window %d..%d", s, e)
	}
	v.fit(40) // and the screen taller than the text
	if s, e := v.window(40); s != 0 || e != 25 || v.at() != 0 {
		t.Fatalf("tall screen: window %d..%d at %d", s, e, v.at())
	}
}

func TestViewportShowScrollsOnlyWhenTheLineIsOutside(t *testing.T) {
	v := scrolling()
	v.refit(50, nil)
	v.fit(10)
	v.show(5)
	if v.at() != 0 {
		t.Fatalf("line 5 is in view, at %d", v.at())
	}
	v.show(25)
	if s, _ := v.window(10); s != 16 {
		t.Fatalf("line 25 at the bottom, start %d", s)
	}
	v.show(3)
	if s, _ := v.window(10); s != 3 {
		t.Fatalf("line 3 at the top, start %d", s)
	}
}

func TestViewportFitKeepsTheCursorInTheWindow(t *testing.T) {
	v := list(30, 10)
	v.handle("end")
	v.fit(10)
	v.fit(4) // the terminal got smaller
	if s, e := v.window(4); v.at() < s || v.at() >= e {
		t.Fatalf("cursor %d outside %d..%d", v.at(), s, e)
	}
	if v.page() != 3 {
		t.Fatalf("page %d", v.page())
	}
	for _, n := range []int{0, 1, 2} {
		w := list(5, n)
		w.handle("pgdown")
		if w.at() == 0 {
			t.Fatalf("room %d: a page is at least one row", n)
		}
	}
}
