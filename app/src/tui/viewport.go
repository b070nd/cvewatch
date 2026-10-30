package tui

// viewport owns the cursor and visible window of a list or a scrolling text.
// A list highlights the row under the cursor; a text has no highlight and its
// cursor is the first visible line. Update feeds it rows (refit) and room
// (fit); drawing only reads window.
type viewport struct {
	n      int
	cur    int
	off    int // first visible row of a list
	room   int // rows that fit, as last given to fit
	lo     int // lowest cursor value; -1 for a list where no row can be selected
	scroll bool
	ids    func(i int) string // identity of row i, so the cursor can follow it
	key    string             // identity of the row under the cursor
}

func scrolling() viewport { return viewport{scroll: true} }

// moveKeys are the keys handle applies. The mode tables do not declare them;
// they describe them once with moveDisp and moveHelp.
var moveKeys = []string{"up", "k", "down", "j", "pgup", "pgdown", "home", "g", "end", "G"}

const (
	moveDisp = "up/down"
	moveHelp = "move; pgup/pgdn page, home/end first and last (k j g G work too)"
)

// at is the row under the cursor (the top line of a scrolling text). It is lo
// when there is no row to select.
func (v *viewport) at() int { return v.cur }

// id is the identity of the row under the cursor, "" without one.
func (v *viewport) id() string { return v.key }

func (v *viewport) hi() int {
	if v.scroll && v.room > 0 {
		return max(v.n-v.room, v.lo)
	}
	return max(v.n-1, v.lo)
}

func (v *viewport) page() int { return max(v.room-1, 1) }

func (v *viewport) remember() {
	v.key = ""
	if v.ids != nil && v.cur >= 0 && v.cur < v.n {
		v.key = v.ids(v.cur)
	}
}

// to puts the cursor on row i, or the nearest row there is.
func (v *viewport) to(i int) {
	v.cur = clamp(i, v.lo, v.hi())
	v.remember()
}

func (v *viewport) move(d int) { v.to(v.cur + d) }

// handle applies the standard movement keys and reports whether k was one.
func (v *viewport) handle(k string) bool {
	switch k {
	case "up", "k":
		v.move(-1)
	case "down", "j":
		v.move(1)
	case "pgup":
		v.move(-v.page())
	case "pgdown":
		v.move(v.page())
	case "home", "g":
		v.to(v.lo)
	case "end", "G":
		v.to(v.hi())
	default:
		return false
	}
	return true
}

// reset starts over on n rows with the cursor on the first.
func (v *viewport) reset(n int) {
	v.n, v.cur, v.off, v.key, v.ids = n, v.lo, 0, "", nil
	v.to(v.lo)
}

// refit takes a new row count after the rows changed. With ids the cursor
// follows the row it was on; without, or when that row is gone, it keeps its
// place as far as the rows allow.
func (v *viewport) refit(n int, ids func(i int) string) {
	prev := v.key
	v.n, v.ids = n, ids
	if ids != nil && prev != "" {
		for i := 0; i < n; i++ {
			if ids(i) == prev {
				v.cur = i
				break
			}
		}
	}
	v.to(v.cur)
}

// fit is told how many rows fit and brings the window and the cursor in line.
func (v *viewport) fit(room int) {
	v.room = max(room, 1)
	v.off, _ = v.window(v.room)
	v.to(v.cur)
}

// show scrolls a text so that line i is visible.
func (v *viewport) show(i int) {
	room := max(v.room, 1)
	switch {
	case i < v.cur:
		v.to(i)
	case i >= v.cur+room:
		v.to(i - room + 1)
	}
}

// window is the range of rows to draw in room rows. It is a function of the
// state: it moves the window the least that shows the cursor, but leaves
// the state alone.
func (v *viewport) window(room int) (start, end int) {
	room = max(room, 1)
	top := max(v.n-room, 0)
	if v.scroll {
		start = clamp(v.cur, 0, top)
	} else {
		start = v.off
		if v.cur < start {
			start = v.cur
		} else if v.cur >= start+room {
			start = v.cur - room + 1
		}
		start = clamp(start, 0, top)
	}
	return start, min(start+room, v.n)
}
