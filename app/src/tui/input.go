package tui

import (
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

// maxInput matches the longest answer the setup flow accepts.
const maxInput = 200

// input is a one-line text field: typing, cursor movement and the usual
// line-editing keys. It never lets control characters in.
type input struct {
	v   []rune
	pos int
}

func (in *input) set(s string) {
	in.v = []rune(clean(s))
	if len(in.v) > maxInput {
		in.v = in.v[:maxInput]
	}
	in.pos = len(in.v)
}

func (in *input) String() string { return string(in.v) }

func (in *input) insert(rs []rune) {
	for _, r := range rs {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || len(in.v) >= maxInput {
			continue
		}
		in.v = append(in.v, 0)
		copy(in.v[in.pos+1:], in.v[in.pos:])
		in.v[in.pos] = r
		in.pos++
	}
}

// key applies an editing key and reports whether the input used it.
func (in *input) key(k tea.KeyMsg) bool {
	switch k.Type {
	case tea.KeyRunes, tea.KeySpace:
		in.insert(k.Runes)
	case tea.KeyBackspace:
		if in.pos > 0 {
			in.v = append(in.v[:in.pos-1], in.v[in.pos:]...)
			in.pos--
		}
	case tea.KeyDelete:
		if in.pos < len(in.v) {
			in.v = append(in.v[:in.pos], in.v[in.pos+1:]...)
		}
	case tea.KeyLeft:
		in.pos = max(0, in.pos-1)
	case tea.KeyRight:
		in.pos = min(len(in.v), in.pos+1)
	case tea.KeyHome, tea.KeyCtrlA:
		in.pos = 0
	case tea.KeyEnd, tea.KeyCtrlE:
		in.pos = len(in.v)
	case tea.KeyCtrlU:
		in.v, in.pos = in.v[in.pos:], 0
	case tea.KeyCtrlK:
		in.v = in.v[:in.pos]
	case tea.KeyCtrlW:
		i := in.pos
		for i > 0 && in.v[i-1] == ' ' {
			i--
		}
		for i > 0 && in.v[i-1] != ' ' {
			i--
		}
		in.v = append(in.v[:i], in.v[in.pos:]...)
		in.pos = i
	default:
		return false
	}
	return true
}

// view draws the text with a visible cursor mark (a glyph, so it shows
// without colour), scrolled so the cursor stays inside w cells.
func (in *input) view(w int, focus bool) string {
	rs := in.v
	pos := in.pos
	room := max(w-1, 1)
	start := 0
	for start < pos && width(string(rs[start:pos])) > room {
		start++
	}
	rs = rs[start:]
	pos -= start
	var b strings.Builder
	b.WriteString(string(rs[:pos]))
	if focus {
		b.WriteString("▏")
	}
	b.WriteString(string(rs[pos:]))
	return trunc(b.String(), max(w, 1))
}
