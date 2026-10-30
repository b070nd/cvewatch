package tui

import (
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/projectflow"
)

const pathSep = string(filepath.Separator)

type folderBox struct {
	in      input
	vp      viewport // over entries; the cursor is -1 for none
	parent  string
	entries []discovery.Entry
	err     error
	own     string // what the typed text names, as a status line
}

func newFolderBox() *folderBox {
	b := &folderBox{vp: viewport{lo: -1}}
	b.refresh()
	return b
}

func (b *folderBox) text() string { return b.in.String() }

// sel is the highlighted entry, -1 for none.
func (b *folderBox) sel() int { return b.vp.at() }

func (b *folderBox) setText(s string) {
	b.in.set(s)
	b.refresh()
}

func (b *folderBox) refresh() {
	t := b.text()
	b.parent, b.entries, b.err = discovery.Suggest(t)
	b.vp.reset(len(b.entries))
	b.own = typedStatus(t)
	if b.own == "no such folder" && len(b.entries) > 0 {
		b.own = plural(len(b.entries), "folder matches", "folders match") // still typing a name
	}
}

func (b *folderBox) key(k tea.KeyMsg) {
	switch k.String() {
	case "tab":
		b.tab()
	case "shift+tab":
		b.setText(parentText(b.text()))
	case "up", "down", "pgup", "pgdown": // home, end and letters belong to the text
		b.vp.handle(k.String())
	default:
		if b.in.key(k) {
			b.refresh()
		}
	}
}

func (b *folderBox) tab() {
	t := b.text()
	if b.sel() >= 0 && b.sel() < len(b.entries) {
		b.setText(folderOf(t) + b.entries[b.sel()].Name + pathSep)
		return
	}
	if c := discovery.Complete(t, b.entries); c != t {
		b.setText(c)
	}
}

func (b *folderBox) chosen() string {
	if b.sel() >= 0 && b.sel() < len(b.entries) {
		return b.entries[b.sel()].Path
	}
	return strings.TrimSpace(b.text())
}

func (b *folderBox) status() string {
	if b.sel() >= 0 && b.sel() < len(b.entries) {
		return marksLine(b.entries[b.sel()].Marks)
	}
	return b.own
}

func folderOf(typed string) string {
	base := filepath.Base(typed)
	switch {
	case typed == "":
		return ""
	case typed == "~" || base == "." || base == "..":
		return typed + pathSep
	}
	return typed[:strings.LastIndex(typed, pathSep)+1]
}

func parentText(typed string) string {
	t := strings.TrimRight(typed, pathSep)
	i := strings.LastIndex(t, pathSep)
	switch {
	case typed == "" || t == ".":
		return ".." + pathSep
	case t == "":
		return pathSep
	case t == "~":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Dir(home) + pathSep
		}
		return typed
	case t[i+1:] == "..":
		return t + pathSep + ".." + pathSep
	}
	return t[:i+1]
}

func typedStatus(typed string) string {
	if strings.TrimSpace(typed) == "" {
		return ""
	}
	abs, err := projectflow.ResolveFolder(typed)
	if err != nil {
		switch msg := err.Error(); {
		case strings.HasPrefix(msg, "no such folder"):
			return "no such folder"
		case strings.Contains(msg, "is a file"):
			return "that is a file, not a folder"
		default:
			return oneLine(msg)
		}
	}
	var marks []string
	if _, es, err := discovery.Suggest(abs); err == nil {
		for _, e := range es {
			if e.Path == abs {
				marks = e.Marks
			}
		}
	}
	return marksLine(marks)
}

func marksLine(marks []string) string {
	if len(marks) == 0 {
		return "no lockfiles or manifests found here"
	}
	return "looks like a project: " + oneLine(strings.Join(marks, ", "))
}

// folderRows is how many suggestions the box shows on a terminal h rows high:
// up to ten while the page keeps three lines of its own, else the three that
// still fit (the prompt around them takes five lines).
func folderRows(h int) int {
	if rows := min(h-13, 10); rows >= 3 {
		return rows
	}
	return clamp(h-10, 0, 3)
}

func (b *folderBox) view(w, h int) []string {
	lines := []string{"> Folder: " + b.in.view(w-10, true), stMuted.Render(trunc("  "+b.status(), w))}
	rows := folderRows(h)
	if rows == 0 {
		return lines
	}
	if b.err != nil {
		return append(lines, stMuted.Render(trunc("  "+oneLine(b.err.Error()), w)))
	}
	head := "  no folders in " + oneLine(b.parent)
	if len(b.entries) > 0 {
		head = "  " + plural(len(b.entries), "folder", "folders") + " in " + oneLine(b.parent)
	}
	lines = append(lines, stMuted.Render(trunc(head, w)))
	start, end := b.vp.window(rows)
	nameW, marksW := 4, 0
	for _, e := range b.entries[start:end] {
		nameW = max(nameW, min(width(oneLine(e.Name)), w/3))
		marksW = max(marksW, width(oneLine(strings.Join(e.Marks, ", "))))
	}
	marksW = min(marksW, max(w-4-nameW-2-7-2, 8))
	for i := start; i < end; i++ {
		e := b.entries[i]
		name := pad(oneLine(e.Name), nameW)
		marks := pad(oneLine(strings.Join(e.Marks, ", ")), marksW)
		if i == b.sel() {
			tag := ""
			if e.Project {
				tag = "  project"
			}
			lines = append(lines, stSel.Render(pad("> "+name+"  "+marks+tag, w)))
			continue
		}
		line := "  " + name + "  " + stMuted.Render(marks)
		if e.Project {
			line += "  " + stGood.Render("project")
		}
		lines = append(lines, line)
	}
	return lines
}
