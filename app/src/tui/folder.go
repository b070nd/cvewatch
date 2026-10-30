package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/projectflow"
)

const pathSep = string(filepath.Separator)

// maxFileRows bounds the files the box lists next to the folders.
const maxFileRows = 100

type boxKind int

const (
	boxSource   boxKind = iota // a folder, or a file a project is proposed from
	boxLockfile                // a lockfile
)

type folderBox struct {
	in      input
	vp      viewport // over entries; the cursor is -1 for none
	parent  string
	entries []discovery.Entry
	err     error
	own     string // what the typed text names, as a status line

	kind  boxKind
	label string
	files map[string]bool // the entries that are files, by path
}

func newFolderBox() *folderBox { return newBox(boxSource, "Folder") }

func newBox(kind boxKind, label string) *folderBox {
	b := &folderBox{vp: viewport{lo: -1}, kind: kind, label: label}
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
	b.addFiles(t)
	b.vp.reset(len(b.entries))
	b.own = b.typedStatus(t)
	if strings.HasPrefix(b.own, "no such") && len(b.entries) > 0 { // still typing a name
		if len(b.files) > 0 {
			b.own = plural(len(b.entries), "entry matches", "entries match")
		} else {
			b.own = plural(len(b.entries), "folder matches", "folders match")
		}
	}
}

func (b *folderBox) takes(name string) bool {
	if b.kind == boxLockfile {
		_, ok := matrix.DetectType(name)
		return ok
	}
	return discovery.SupportedFile(name)
}

// addFiles puts the files the box accepts after the folders Suggest listed.
func (b *folderBox) addFiles(typed string) {
	b.files = map[string]bool{}
	if b.err != nil {
		return
	}
	children, err := os.ReadDir(b.parent)
	if err != nil {
		return
	}
	prefix := ""
	if f := folderOf(typed); strings.HasPrefix(typed, f) {
		prefix = typed[len(f):]
	}
	var files []discovery.Entry
	for _, d := range children {
		name := d.Name()
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(prefix, ".") || !strings.Contains(strings.ToLower(name), strings.ToLower(prefix)) || !b.takes(name) {
			continue
		}
		if path := filepath.Join(b.parent, name); isFile(path, d) {
			files = append(files, discovery.Entry{Path: path, Name: name, Marks: []string{fileKind(name)}})
		}
	}
	slices.SortStableFunc(files, func(x, y discovery.Entry) int {
		px, py := strings.HasPrefix(strings.ToLower(x.Name), strings.ToLower(prefix)), strings.HasPrefix(strings.ToLower(y.Name), strings.ToLower(prefix))
		if px != py {
			if px {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	for _, e := range files[:min(len(files), maxFileRows)] {
		b.files[e.Path] = true
		b.entries = append(b.entries, e)
	}
}

func isFile(path string, d os.DirEntry) bool {
	if d.Type()&os.ModeSymlink != 0 {
		fi, err := os.Stat(path)
		return err == nil && fi.Mode().IsRegular()
	}
	return d.Type().IsRegular()
}

// fileKind says what a file a project can be proposed from is, from its name.
func fileKind(name string) string {
	low := strings.ToLower(filepath.Base(name))
	if t, ok := matrix.DetectType(low); ok {
		return t + " lockfile"
	}
	switch {
	case strings.Contains(low, "dockerfile") || strings.Contains(low, "containerfile"):
		return "Dockerfile"
	case strings.HasSuffix(low, ".tf"):
		return "Terraform file"
	case strings.Contains(low, "compose"):
		return "compose file"
	}
	return "YAML manifest"
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
		b.setText(folderOf(t) + b.entries[b.sel()].Name + b.tail(b.entries[b.sel()]))
		return
	}
	if len(b.entries) == 1 && b.files[b.entries[0].Path] {
		b.setText(folderOf(t) + b.entries[0].Name)
		return
	}
	if c := discovery.Complete(t, b.entries); c != t {
		b.setText(c)
	}
}

// tail ends a completed name: a folder is opened, a file is done.
func (b *folderBox) tail(e discovery.Entry) string {
	if b.files[e.Path] {
		return ""
	}
	return pathSep
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

func (b *folderBox) typedStatus(typed string) string {
	if strings.TrimSpace(typed) == "" {
		return ""
	}
	if b.kind == boxLockfile {
		return lockStatus(typed)
	}
	src, err := projectflow.ResolveSource(typed)
	if err != nil {
		switch msg := err.Error(); {
		case strings.HasPrefix(msg, "no such folder"):
			return "no such folder or file"
		case strings.Contains(msg, "is a file"):
			return "that is a file, not a folder, and not a Dockerfile, compose file, Kubernetes manifest, Terraform file or lockfile"
		default:
			return oneLine(msg)
		}
	}
	if src.IsFile() {
		return "a " + fileKind(src.Path) + ": a project is proposed from this file alone"
	}
	var marks []string
	if _, es, err := discovery.Suggest(src.Path); err == nil {
		for _, e := range es {
			if e.Path == src.Path {
				marks = e.Marks
			}
		}
	}
	return marksLine(marks)
}

// expandTyped makes a typed path absolute, ~ expanded.
func expandTyped(typed string) (string, error) {
	p := strings.TrimSpace(typed)
	if p == "~" || strings.HasPrefix(p, "~"+pathSep) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, p[1:])
	}
	return filepath.Abs(p)
}

func lockStatus(typed string) string {
	abs, err := expandTyped(typed)
	if err != nil {
		return oneLine(err.Error())
	}
	fi, err := os.Stat(abs)
	switch {
	case err != nil:
		return "no such file"
	case fi.IsDir():
		return "that is a folder: tab opens it, then pick a lockfile"
	}
	if t, ok := matrix.DetectType(filepath.Base(abs)); ok {
		return "a " + t + " lockfile"
	}
	return "the type is not known from the name: you are asked for it"
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
	lw := width(b.label) + 4
	lines := []string{"> " + b.label + ": " + b.in.view(w-lw, true), stMuted.Render(trunc("  "+b.status(), w))}
	rows := folderRows(h)
	if rows == 0 {
		return lines
	}
	if b.err != nil {
		return append(lines, stMuted.Render(trunc("  "+oneLine(b.err.Error()), w)))
	}
	head := "  no folders in " + oneLine(b.parent)
	switch folders, files := len(b.entries)-len(b.files), len(b.files); {
	case files > 0 && folders > 0:
		head = "  " + plural(folders, "folder", "folders") + ", " + plural(files, "file", "files") + " in " + oneLine(b.parent)
	case files > 0:
		head = "  " + plural(files, "file", "files") + " in " + oneLine(b.parent)
	case folders > 0:
		head = "  " + plural(folders, "folder", "folders") + " in " + oneLine(b.parent)
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
			if b.files[e.Path] {
				tag = "  file"
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
