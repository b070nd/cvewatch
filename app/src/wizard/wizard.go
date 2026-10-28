// Package wizard is the plain prompt front end of the setup flow. It works on
// any terminal, over ssh, in a container and with piped input. It is a thin
// adapter: it prints a setup.Step, reads one line and hands it to Flow.Answer.
// Every rule (order, defaults, validation, edits) lives in package setup.
package wizard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/setup"
)

// IO is where the wizard reads answers and writes questions.
type IO struct {
	In  io.Reader
	Out io.Writer
}

// maxRejected is how many wrong answers in a row end the wizard, so piped
// input that never fits cannot loop forever.
const maxRejected = 5

var (
	errQuit     = errors.New("quit")
	errEOF      = errors.New("input ended")
	errTooMany  = fmt.Errorf("%d rejected answers in a row", maxRejected)
	errNoSource = errors.New("no input to read from")
)

// wiz holds the one buffered reader and the output of a run.
type wiz struct {
	in  *bufio.Reader
	out io.Writer
}

func newWiz(io IO) (*wiz, error) {
	if io.In == nil || io.Out == nil {
		return nil, errNoSource
	}
	return &wiz{in: bufio.NewReader(io.In), out: io.Out}, nil
}

// Setup walks the user through creating a project from a folder (dir may be
// empty to start from scratch) or editing an existing one (existing != ""),
// shows the diff and the issues, asks to confirm inside the flow's own review
// step and saves with sess.EditProject.
func Setup(io IO, sess *ops.Session, dir, existing string) error {
	w, err := newWiz(io)
	if err != nil {
		return err
	}
	if err := w.setup(sess, dir, existing); err != nil && !errors.Is(err, errQuit) {
		return err
	}
	return nil
}

// Menu lists the projects and offers: new from a folder, edit a project, quit.
// It loops until the user quits. End of input at this menu counts as quit.
func Menu(io IO, sess *ops.Session) error {
	w, err := newWiz(io)
	if err != nil {
		return err
	}
	for {
		names, err := sess.ProjectNames()
		if err != nil {
			return err
		}
		help := "No projects yet."
		if len(names) > 0 {
			help = "Projects: " + strings.Join(names, ", ")
		}
		opts := []setup.Option{{Value: "new", Label: "New project from a folder"}}
		if len(names) > 0 {
			opts = append(opts, setup.Option{Value: "edit", Label: "Edit a project"})
		}
		opts = append(opts, setup.Option{Value: "quit", Label: "Quit"})
		choice, err := w.pick(setup.Step{Title: "cvewatch projects", Help: help, Kind: setup.KindChoice, Options: opts}, true)
		if errors.Is(err, errEOF) {
			w.printf("\n")
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "quit":
			return nil
		case "new":
			err = w.newProject(sess)
		case "edit":
			err = w.editProject(sess, names)
		}
		switch {
		case err == nil, errors.Is(err, errQuit):
		case errors.Is(err, errEOF), errors.Is(err, errTooMany):
			return err
		default:
			w.printf("  ! %s\n", clean(err.Error())) // a failed project does not end the menu
		}
	}
}

func (w *wiz) newProject(sess *ops.Session) error {
	dir, err := w.pick(setup.Step{Title: "Folder to scan", Kind: setup.KindText,
		Help: "Path of a repository or project folder. Empty starts from scratch."}, false)
	if err != nil {
		return err
	}
	return w.setup(sess, dir, "")
}

func (w *wiz) editProject(sess *ops.Session, names []string) error {
	var opts []setup.Option
	for _, n := range names {
		opts = append(opts, setup.Option{Value: n, Label: n})
	}
	name, err := w.pick(setup.Step{Title: "Which project?", Kind: setup.KindChoice, Options: opts}, false)
	if err != nil {
		return err
	}
	return w.setup(sess, "", name)
}

// pick asks one question outside a flow and returns the validated answer.
// At the top menu quit returns "quit" and back is ignored; in a sub-question
// both return to the menu as errQuit.
func (w *wiz) pick(st setup.Step, top bool) (string, error) {
	w.show(st)
	for bad := 0; ; {
		val, cmd, err := w.read(st, func() { w.show(st) })
		switch {
		case err != nil:
			return "", err
		case cmd == "quit" && top:
			return "quit", nil
		case cmd == "back" && top:
			continue
		case cmd != "":
			return "", errQuit
		case st.Kind != setup.KindChoice || hasValue(st.Options, val):
			return val, nil
		}
		w.printf("  ! choose one of the numbers above\n")
		if bad++; bad >= maxRejected {
			return "", errTooMany
		}
	}
}

func hasValue(opts []setup.Option, v string) bool {
	return slices.ContainsFunc(opts, func(o setup.Option) bool { return strings.EqualFold(o.Value, v) })
}

// setup builds the flow for one project and drives it to a save.
func (w *wiz) setup(sess *ops.Session, dir, existing string) error {
	cat := sess.Cfg.Catalog
	var cur *model.Project
	var src []byte
	if existing != "" {
		names, err := sess.ProjectNames() // scoped to what the actor may see
		if err != nil {
			return err
		}
		path, err := projectfile.Path(projectsDir(sess), existing)
		if err != nil || !slices.Contains(names, existing) {
			return fmt.Errorf("unknown project %q", existing)
		}
		if src, err = os.ReadFile(path); err != nil {
			return err
		}
		file, err := projectfile.Parse(src)
		if err != nil {
			return err
		}
		p := file.Project()
		cur = &p
	}
	f := setup.NewFlow(cat, cur)
	f.SetExistingBytes(src)
	f.NameTaken = func(n string) bool {
		names, _ := sess.ProjectNames()
		return slices.Contains(names, n)
	}
	if dir != "" {
		res, err := discovery.Scan(dir, cat, discovery.Options{})
		if err != nil {
			return err
		}
		f.UseDiscovery(res.Root, res)
	}

	w.printf("Type back for the previous question, ? for help, quit to stop without saving.\n")
	review := func(st setup.Step) setup.Step {
		if st.ID == "review" {
			st.Help = reviewText(sess, f, st.Help)
		}
		return st
	}
	if err := w.drive(f, review); err != nil {
		return err
	}
	return w.save(sess, f)
}

// drive asks the flow's steps until it is done. adjust may rewrite a step
// just before it is shown (used to show the real diff on the review step).
func (w *wiz) drive(f *setup.Flow, adjust func(setup.Step) setup.Step) error {
	show, bad := true, 0
	for !f.Done() {
		st := f.Current()
		again := func() { w.show(adjust(st)) }
		if show {
			again()
		}
		val, cmd, err := w.read(st, again)
		switch {
		case err != nil:
			return err
		case cmd == "quit":
			w.printf("nothing was changed\n")
			return errQuit
		case cmd == "back":
			f.Back()
			show, bad = true, 0
			continue
		}
		if err := f.Answer(val); err != nil {
			w.printf("  ! %s\n", clean(err.Error()))
			if p := f.Current().Problem; p != "" && p != err.Error() {
				w.printf("  ! %s\n", clean(p))
			}
			if bad++; bad >= maxRejected {
				return errTooMany
			}
			show = false
			continue
		}
		show, bad = true, 0
	}
	return nil
}

// reviewText is the help of the review step: the diff and the issues of the
// change as it would be saved (lockfile paths relative to the root).
func reviewText(sess *ops.Session, f *setup.Flow, fallback string) string {
	p, err := sess.EditProject(ops.ProjectChange{Project: f.Draft().Project.Name, Ops: relOps(sess, f.Ops())})
	if err != nil {
		return fallback + "\n! " + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Changes to %s:\n%s", relPath(sess, p.Path), p.Diff)
	for _, is := range p.Issues {
		fmt.Fprintf(&b, "\n%s: %s: %s", is.Level, is.Field, is.Message)
	}
	if p.Blocked() {
		b.WriteString("\nThis cannot be saved until the errors are fixed: answer no to go back.")
	}
	return b.String()
}

// save writes the confirmed change.
func (w *wiz) save(sess *ops.Session, f *setup.Flow) error {
	p, err := sess.EditProject(ops.ProjectChange{Project: f.Draft().Project.Name, Ops: relOps(sess, f.Ops()), Save: true})
	if err != nil {
		for _, is := range p.Issues {
			w.printf("  %s: %s: %s\n", is.Level, is.Field, clean(is.Message))
		}
		return err
	}
	if !p.Saved {
		w.printf("\nnothing to save: %s already matches\n", clean(relPath(sess, p.Path)))
		return nil
	}
	w.printf("\nsaved %s\n\nNext steps:\n  cvewatch doctor   check the setup\n  cvewatch update   fetch advisories and match them to the project\n",
		clean(relPath(sess, p.Path)))
	return nil
}

// relOps makes the lockfiles being added relative to the config root, so the
// config keeps working when it is moved or mounted elsewhere.
func relOps(sess *ops.Session, in []projectfile.Op) []projectfile.Op {
	root := realPath(sess.Cfg.Root)
	out := slices.Clone(in)
	for i, op := range out {
		if op.Kind != "add_lockfile" || !filepath.IsAbs(op.Lockfile.Path) {
			continue
		}
		if rel, err := filepath.Rel(root, realPath(op.Lockfile.Path)); err == nil {
			out[i].Lockfile.Path = filepath.ToSlash(rel)
		}
	}
	return out
}

// realPath resolves symlinks (a temp dir may be one) so paths compare equal.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func projectsDir(sess *ops.Session) string { return filepath.Join(sess.Cfg.Root, "config", "projects") }

func relPath(sess *ops.Session, p string) string {
	if rel, err := filepath.Rel(sess.Cfg.Root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return p
}

// ---- terminal ----

func (w *wiz) printf(format string, a ...any) { fmt.Fprintf(w.out, format, a...) }

// show prints a step: title, help and the numbered options.
func (w *wiz) show(st setup.Step) {
	w.printf("\n%s\n", clean(st.Title))
	if st.Help != "" {
		w.printf("%s\n", clean(st.Help))
	}
	for i, o := range st.Options {
		label := o.Label
		if label == "" {
			label = o.Value
		}
		mark := ""
		if st.Kind == setup.KindMulti {
			mark = "[ ] "
			if o.Selected {
				mark = "[x] "
			}
		}
		w.printf("%3d. %s%s\n", i+1, mark, clean(label))
		if o.Detail != "" {
			w.printf("       %s\n", clean(o.Detail))
		}
	}
}

// read prompts for one line. It answers ? by calling again and returns the
// command (back or quit) or the answer translated to what the flow expects.
func (w *wiz) read(st setup.Step, again func()) (val, cmd string, err error) {
	for {
		w.printf("%s", prompt(st))
		line, err := w.in.ReadString('\n')
		if err != nil && (err != io.EOF || line == "") {
			if err == io.EOF {
				err = errEOF
			}
			return "", "", err
		}
		line = strings.TrimSpace(line)
		switch c := strings.ToLower(line); c {
		case "back", "quit":
			return "", c, nil
		case "?":
			again()
			continue
		}
		return translate(st, line), "", nil
	}
}

func prompt(st setup.Step) string {
	def := clean(st.Default)
	switch st.Kind {
	case setup.KindChoice:
		if def != "" {
			return fmt.Sprintf("Choose 1-%d [%s]: ", len(st.Options), def)
		}
		return fmt.Sprintf("Choose 1-%d: ", len(st.Options))
	case setup.KindMulti:
		var sel []string
		for i, o := range st.Options {
			if o.Selected {
				sel = append(sel, fmt.Sprint(i+1))
			}
		}
		cur := "none"
		if len(sel) > 0 {
			cur = strings.Join(sel, ",")
		}
		return fmt.Sprintf("Numbers, all or none [%s]: ", cur)
	case setup.KindConfirm:
		if def != "" {
			return fmt.Sprintf("yes or no [%s]: ", def)
		}
		return "yes or no: "
	}
	if def != "" {
		return fmt.Sprintf("Answer [%s] (- for empty): ", def)
	}
	return "Answer: "
}

// translate maps what was typed to the value the flow expects.
func translate(st setup.Step, line string) string {
	number := func(s string) (string, bool) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > len(st.Options) {
			return "", false
		}
		return st.Options[n-1].Value, true
	}
	switch st.Kind {
	case setup.KindChoice:
		if v, ok := number(line); ok {
			return v
		}
	case setup.KindMulti:
		var out []string
		for _, o := range st.Options {
			if line == "" && o.Selected {
				out = append(out, o.Value) // empty keeps the current selection
			}
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
			switch v, ok := number(tok); {
			case ok:
				out = append(out, v)
			case strings.EqualFold(tok, "all"):
				for _, o := range st.Options {
					out = append(out, o.Value)
				}
			case strings.EqualFold(tok, "none"):
			default:
				out = append(out, tok)
			}
		}
		return strings.Join(out, ",")
	case setup.KindConfirm:
		switch strings.ToLower(line) {
		case "y", "yes":
			return "yes"
		case "n", "no":
			return "no"
		}
	case setup.KindText:
		switch {
		case line == "":
			return st.Default
		case line == "-" && st.Default != "":
			return ""
		}
	}
	return line
}

// clean makes untrusted text safe to print: control characters (so no escape
// sequences), invisible format characters and bad UTF-8 are dropped. Newlines
// stay because help texts are multi-line.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp), r == unicode.ReplacementChar:
			return -1
		}
		return r
	}, s)
}
