package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/report"
	"github.com/b070nd/cvewatch/app/src/store"
)

// LifecycleVerb is what happens to a whole project, as opposed to an edit of
// what the project file holds.
type LifecycleVerb string

const (
	VerbRename    LifecycleVerb = "rename"
	VerbDuplicate LifecycleVerb = "duplicate"
	VerbDelete    LifecycleVerb = "delete"
	VerbDisable   LifecycleVerb = "disable"
	VerbEnable    LifecycleVerb = "enable"
)

// LifecycleVerbs lists the verbs, for front ends that build menus or schemas.
var LifecycleVerbs = []LifecycleVerb{VerbRename, VerbDuplicate, VerbDisable, VerbEnable, VerbDelete}

// ErrConfirm means the change is destructive and was not confirmed.
var ErrConfirm = errors.New("this change needs confirmation")

// LifecycleRequest asks for one lifecycle change. Without Apply it is only
// previewed. A destructive change (see LifecyclePreview.RequiresConfirm) is
// applied only with Confirm, which a front end sets after showing the preview.
type LifecycleRequest struct {
	Verb    LifecycleVerb `json:"verb"`
	Project string        `json:"project"`
	NewName string        `json:"new_name,omitempty"` // rename and duplicate
	// CloseFindings (delete only) marks the project's open findings ignored with
	// a note. Without it they stay as they are, like findings of any project
	// that is no longer configured.
	CloseFindings bool `json:"close_findings,omitempty"`
	Apply         bool `json:"apply,omitempty"`
	Confirm       bool `json:"confirm,omitempty"`
}

// LifecyclePreview is what a request does, computed without touching anything.
type LifecyclePreview struct {
	Verb            LifecycleVerb  `json:"verb"`
	Project         string         `json:"project"`
	NewName         string         `json:"new_name,omitempty"`
	Findings        FindingCounts  `json:"findings"`
	Access          []AccessChange `json:"access,omitempty"`
	Files           []FileChange   `json:"files"`
	Warnings        []string       `json:"warnings,omitempty"`
	Destructive     bool           `json:"destructive"`
	RequiresConfirm bool           `json:"requires_confirm"`
	Applied         bool           `json:"applied"`
	Backup          string         `json:"backup,omitempty"` // where the old project file went, once applied
}

// FindingCounts says how many findings the project has, by status.
type FindingCounts struct {
	Total    int                  `json:"total"`
	ByStatus map[model.Status]int `json:"by_status,omitempty"`
}

// AccessChange is one actor's access rule that the change rewrites.
type AccessChange struct {
	Actor  string   `json:"actor"`
	Action string   `json:"action"`         // rename | remove
	Left   []string `json:"left,omitempty"` // projects the actor keeps afterwards
}

// FileChange is a file the change creates, moves, rewrites or backs up.
type FileChange struct {
	Action string `json:"action"` // create | rename | backup | rewrite
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

// ProjectLifecycle previews a rename, duplicate, delete, disable or enable and,
// with Apply, carries it out. Every step that needs a decision is checked
// before the first one runs: names, collisions, access, and that the whole
// configuration with the change in place still validates. The audit event is
// written before anything changes, the steps run in an order where each stage
// is a configuration that loads, and a failed step undoes the earlier ones.
func (s *Session) ProjectLifecycle(r LifecycleRequest) (LifecyclePreview, error) {
	pl, err := s.planLifecycle(r)
	if err != nil || !r.Apply {
		return pl.preview, err
	}
	if err := pl.mayApply(s); err != nil {
		return pl.preview, err
	}
	if pl.preview.RequiresConfirm && !r.Confirm {
		return pl.preview, fmt.Errorf("%w: %s of %s is destructive; review the consequences and confirm", ErrConfirm, r.Verb, pl.name)
	}
	if err := s.runLifecycle(pl); err != nil {
		return pl.preview, err
	}
	pl.preview.Applied = true
	return pl.preview, nil
}

// DisabledProjects lists the projects whose file is switched off, if the actor
// may see all projects (a disabled project is in nobody's access rules).
func (s *Session) DisabledProjects() ([]string, error) {
	if _, _, open := s.Cfg.Allowed(baseActor(s.Actor)); !open {
		return []string{}, nil
	}
	files, err := s.disabledFiles()
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(files)), nil
}

// DisabledFile is the switched-off file of a project, if there is one.
func (s *Session) DisabledFile(name string) (string, bool) {
	files, err := s.disabledFiles()
	path, ok := files[name]
	return path, ok && err == nil
}

type lifecyclePlan struct {
	req      LifecycleRequest
	name     string
	newName  string
	preview  LifecyclePreview
	livePath string // <name>.yaml
	offPath  string // <name>.yaml.disabled
	srcPath  string // the file the verb starts from
	newPath  string // file created by rename, duplicate or enable
	oldData  []byte
	newData  []byte
	moving   []model.Finding // the project's findings
	actors   []AccessChange
	base     *confdoc.Set // config documents as they are; nil when no access rule names the project
	cand     *confdoc.Set // ... and with the access rules rewritten
	closing  []string     // keys of the open findings a delete closes
}

func (s *Session) planLifecycle(r LifecycleRequest) (*lifecyclePlan, error) {
	pl := &lifecyclePlan{req: r, name: strings.TrimSpace(r.Project), newName: strings.TrimSpace(r.NewName)}
	pl.preview = LifecyclePreview{Verb: r.Verb, Project: pl.name, NewName: pl.newName, Files: []FileChange{}}
	if !slices.Contains(LifecycleVerbs, r.Verb) {
		return pl, fmt.Errorf("unknown verb %q (use rename, duplicate, disable, enable or delete)", r.Verb)
	}
	if r.CloseFindings && r.Verb != VerbDelete {
		return pl, errors.New("close_findings applies to delete only")
	}
	dir := s.projectsDir()
	var err error
	if err := pl.resolveFiles(s); err != nil {
		return pl, err
	}
	if err := pl.locate(s); err != nil {
		return pl, err
	}
	if err := s.mayRead(pl.name); err != nil {
		return pl, err
	}

	var f *projectfile.File
	parsed, perr := projectfile.Parse(pl.oldData)
	if perr == nil {
		f = parsed
		if got := f.Project().Name; got != pl.name && got != "" {
			// only a file that did not load can get here: the ledger follows the name the file declares
			if r.Verb == VerbRename {
				return pl, fmt.Errorf("%s declares the name %q, not %q; make them match before renaming the project", filepath.Base(pl.srcPath), got, pl.name)
			}
			pl.warn("%s declares the name %q, not %q", filepath.Base(pl.srcPath), got, pl.name)
		}
	}
	needsFile := r.Verb == VerbRename || r.Verb == VerbDuplicate || r.Verb == VerbEnable
	if perr != nil && needsFile {
		return pl, fmt.Errorf("the project file does not parse (%v); fix it first", perr)
	}
	if perr != nil {
		pl.warn("the project file does not parse (%v)", perr)
	}

	if r.Verb == VerbRename || r.Verb == VerbDuplicate {
		if pl.newPath, err = projectfile.Path(dir, pl.newName); err != nil {
			return pl, err
		}
		if pl.newName == pl.name {
			return pl, errors.New("the new name is the same as the old one")
		}
		if s.nameTaken(pl.newName, pl.newPath) {
			return pl, fmt.Errorf("a project named %q already exists (or its file is disabled)", pl.newName)
		}
		if err := f.SetName(pl.newName); err != nil {
			return pl, err
		}
		if pl.newData, err = f.Bytes(); err != nil {
			return pl, err
		}
	}
	if r.Verb == VerbEnable {
		pl.newPath = pl.livePath
		pl.newData = pl.oldData
		for _, i := range f.Validate(s.Cfg.Catalog.Has) {
			if i.Level == "error" {
				return pl, fmt.Errorf("the disabled project has errors (%s: %s); fix the file before enabling it", i.Field, i.Message)
			}
		}
	}

	s.countFindings(pl)
	if err := s.checkNewName(pl); err != nil {
		return pl, err
	}
	if err := s.planAccess(pl); err != nil {
		return pl, err
	}
	if err := s.planFiles(pl); err != nil {
		return pl, err
	}
	if err := s.validateCandidate(pl); err != nil {
		return pl, err
	}
	pl.consequences()
	return pl, nil
}

func (pl *lifecyclePlan) warn(format string, a ...any) {
	pl.preview.Warnings = append(pl.preview.Warnings, fmt.Sprintf(format, a...))
}

// resolveFiles finds where the project's live and disabled files are. They need
// not be called after the project: a disabled file is enabled under its own
// name, and a project nobody has a file for gets <name>.yaml.
func (pl *lifecyclePlan) resolveFiles(s *Session) error {
	live, err := s.projectFiles()
	if err != nil {
		return err
	}
	off, err := s.disabledFiles()
	if err != nil {
		return err
	}
	livePath, isLive := live[pl.name]
	offPath, isOff := off[pl.name]
	switch {
	case isOff && pl.req.Verb == VerbEnable: // back under the disabled file's own name; a live file of the project is a conflict to report
		pl.livePath = strings.TrimSuffix(offPath, ".disabled")
	case isLive:
		pl.livePath = livePath
	case isOff:
		pl.livePath = strings.TrimSuffix(offPath, ".disabled")
	default:
		if pl.livePath, err = s.ProjectFile(pl.name); err != nil {
			return err
		}
	}
	pl.offPath = pl.livePath + ".disabled"
	if isOff {
		pl.offPath = offPath
	}
	return nil
}

// locate finds the file the verb starts from: the live one, or for enable and
// delete the disabled one.
func (pl *lifecyclePlan) locate(s *Session) error {
	live, liveErr := os.ReadFile(pl.livePath)
	off, offErr := os.ReadFile(pl.offPath)
	for _, e := range []error{liveErr, offErr} {
		if e != nil && !errors.Is(e, fs.ErrNotExist) {
			return e
		}
	}
	switch pl.req.Verb {
	case VerbEnable:
		switch {
		case liveErr == nil:
			return fmt.Errorf("project %q is already enabled (%s exists)", pl.name, filepath.Base(pl.livePath))
		case offErr != nil:
			return fmt.Errorf("no disabled project %q", pl.name)
		}
		pl.srcPath, pl.oldData = pl.offPath, off
	case VerbDelete:
		switch {
		case liveErr == nil:
			pl.srcPath, pl.oldData = pl.livePath, live
		case offErr == nil:
			pl.srcPath, pl.oldData = pl.offPath, off
		default:
			return fmt.Errorf("unknown project %q", pl.name)
		}
	default:
		switch {
		case liveErr == nil:
			pl.srcPath, pl.oldData = pl.livePath, live
		case offErr == nil:
			return fmt.Errorf("project %q is disabled; enable it first", pl.name)
		default:
			return fmt.Errorf("unknown project %q", pl.name)
		}
	}
	return nil
}

// nameTaken reports a project, loaded or broken, a file, or a disabled file
// that already uses the name.
func (s *Session) nameTaken(name, livePath string) bool {
	if slices.ContainsFunc(s.Cfg.Projects, func(p model.Project) bool { return p.Name == name }) ||
		slices.ContainsFunc(s.Cfg.Broken, func(b config.BrokenProject) bool { return b.Name == name }) {
		return true
	}
	for _, p := range []string{livePath, livePath + ".disabled"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	live, _ := s.projectFiles()
	off, _ := s.disabledFiles()
	_, inLive := live[name]
	_, inOff := off[name]
	return inLive || inOff
}

func (s *Session) countFindings(pl *lifecyclePlan) {
	pl.preview.Findings.ByStatus = map[model.Status]int{}
	for _, f := range s.Ledger.Findings() {
		if f.Project != pl.name {
			continue
		}
		pl.moving = append(pl.moving, f)
		pl.preview.Findings.Total++
		pl.preview.Findings.ByStatus[f.Status]++
		if f.Status == model.StatusOpen {
			pl.closing = append(pl.closing, f.Key())
		}
	}
	if len(pl.preview.Findings.ByStatus) == 0 {
		pl.preview.Findings.ByStatus = nil
	}
}

// planAccess finds the access rules that name the project and prepares their
// rewrite on a copy of the configuration documents. Nothing is written.
func (s *Session) planAccess(pl *lifecyclePlan) error {
	verb := pl.req.Verb
	if verb == VerbDuplicate || verb == VerbEnable {
		return nil // the copy and the revived project are in nobody's rules
	}
	var edits []confdoc.Edit
	for _, actor := range slices.Sorted(maps.Keys(s.Cfg.Access)) {
		g := s.Cfg.Access[actor]
		if !slices.Contains(g.Projects, pl.name) {
			continue
		}
		path := confdoc.FormatPath([]string{"access", actor, "projects", "=" + pl.name})
		ch := AccessChange{Actor: actor, Action: "remove"}
		if verb == VerbRename {
			ch.Action = "rename"
			edits = append(edits, confdoc.Edit{Doc: confdoc.IDSettings, Op: confdoc.OpSet, Path: path, Value: pl.newName})
		} else {
			edits = append(edits, confdoc.Edit{Doc: confdoc.IDSettings, Op: confdoc.OpUnset, Path: path})
		}
		ch.Left = slices.DeleteFunc(slices.Clone(g.Projects), func(p string) bool { return p == pl.name })
		if verb == VerbRename {
			ch.Left = slices.Clone(g.Projects)
			ch.Left[slices.Index(ch.Left, pl.name)] = pl.newName
		}
		pl.actors = append(pl.actors, ch)
	}
	pl.preview.Access = pl.actors
	if len(edits) == 0 {
		return nil
	}
	base, err := confdoc.Read(s.Cfg.Root)
	if err != nil {
		return err
	}
	if _, err := base.Doc(confdoc.IDSettings).Access(); err != nil {
		return fmt.Errorf("the access rules in config.yaml cannot be read (%v), so the rules naming %q cannot be updated; nothing was changed. Fix config.yaml in an editor first", err, pl.name)
	}
	cand, err := base.With(edits...)
	if err != nil {
		return fmt.Errorf("the access rules naming %q cannot be updated (%v); nothing was changed", pl.name, err)
	}
	pl.base, pl.cand = base, cand
	return nil
}

func (s *Session) planFiles(pl *lifecyclePlan) error {
	backups := filepath.Join(s.Cfg.DataDir, "project-backups")
	now := s.Now()
	add := func(action, from, to string) {
		pl.preview.Files = append(pl.preview.Files, FileChange{Action: action, From: from, To: to})
	}
	switch pl.req.Verb {
	case VerbRename:
		add("create", pl.srcPath, pl.newPath)
		add("backup", pl.srcPath, projectfile.BackupTarget(pl.srcPath, backups, now))
	case VerbDuplicate:
		add("create", pl.srcPath, pl.newPath)
	case VerbDelete:
		add("backup", pl.srcPath, projectfile.BackupTarget(pl.srcPath, backups, now))
	case VerbDisable:
		add("rename", pl.livePath, pl.offPath)
	case VerbEnable:
		add("rename", pl.offPath, pl.livePath)
	}
	if pl.cand != nil {
		doc := pl.base.Doc(confdoc.IDSettings)
		add("rewrite", doc.Path, "")
		add("backup", doc.Path, projectfile.BackupTarget(doc.Path, filepath.Join(s.Cfg.DataDir, "config-backups"), now))
	}
	return nil
}

// validateCandidate assembles the configuration as it would be and refuses a
// change that introduces an error.
func (s *Session) validateCandidate(pl *lifecyclePlan) error {
	set := pl.base
	if set == nil {
		var err error
		if set, err = confdoc.Read(s.Cfg.Root); err != nil {
			return err
		}
	}
	over := config.Overlay{}
	switch pl.req.Verb {
	case VerbRename:
		over[pl.srcPath], over[pl.newPath] = nil, pl.newData
	case VerbDuplicate, VerbEnable:
		over[pl.newPath] = pl.newData
	case VerbDelete, VerbDisable:
		over[pl.srcPath] = nil
	}
	cand := set
	if pl.cand != nil {
		cand = pl.cand
	}
	rep := cand.ValidateWith(over)
	rep.MarkExisting(set.Validate())
	var msgs []string
	for _, i := range rep.Issues {
		// a project file that would be skipped as broken (a duplicate name, say) is only a warning to the loader
		if !i.Existing && (i.Level == confdoc.LevelError || strings.HasPrefix(i.Doc, "projects/")) {
			msgs = append(msgs, strings.TrimSpace(i.Doc+" "+i.Field+": "+i.Message))
		}
	}
	if len(msgs) > 0 {
		return fmt.Errorf("the configuration would not load after this change (%s); nothing was changed", strings.Join(msgs, "; "))
	}
	return nil
}

// consequences fills in what the person should know before confirming.
func (pl *lifecyclePlan) consequences() {
	p, n := pl.preview.Findings, pl.preview.Findings.ByStatus[model.StatusOpen]
	switch pl.req.Verb {
	case VerbRename:
		pl.preview.Destructive = true
		if p.Total > 0 {
			pl.warn("%d findings move to %q; reports of those issues are rewritten", p.Total, pl.newName)
		}
		pl.warn("the audit log and past evidence keep the old name")
	case VerbDuplicate:
		pl.warn("the copy points at the same lockfiles, so it finds the same issues; it is in no access rule")
	case VerbDelete:
		pl.preview.Destructive = true
		switch {
		case pl.req.CloseFindings && n > 0:
			pl.warn("%d open findings are marked ignored (note: project deleted); the others keep their status", n)
		case p.Total > 0:
			pl.warn("%d findings stay in the ledger unchanged, %d of them open: they are no longer re-checked against an inventory but still show in lists and digests", p.Total, n)
		}
		pl.warn("the file is moved to the project backups, not erased")
	case VerbDisable:
		pl.preview.Destructive = len(pl.actors) > 0
		if p.Total > 0 {
			pl.warn("%d findings stay in the ledger unchanged, %d of them open: no new issues are matched and they are not re-checked while disabled", p.Total, n)
		}
	case VerbEnable:
		if p.Total > 0 {
			pl.warn("%d existing findings resume being checked", p.Total)
		}
		pl.warn("access rules that named this project were removed when it was disabled and are not restored")
	}
	for _, a := range pl.actors {
		if a.Action == "remove" && len(a.Left) == 0 {
			pl.warn("%s is left with no project in its access rule", a.Actor)
		}
	}
	if pl.req.Verb == VerbDisable && len(pl.actors) > 0 {
		pl.warn("the rules naming this project are removed and not restored by enable")
	}
	pl.preview.RequiresConfirm = pl.preview.Destructive
}

// checkNewName looks at findings already stored under the new name, left by an
// earlier project of that name. A rename cannot merge findings with the same
// key; a duplicate just reuses the others.
func (s *Session) checkNewName(pl *lifecyclePlan) error {
	if pl.req.Verb != VerbRename && pl.req.Verb != VerbDuplicate {
		return nil
	}
	existing := map[string]bool{}
	for _, f := range s.Ledger.Findings() {
		if f.Project == pl.newName {
			existing[f.Key()] = true
		}
	}
	if len(existing) == 0 {
		return nil
	}
	if pl.req.Verb == VerbRename {
		for _, f := range pl.moving {
			if existing[f.VulnID+"|"+pl.newName+"|"+string(f.Env)] {
				return fmt.Errorf("the ledger already holds a finding of %q for %s in %s (from an earlier project of that name); choose another name", pl.newName, f.VulnID, f.Env)
			}
		}
	}
	pl.warn("the ledger already holds %d findings under the name %q; they join this project", len(existing), pl.newName)
	return nil
}

// mayApply is the write check, made after the preview so a person who may only
// look can still see consequences.
func (pl *lifecyclePlan) mayApply(s *Session) error {
	switch pl.req.Verb {
	case VerbRename:
		if err := s.mayWrite(pl.name); err != nil {
			return err
		}
		if err := s.mayWrite(pl.newName); err != nil {
			return err
		}
		if pl.cand != nil { // renaming rewrites access rules, which only an unrestricted writer may change
			return s.Settings().mayWrite()
		}
		return nil
	case VerbDuplicate, VerbEnable:
		return s.mayWrite("")
	}
	if pl.cand != nil { // the access rules are settings: only an unrestricted writer may change them
		return s.Settings().mayWrite()
	}
	return s.mayWrite(pl.name)
}

// ---- applying ----

// undoStack holds the way back from each step that succeeded.
type undoStack []func() error

func (u *undoStack) add(f func() error) { *u = append(*u, f) }

// unwind runs the undo steps newest first and says what happened.
func (u undoStack) unwind() string {
	var failed []string
	for i := len(u) - 1; i >= 0; i-- {
		if err := u[i](); err != nil {
			failed = append(failed, err.Error())
		}
	}
	if len(failed) > 0 {
		return "undoing the earlier steps failed too (" + strings.Join(failed, "; ") + ")"
	}
	return "everything was put back"
}

func (s *Session) runLifecycle(pl *lifecyclePlan) (err error) {
	now := s.Now()
	ev := audit.Event{Time: now, Actor: s.Actor, Action: "project", Project: pl.name, Note: pl.auditNote()}
	if err := s.Audit.Append(ev); err != nil {
		return fmt.Errorf("audit log: %w", err) // never change anything without a record
	}
	var undo undoStack
	defer func() {
		if err == nil {
			return
		}
		result := undo.unwind()
		err = fmt.Errorf("%s of %s failed: %w; %s", pl.req.Verb, pl.name, err, result)
		ev.Action, ev.Note = "project-failed", err.Error()
		s.Audit.Append(ev)
	}()

	backups := filepath.Join(s.Cfg.DataDir, "project-backups")
	switch pl.req.Verb {
	case VerbDuplicate:
		return s.createFile(pl, &undo, backups, now)
	case VerbEnable:
		return s.moveFile(&undo, pl.offPath, pl.livePath)
	case VerbDisable:
		if err := s.writeAccess(pl, &undo, now); err != nil {
			return err
		}
		return s.moveFile(&undo, pl.livePath, pl.offPath)
	case VerbRename:
		if err := s.createFile(pl, &undo, backups, now); err != nil {
			return err
		}
		if err := s.commitLedger(func() error { _, err := s.Ledger.RenameProject(pl.name, pl.newName); return err }); err != nil {
			return err
		}
		undo.add(func() error {
			return s.commitLedger(func() error { _, err := s.Ledger.RenameProject(pl.newName, pl.name); return err })
		})
		if err := s.writeAccess(pl, &undo, now); err != nil {
			return err
		}
		if err := s.archive(pl, &undo, backups, now); err != nil {
			return err
		}
		s.refreshReports(pl, now)
	case VerbDelete:
		if err := s.writeAccess(pl, &undo, now); err != nil {
			return err
		}
		if err := s.archive(pl, &undo, backups, now); err != nil {
			return err
		}
		if pl.req.CloseFindings && len(pl.closing) > 0 {
			if err := s.commitLedger(func() error { s.closeFindings(pl, now); return nil }); err != nil {
				return err
			}
			s.refreshReports(pl, now)
		}
	}
	return nil
}

func (pl *lifecyclePlan) auditNote() string {
	n := pl.preview.Findings.Total
	var actors []string
	for _, a := range pl.actors {
		actors = append(actors, a.Actor)
	}
	rules := ""
	if len(actors) > 0 {
		rules = "; access rules of " + strings.Join(actors, ", ")
		if pl.req.Verb == VerbRename {
			rules += " updated"
		} else {
			rules += " dropped"
		}
	}
	switch pl.req.Verb {
	case VerbRename:
		return fmt.Sprintf("renamed project to %s: %d findings moved%s", pl.newName, n, rules)
	case VerbDuplicate:
		return fmt.Sprintf("duplicated project as %s", pl.newName)
	case VerbDelete:
		closed := ""
		if pl.req.CloseFindings {
			closed = fmt.Sprintf("; %d open findings ignored", len(pl.closing))
		}
		return fmt.Sprintf("deleted project (file backed up); %d findings kept%s%s", n, closed, rules)
	case VerbDisable:
		return fmt.Sprintf("disabled project (file renamed to .disabled); %d findings kept%s", n, rules)
	}
	return "enabled project"
}

// createFile writes the new project file of a rename or duplicate.
func (s *Session) createFile(pl *lifecyclePlan, undo *undoStack, backups string, now time.Time) error {
	if _, err := os.Stat(pl.newPath); err == nil {
		return fmt.Errorf("%s appeared since the preview", filepath.Base(pl.newPath))
	}
	if err := projectfile.Write(pl.newPath, pl.newData, backups, now); err != nil {
		return err
	}
	undo.add(func() error { return os.Remove(pl.newPath) })
	return nil
}

// moveFile renames a file in place; it refuses to replace one.
func (s *Session) moveFile(undo *undoStack, from, to string) error {
	if _, err := os.Stat(to); err == nil {
		return fmt.Errorf("%s exists", filepath.Base(to))
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	undo.add(func() error { return os.Rename(to, from) })
	return nil
}

// archive moves the project's file into the backups and records where.
func (s *Session) archive(pl *lifecyclePlan, undo *undoStack, backups string, now time.Time) error {
	path, err := projectfile.Archive(pl.srcPath, backups, now)
	if err != nil {
		return fmt.Errorf("%w (a copy may be in %s)", err, backups)
	}
	pl.preview.Backup = path
	undo.add(func() error { return projectfile.Write(pl.srcPath, pl.oldData, backups, now) })
	return nil
}

// writeAccess saves the rewritten access rules, if there are any. The old
// text of config.yaml is backed up first, and is what undo writes back.
func (s *Session) writeAccess(pl *lifecyclePlan, undo *undoStack, now time.Time) error {
	if pl.cand == nil {
		return nil
	}
	dir := filepath.Join(s.Cfg.DataDir, "config-backups")
	written, err := pl.cand.Write(dir, now)
	restore := func() error {
		var errs []error
		for _, p := range written {
			for _, d := range pl.base.Docs {
				if d.Path == p {
					b, _ := d.Bytes()
					errs = append(errs, projectfile.Write(p, b, dir, now))
				}
			}
		}
		return errors.Join(errs...)
	}
	if err != nil {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (and putting config.yaml back failed: %v; the old text is in %s)", err, rerr, dir)
		}
		return err
	}
	undo.add(restore)
	return nil
}

// commitLedger changes the ledger and saves it, redoing the change once on a
// stale state like the other write paths do.
func (s *Session) commitLedger(change func() error) error {
	do := func() error {
		if err := change(); err != nil {
			return err
		}
		return s.Commit()
	}
	err := do()
	if errors.Is(err, store.ErrConflict) {
		if err = s.reload(); err == nil {
			err = do()
		}
	}
	if err != nil {
		s.reload() // the change may be in memory only; show what is really stored
	}
	return err
}

func (s *Session) closeFindings(pl *lifecyclePlan, now time.Time) {
	note := "project deleted"
	for _, key := range pl.closing {
		s.Ledger.Mutate(key, func(f *model.Finding) {
			if f.Status != model.StatusOpen {
				return
			}
			f.Status, f.Note, f.Updated = model.StatusIgnored, note, now
			f.History = append(f.History, model.Disposition{Time: now, Actor: s.Actor, Action: "status", Status: f.Status, Note: note})
		})
	}
}

// refreshReports rewrites the report of every issue the project has a finding
// for, so the status tables show the new name or status. A report that cannot
// be written is only a warning: the ledger is the source of truth.
func (s *Session) refreshReports(pl *lifecyclePlan, now time.Time) {
	seen := map[string]bool{}
	for _, f := range pl.moving {
		v := s.Ledger.Vuln(f.VulnID)
		if v == nil || seen[v.ID] {
			continue
		}
		seen[v.ID] = true
		if _, err := report.Write(s.Cfg.AlertsDir, v, s.Ledger.FindingsOf(v.ID), now); err != nil {
			pl.warn("report for %s not refreshed: %v", v.ID, err)
		}
	}
}
