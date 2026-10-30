package ops

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/config"
)

// SettingsNote is what a front end tells people after a save.
const SettingsNote = "Changes apply from the next daemon cycle."

// SettingsChange is a set of edits to the configuration documents (config.yaml,
// techs.yaml, sources/*.yaml). Without Save the change is only previewed.
type SettingsChange struct {
	Edits []confdoc.Edit
	Save  bool
}

// SettingsPreview is what a change does, so callers can show it before saving.
// Nothing in it holds a secret value: those read "(set)".
type SettingsPreview struct {
	Saved   bool              `json:"saved"`
	Changed []string          `json:"changed"` // IDs of the documents that differ
	Diff    string            `json:"diff"`
	Diffs   []confdoc.DocDiff `json:"diffs"`
	Issues  []confdoc.Issue   `json:"issues"`
	Written []string          `json:"written,omitempty"` // files written when saved
	Note    string            `json:"note"`
}

// Blocked reports a new error, so the change cannot be saved.
func (p SettingsPreview) Blocked() bool {
	for _, i := range p.Issues {
		if i.Level == confdoc.LevelError && !i.Existing {
			return true
		}
	}
	return false
}

// DocView is one configuration document as shown to people. Secret values are
// hidden; a document whose YAML does not parse carries the error instead.
type DocView struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Layer    confdoc.Layer   `json:"layer"`
	Path     string          `json:"path,omitempty"`
	Exists   bool            `json:"exists"`
	ReadOnly bool            `json:"read_only"`
	Error    string          `json:"error,omitempty"`
	Entries  []confdoc.Entry `json:"entries,omitempty"`
	Text     string          `json:"text,omitempty"`
}

// SettingsView is the configuration documents plus what is wrong with them.
type SettingsView struct {
	Docs   []DocView       `json:"docs"`
	Issues []confdoc.Issue `json:"issues"`
}

// SettingsSession reads and edits the configuration documents. It needs no
// state storage and no valid configuration, so it opens even when config.yaml
// is broken; that is how a broken file gets repaired.
type SettingsSession struct {
	Root     string
	DataDir  string
	Actor    string
	Now      func() time.Time
	Audit    *audit.Log
	ReadOnly bool

	access    map[string]config.Grant
	accessErr error // the access rules could not be read, so nobody is trusted
}

// OpenSettings opens the configuration under root without loading it. The
// access rules are read from config.yaml as far as they can be; when they
// cannot be read at all, the documents can be viewed but not changed.
func OpenSettings(root string) (*SettingsSession, error) {
	set, err := confdoc.Read(root)
	if err != nil {
		return nil, err
	}
	return newSettingsSession(root, set), nil
}

func newSettingsSession(root string, set *confdoc.Set) *SettingsSession {
	ss := &SettingsSession{Root: root, Now: time.Now, Actor: audit.Actor()}
	doc := set.Doc(confdoc.IDSettings)
	ss.access, ss.accessErr = doc.Access()
	dir := doc.Scalar("data_dir")
	if dir == "" {
		dir = config.Defaults().DataDir
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Clean(filepath.Join(root, dir))
	}
	ss.DataDir = dir
	ss.Audit = audit.Open(dir)
	return ss
}

// Settings gives the session's view of the configuration documents.
func (s *Session) Settings() *SettingsSession {
	return &SettingsSession{Root: s.Cfg.Root, DataDir: s.Cfg.DataDir, Actor: s.Actor, Now: s.Now, Audit: s.Audit,
		ReadOnly: s.readOnly, access: s.Cfg.Access}
}

// EditSettings previews a change to the configuration documents and, with Save,
// validates and writes it. The files keep their comments and layout, the old
// text is backed up, and the edit is recorded in the audit log before anything
// is written.
func (s *Session) EditSettings(c SettingsChange) (SettingsPreview, error) {
	return s.Settings().Edit(c)
}

// mayRead lets an actor see the settings only when no access rule restricts it:
// the documents name every project and every actor.
func (ss *SettingsSession) mayRead() error {
	_, _, open := config.AllowedBy(ss.access, baseActor(ss.Actor))
	if ss.accessErr == nil && !open {
		return fmt.Errorf("%w: %s may not see the settings", ErrDenied, ss.Actor)
	}
	return nil
}

// mayWrite lets an actor change settings only when it has write access to every
// project. Because that also covers the access rules, nobody can grant
// themselves rights they lack.
func (ss *SettingsSession) mayWrite() error {
	if ss.ReadOnly {
		return ErrReadOnly
	}
	if ss.accessErr != nil {
		return fmt.Errorf("%w: the access rules in config.yaml cannot be read (%v), so changes are refused until it is fixed in an editor", ErrDenied, ss.accessErr)
	}
	_, write, open := config.AllowedBy(ss.access, baseActor(ss.Actor))
	if !write || !open {
		return fmt.Errorf("%w: %s may not change the settings", ErrDenied, ss.Actor)
	}
	return nil
}

// Writable says whether the actor may change the settings; the error says why not.
func (ss *SettingsSession) Writable() error { return ss.mayWrite() }

// RulesUnreadable says the access rules in config.yaml cannot be read, so the
// documents can only be repaired in an editor.
func (ss *SettingsSession) RulesUnreadable() bool { return ss.accessErr != nil }

// View reads the documents and validates them as they are on disk.
func (ss *SettingsSession) View() (SettingsView, error) {
	var v SettingsView
	if err := ss.mayRead(); err != nil {
		return v, err
	}
	set, err := confdoc.Read(ss.Root)
	if err != nil {
		return v, err
	}
	hide := ss.accessErr != nil // unreadable rules: show only that the file is broken
	for _, d := range set.Docs {
		dv := DocView{ID: d.ID, Kind: d.Kind, Layer: d.Layer, Path: d.Path, Exists: d.Exists, ReadOnly: d.ReadOnly}
		if d.ParseErr != nil {
			dv.Error = d.ParseErr.Error()
		}
		if !(hide && d.ID == confdoc.IDSettings) {
			dv.Entries, dv.Text = d.Entries(), d.Text()
		}
		v.Docs = append(v.Docs, dv)
	}
	v.Issues = set.Validate().Issues
	return v, nil
}

// Edit previews a change and, with Save, validates and writes it.
func (ss *SettingsSession) Edit(c SettingsChange) (SettingsPreview, error) {
	out := SettingsPreview{Note: SettingsNote}
	if err := ss.mayRead(); err != nil {
		return out, err
	}
	base, err := confdoc.Read(ss.Root)
	if err != nil {
		return out, err
	}
	cand, err := base.With(c.Edits...)
	if err != nil {
		return out, err
	}
	out.Diffs = confdoc.Diff(base, cand)
	var diffs []string
	for _, d := range out.Diffs {
		out.Changed = append(out.Changed, d.Doc)
		diffs = append(diffs, "# "+d.Doc+"\n"+d.Diff)
	}
	out.Diff = strings.Join(diffs, "\n")
	if len(out.Diffs) == 0 {
		out.Diff = "(no changes)"
	}
	rep := cand.Validate()
	rep.MarkExisting(base.Validate())
	out.Issues = append(rep.Issues, ss.accessIssues(base, cand)...)
	if !c.Save {
		return out, nil
	}
	if err := ss.mayWrite(); err != nil {
		return out, err
	}
	if out.Blocked() {
		return out, errors.New("the settings have errors; fix them before saving")
	}
	if len(out.Diffs) == 0 {
		return out, nil
	}
	ev := audit.Event{Time: ss.Now(), Actor: ss.Actor, Action: "settings", Note: auditNote(c.Edits, out.Changed)}
	if err := ss.Audit.Append(ev); err != nil {
		return out, fmt.Errorf("audit log: %w", err) // never change anything without a record
	}
	written, err := cand.Write(filepath.Join(ss.DataDir, "config-backups"), ss.Now())
	out.Written = written
	if err != nil {
		return out, err
	}
	out.Saved = true
	return out, nil
}

// accessIssues guards the access rules: a change to them must leave the actor
// with write access to every project, or the actor could lock everyone out,
// itself included, with no way back from inside the tool.
func (ss *SettingsSession) accessIssues(base, cand *confdoc.Set) []confdoc.Issue {
	was, _ := base.Doc(confdoc.IDSettings).Access()
	now, err := cand.Doc(confdoc.IDSettings).Access()
	if err != nil || reflect.DeepEqual(was, now) {
		return nil
	}
	if _, write, open := config.AllowedBy(now, baseActor(ss.Actor)); write && open {
		return nil
	}
	return []confdoc.Issue{{Level: confdoc.LevelError, Doc: confdoc.IDSettings, Field: "access",
		Message: fmt.Sprintf("these rules would leave %s without write access to every project; add %s with projects [\"*\"] and write: true", baseActor(ss.Actor), baseActor(ss.Actor))}}
}

// auditNote lists what was edited by path; values never go into the log.
func auditNote(edits []confdoc.Edit, docs []string) string {
	var parts []string
	for _, e := range edits {
		if e.Op == confdoc.OpReplace {
			parts = append(parts, "replace "+e.Doc)
		} else {
			parts = append(parts, string(e.Op)+" "+e.Path)
		}
	}
	note := fmt.Sprintf("edited settings (%s): %s", strings.Join(docs, ", "), strings.Join(parts, "; "))
	if len(note) > 400 {
		note = note[:400] + "..."
	}
	return note
}
