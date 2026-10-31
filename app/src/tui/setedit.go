package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// The editors of the Settings screen. Every one of them ends in the same
// place: a list of confdoc edits that ops previews, the user reads as a diff
// and then saves. Nothing is written before that yes.

// setReview is a change on its way to the files: first the preview, then the
// user's yes.
type setReview struct {
	label  string
	crumb  string // the setting, for the breadcrumb
	edits  []confdoc.Edit
	prev   *ops.SettingsPreview
	saving bool
	vp     viewport

	run func(ss *ops.SettingsSession, save bool) (ops.SettingsPreview, error) // a change ops makes itself, such as one to the technologies; edits is then empty
}

// apply previews or saves the review's change.
func (rv *setReview) apply(ss *ops.SettingsSession, edits []confdoc.Edit, save bool) (ops.SettingsPreview, error) {
	if rv.run != nil {
		return rv.run(ss, save)
	}
	return ss.Edit(ops.SettingsChange{Edits: edits, Save: save})
}

type (
	setCheckedMsg struct {
		rv   *setReview
		prev ops.SettingsPreview
		err  error
	}
	setSavedMsg struct {
		rv   *setReview
		prev ops.SettingsPreview
		err  error
	}
)

func settingsPreviewCmd(b Backend, rv *setReview, edits []confdoc.Edit) tea.Cmd {
	return func() tea.Msg {
		var p ops.SettingsPreview
		err := b.Settings(func(ss *ops.SettingsSession) (e error) {
			p, e = rv.apply(ss, edits, false)
			return e
		})
		return setCheckedMsg{rv: rv, prev: p, err: err}
	}
}

func settingsSaveCmd(b Backend, rv *setReview, edits []confdoc.Edit) tea.Cmd {
	return func() tea.Msg {
		var p ops.SettingsPreview
		err := b.Settings(func(ss *ops.SettingsSession) (e error) {
			p, e = rv.apply(ss, edits, true)
			return e
		})
		return setSavedMsg{rv: rv, prev: p, err: err}
	}
}

// settingsError says why a change was refused; a refused access is said as that.
func settingsError(err error) string {
	switch {
	case errors.Is(err, ops.ErrDenied):
		return "access refused: " + denyText(err)
	case errors.Is(err, ops.ErrReadOnly):
		return "this session is read-only"
	}
	return oneLine(err.Error())
}

// previewSettings asks ops what the edits would do. If they cannot be applied,
// or add an error, the prompt that asked stays open with its text and the
// reason; otherwise the change is shown for saving.
func (m *app) previewSettings(label, crumb string, edits []confdoc.Edit, prm *prompt) tea.Cmd {
	rv := &setReview{label: label, crumb: crumb, edits: edits, vp: scrolling()}
	return m.start("checking...", "settings", 0, prm, settingsPreviewCmd(m.b, rv, edits))
}

func (m *app) setChecked(msg setCheckedMsg) outcome {
	if msg.err != nil {
		return outcome{err: errors.New(settingsError(msg.err))}
	}
	for _, is := range msg.prev.Issues {
		if is.Level == confdoc.LevelError && !is.Existing {
			text := oneLine(is.Message)
			if is.Field != "" {
				text = oneLine(is.Field) + ": " + text
			}
			return outcome{err: errors.New(text)}
		}
	}
	if len(msg.prev.Diffs) == 0 {
		return outcome{err: errors.New("that is the value already: nothing would change")}
	}
	p := msg.prev
	msg.rv.prev = &p
	m.set.review, m.set.pick = msg.rv, nil
	return outcome{}
}

func (m *app) setApply() tea.Cmd {
	rv := m.set.review
	if rv == nil || rv.prev == nil || rv.saving {
		return nil
	}
	if rv.prev.Blocked() {
		m.fail("this cannot be saved until the errors are fixed")
		return nil
	}
	cmd := m.start("saving...", "settings", reList|reSettings, nil, settingsSaveCmd(m.b, rv, rv.edits))
	rv.saving = cmd != nil
	return cmd
}

func (m *app) setCancel() tea.Cmd {
	m.set.review = nil
	m.say("cancelled, nothing was saved")
	return nil
}

func (m *app) setSaved(msg setSavedMsg) outcome {
	if msg.rv != m.set.review {
		return outcome{err: msg.err}
	}
	m.set.review = nil
	switch {
	case msg.err != nil:
		return outcome{err: errors.New(settingsError(msg.err))}
	case !msg.prev.Saved:
		return outcome{note: "no changes to save"}
	}
	if msg.rv.tuiOnly() {
		return outcome{note: "saved: " + msg.rv.label + " (applies on the next re-read)"}
	}
	return outcome{note: "saved: " + msg.rv.label + " (applies from the next daemon cycle)"}
}

// tuiOnly says the edits are of the tui section, which this program itself
// reads again every period and not the daemon.
func (rv *setReview) tuiOnly() bool {
	for _, e := range rv.edits {
		if !strings.HasPrefix(e.Path, "tui.") {
			return false
		}
	}
	return len(rv.edits) > 0
}

// settingsNote is what people are told after a save: when the daemon sees it.
func settingsNote(interval string) string {
	note := strings.TrimSuffix(ops.SettingsNote, ".")
	if interval != "" {
		note += " (up to " + interval + " away)"
	}
	return note + "."
}

func (rv *setReview) note(interval string) string {
	if rv.tuiOnly() {
		return "Changes apply on the next re-read of the interface."
	}
	return settingsNote(interval)
}

func (rv *setReview) frame(w, h int) (head []string, room int) {
	var docs []string
	if rv.prev != nil {
		for _, id := range rv.prev.Changed {
			docs = append(docs, displayDoc(id))
		}
	}
	head = []string{stBold.Render(trunc("Change settings: "+oneLine(rv.label), w)), section(trunc(strings.Join(docs, ", "), w)), ""}
	return head, max(h-len(head)-3, 1)
}

func (rv *setReview) body(w int) []string {
	var body []string
	switch {
	case rv.saving:
		body = append(body, stMuted.Render("Saving..."))
	case rv.prev == nil:
		body = append(body, stMuted.Render("Checking the change..."))
	}
	if rv.prev == nil {
		return body
	}
	body = append(body, diffRows(rv.prev.Diff, w)...)
	for _, is := range rv.prev.Issues {
		lvl := stMuted.Render(oneLine(string(is.Level)))
		if is.Level == confdoc.LevelError {
			lvl = stErr.Render("error")
		}
		body = append(body, lvl+": "+trunc(strings.TrimPrefix(issueLine(&setIssue{Issue: is}), string(is.Level)+" "), w-8))
	}
	if rv.prev.Blocked() {
		body = append(body, stErr.Render("this cannot be saved until the errors are fixed"))
	}
	return body
}

func (rv *setReview) layout(w, h int) {
	_, room := rv.frame(w, h)
	rv.vp.refit(len(rv.body(w)), nil)
	rv.vp.fit(room)
}

func (rv *setReview) view(w, h int, interval string) []string {
	out, room := rv.frame(w, h)
	body := rv.body(w)
	start, end := rv.vp.window(room)
	start, end = min(start, len(body)), min(end, len(body))
	out = append(out, body[start:end]...)
	return append(out, "", stBold.Render("Save these settings changes?")+"  y or enter = save, esc = cancel", stMuted.Render(trunc(rv.note(interval), w)))
}

// ---- the keys that start a change ----

// setMayEdit says whether settings can be changed, and why not when they cannot.
func (m *app) setMayEdit() bool {
	if err := m.set.write; err != nil {
		m.fail("the settings cannot be changed: " + denyText(err))
		return false
	}
	return true
}

// setDocOK refuses to edit by field a document that does not parse.
func (m *app) setDocOK(doc string) bool {
	if d, ok := m.set.mdl.docs[doc]; ok && d.Error != "" {
		m.fail(displayDoc(doc) + " has a syntax error and cannot be edited by field: press E to fix it in your editor")
		return false
	}
	return true
}

func (m *app) setAddKey() tea.Cmd {
	lv := m.set.level()
	if lv == nil || !m.setMayEdit() {
		return nil
	}
	return m.setAdd(lv.node)
}

func (m *app) setRemoveKey() tea.Cmd {
	r, ok := m.set.row()
	if !ok || r.kind != rowItem || !m.setMayEdit() || !m.setDocOK(r.doc) {
		return nil
	}
	if onTechItem(m) {
		return m.setTechRemove()
	}
	what := r.label
	if r.secret {
		what = "an item"
	}
	return m.previewSettings("remove "+oneLine(what)+" from "+r.f.Label, lastSeg(r.segs),
		[]confdoc.Edit{{Doc: r.doc, Op: confdoc.OpUnset, Path: confdoc.FormatPath(r.segs)}}, nil)
}

func (m *app) setUnsetKey() tea.Cmd {
	r, ok := m.set.row()
	if !ok || r.kind != rowField || !r.set || !m.setMayEdit() || !m.setDocOK(r.doc) {
		return nil
	}
	return m.previewSettings(unsetLabel(r), lastSeg(r.segs), []confdoc.Edit{{Doc: r.doc, Op: confdoc.OpUnset, Path: confdoc.FormatPath(r.segs)}}, nil)
}

func lastSeg(segs []string) string { return itemName(segs[len(segs)-1]) }

func unsetLabel(r setRow) string {
	if r.f.Default != "" && !r.secret {
		return fmt.Sprintf("restore the default of %s (%s)", r.f.Label, oneLine(r.f.Default))
	}
	if r.f.Type == confdoc.TypeList || r.f.Type == confdoc.TypeMap {
		return "remove all of " + r.f.Label
	}
	return "remove " + r.f.Label + " (nothing is set)"
}

// setEditRow changes the field or item under the cursor, or opens the list it is.
func (m *app) setEditRow(r setRow) tea.Cmd {
	s := &m.set
	lv := s.level()
	switch r.kind {
	case rowAdd:
		if !m.setMayEdit() {
			return nil
		}
		return m.setAdd(lv.node)
	case rowItem:
		if isRecords(r.f) {
			if n, ok := nodeAt(r.f.Doc, r.segs); ok {
				s.push(n)
			}
			return nil
		}
		if !m.setMayEdit() || !m.setDocOK(r.doc) {
			return nil
		}
		return m.setEditItem(lv.node, r)
	}
	if isCollection(r.f) {
		if n, ok := nodeAt(r.f.Doc, r.segs); ok {
			s.push(n)
		}
		return nil
	}
	if !m.setMayEdit() || !m.setDocOK(r.doc) {
		return nil
	}
	switch r.f.Type {
	case confdoc.TypeBool:
		return m.setToggle(r)
	case confdoc.TypeEnum:
		m.setPickEnum(r)
		return nil
	}
	m.setPrompt(r)
	return nil
}

// setToggle turns a switch over, from what it is now.
func (m *app) setToggle(r setRow) tea.Cmd {
	on := r.value == "true"
	if !r.set {
		on = r.f.Default == "true"
	}
	verb := "turn on "
	if on {
		verb = "turn off "
	}
	return m.previewSettings(verb+r.f.Label, lastSeg(r.segs),
		[]confdoc.Edit{{Doc: r.doc, Op: confdoc.OpSet, Path: confdoc.FormatPath(r.segs), Value: !on}}, nil)
}

// setPickEnum offers the values a setting may have.
func (m *app) setPickEnum(r setRow) {
	pk := &picker{title: "Choose " + oneLine(r.f.Label), hint: "enter chooses; d on the setting restores the default" + enumHint(r.f.Path), crumb: lastSeg(r.segs)}
	for _, v := range r.f.Enum {
		it := pickItem{value: v, label: enumLabel(r.f.Path, v)}
		switch {
		case r.set && r.value == v:
			it.detail = "now"
		case r.f.Default == v:
			it.detail = "default"
		}
		it.detail = enumNote(r.f.Path, v, it.detail)
		pk.items = append(pk.items, it)
	}
	pk.vp.reset(len(pk.items))
	if i := slices.IndexFunc(pk.items, func(it pickItem) bool { return it.value == r.value }); i >= 0 {
		pk.vp.to(i)
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		return m.previewSettings(fmt.Sprintf("set %s to %s", r.f.Label, enumLabel(r.f.Path, vals[0])), lastSeg(r.segs),
			[]confdoc.Edit{{Doc: r.doc, Op: confdoc.OpSet, Path: confdoc.FormatPath(r.segs), Value: vals[0]}}, nil)
	}
	m.set.pick = pk
}

// settingHint says what a value of the setting may be, in one line.
func settingHint(f confdoc.Field, secret bool) string {
	if h := horizonHint(f.Path); h != "" {
		return h
	}
	var hint string
	switch f.Type {
	case confdoc.TypeDuration:
		hint = "a duration such as 30s, 5m or 2h"
		if f.Min != nil {
			hint += fmt.Sprintf(", at least %s", formatSpan(time.Duration(*f.Min*float64(time.Second))))
		}
	case confdoc.TypeInt, confdoc.TypeFloat:
		hint = "a whole number"
		if f.Type == confdoc.TypeFloat {
			hint = "a number"
		}
		switch {
		case f.Min != nil && f.Max != nil:
			hint += fmt.Sprintf(" from %g to %g", *f.Min, *f.Max)
		case f.Min != nil:
			hint += fmt.Sprintf(", at least %g", *f.Min)
		}
	case confdoc.TypeEnvRef:
		hint = "the NAME of an environment variable, never the secret itself; the daemon reads it from its environment"
	case confdoc.TypeBool:
		hint = "yes or no"
	case confdoc.TypeEnum:
		hint = "one of " + strings.Join(f.Enum, ", ")
	case confdoc.TypeList:
		hint = "values separated by commas"
	default:
		if secret {
			hint = "text; what you type is hidden, and the current value is never shown"
		}
	}
	return hint
}

// fieldHint is what a field of a form for a new item wants: its help, then its kind.
func fieldHint(f confdoc.Field, secret bool) string {
	kind := settingHint(f, secret)
	help := strings.TrimSuffix(strings.TrimSpace(f.Help), ".")
	switch {
	case help == "":
		return kind
	case kind == "":
		return help
	}
	return help + " (" + kind + ")"
}

// setPrompt asks for a new value of a setting. A secret is never put into the
// box and what is typed is hidden.
func (m *app) setPrompt(r setRow) {
	f := r.f
	fl := field{label: f.Label, secret: r.secret}
	if r.set && !r.secret {
		fl.in.set(r.value)
	}
	hint := settingHint(f, r.secret)
	if hint == "" {
		hint = "text"
	}
	switch {
	case r.set && f.Default != "" && !r.secret:
		hint += "; empty restores the default (" + oneLine(f.Default) + ")"
	case r.set:
		hint += "; empty removes the value"
	case f.Default != "":
		hint += "; default " + oneLine(f.Default)
	}
	path := confdoc.FormatPath(r.segs)
	m.prm = &prompt{kind: pkSetting, crumb: lastSeg(r.segs), title: oneLine("Change " + f.Label + ": " + path), hint: hint, fields: []field{fl},
		sbuild: func(v []string) (string, []confdoc.Edit, error) {
			if v[0] == "" {
				if !r.set {
					return "", nil, errors.New("type a value; nothing is set, so the default applies")
				}
				return unsetLabel(r), []confdoc.Edit{{Doc: r.doc, Op: confdoc.OpUnset, Path: path}}, nil
			}
			label := "set " + f.Label + " to " + v[0]
			if r.secret {
				label = "change " + f.Label // a secret is never written into a label
			}
			return label, []confdoc.Edit{{Doc: r.doc, Op: confdoc.OpSet, Path: path, Value: v[0]}}, nil
		}}
}

// setEditItem changes one item of a list or map of plain values.
func (m *app) setEditItem(n setNode, r setRow) tea.Cmd {
	path := confdoc.FormatPath(r.segs)
	if n.f.Type == confdoc.TypeList && len(n.f.Enum) > 0 {
		m.setPickAdd(n, r)
		return nil
	}
	fl := field{label: "Value", secret: r.secret}
	if !r.secret {
		if n.f.Type == confdoc.TypeList {
			fl.in.set(r.label)
		} else {
			fl.in.set(r.value)
		}
	}
	m.prm = &prompt{kind: pkSetting, crumb: lastSeg(r.segs), title: oneLine("Change an item of " + n.f.Label), hint: settingHint(confdoc.Field{Type: n.f.Elem, Enum: n.f.Enum}, r.secret) + "; x removes the item",
		fields: []field{fl},
		sbuild: func(v []string) (string, []confdoc.Edit, error) {
			if v[0] == "" {
				return "", nil, errors.New("type a value, or press x on the item to remove it")
			}
			label := "change " + oneLine(lastSeg(r.segs)) + " in " + n.f.Label
			return label, []confdoc.Edit{{Doc: r.doc, Op: confdoc.OpSet, Path: path, Value: v[0]}}, nil
		}}
	return nil
}

// setPickAdd offers the values of a list of choices that it does not have yet;
// for an item it replaces, that item.
func (m *app) setPickAdd(n setNode, replace setRow) {
	have, _ := m.set.mdl.get(n.f.Doc, n.segs)
	pk := &picker{title: "Choose a value for " + oneLine(n.f.Label), hint: "enter chooses", crumb: lastSeg(n.segs)}
	for _, v := range n.f.Enum {
		if !slices.Contains(have.items, v) {
			pk.items = append(pk.items, pickItem{value: v, label: v})
		}
	}
	if len(pk.items) == 0 {
		m.fail("every value is in the list already")
		return
	}
	pk.vp.reset(len(pk.items))
	doc := m.set.mdl.docFor(n.f.Doc, n.segs)
	pk.done = func(m *app, vals []string) tea.Cmd {
		if replace.kind == rowItem {
			return m.previewSettings(fmt.Sprintf("change an item of %s to %s", n.f.Label, vals[0]), n.crumb,
				[]confdoc.Edit{{Doc: doc, Op: confdoc.OpSet, Path: confdoc.FormatPath(replace.segs), Value: vals[0]}}, nil)
		}
		return m.previewSettings(fmt.Sprintf("add %s to %s", vals[0], n.f.Label), lastSeg(n.segs),
			[]confdoc.Edit{{Doc: doc, Op: confdoc.OpAppend, Path: confdoc.FormatPath(n.segs), Value: vals[0]}}, nil)
	}
	m.set.pick = pk
}

// ---- adding ----

// addForms are the settings the form for a new item asks for, after the key
// that names it: enough for the item to be valid. The rest are rows to change
// once it exists.
var addForms = map[string][]string{
	"policy.rules":            {"name", "fix_within", "owner_within"},
	"access":                  {"projects", "write"},
	"sources":                 {"id", "type", "url"},
	"techs":                   {"name", "title"},
	"techs.*.feeds":           {"id", "type", "url"},
	"techs.*.detect.packages": {"ecosystem", "name"},
	"techs.*.detect.versions": {"file", "pattern"},
}

// mapKeys name the key of a map of records, which has no row of its own.
var mapKeys = map[string]string{"access": "Actor"}

type addField struct {
	field confdoc.Field
	rest  []string // where the value goes inside the new item; nil for the key of a map
}

func (m *app) setAdd(n setNode) tea.Cmd {
	switch {
	case isTechList(n):
		return m.setTechAdd()
	case isRecords(n.f):
		m.setAddRecord(n)
	case n.f.Type == confdoc.TypeMap:
		m.setAddEntry(n)
	case len(n.f.Enum) > 0:
		m.setPickAdd(n, setRow{})
	default:
		path := confdoc.FormatPath(n.segs)
		doc := m.set.mdl.docFor(n.f.Doc, n.segs)
		m.prm = &prompt{kind: pkSetting, crumb: lastSeg(n.segs), title: oneLine("Add to " + n.f.Label), hint: settingHint(confdoc.Field{Type: n.f.Elem}, false),
			fields: []field{{label: "Value"}},
			sbuild: func(v []string) (string, []confdoc.Edit, error) {
				if v[0] == "" {
					return "", nil, errors.New("type a value")
				}
				return "add " + v[0] + " to " + n.f.Label, []confdoc.Edit{{Doc: doc, Op: confdoc.OpAppend, Path: path, Value: v[0]}}, nil
			}}
	}
	return nil
}

// setAddEntry asks for the key and value of a new entry in a map.
func (m *app) setAddEntry(n setNode) {
	path := n.segs
	doc := m.set.mdl.docFor(n.f.Doc, n.segs)
	secret := n.f.Secret
	elem := confdoc.Field{Type: n.f.Elem, Min: n.f.Min, Max: n.f.Max}
	m.prm = &prompt{kind: pkSetting, crumb: lastSeg(n.segs), title: oneLine("Add to " + n.f.Label), hint: n.f.Help,
		fields: []field{{label: "Name", hint: "the name of the entry, such as a host or a header"}, {label: "Value", secret: secret, hint: fieldHint(elem, secret)}},
		sbuild: func(v []string) (string, []confdoc.Edit, error) {
			switch {
			case v[0] == "":
				return "", nil, errors.New("give the entry a name")
			case v[1] == "":
				return "", nil, errors.New("give the entry a value")
			case slices.Contains(m.set.mdl.children("", path), v[0]):
				return "", nil, fmt.Errorf("%s is in the list already: select it to change it", v[0])
			}
			label := "add " + v[0] + " to " + n.f.Label
			return label, []confdoc.Edit{{Doc: doc, Op: confdoc.OpSet, Path: confdoc.FormatPath(append(slices.Clone(path), v[0])), Value: v[1]}}, nil
		}}
}

// setAddRecord asks for what a new item of a list or map of records needs.
func (m *app) setAddRecord(n setNode) {
	pat := n.f.Path + ".*"
	var fs []addField
	if n.f.Type == confdoc.TypeMap {
		fs = append(fs, addField{field: confdoc.Field{Label: mapKeys[n.f.Path], Type: confdoc.TypeString, Help: "the name of the actor, as the audit log writes it"}})
		if fs[0].field.Label == "" {
			fs[0].field.Label = "Name"
		}
	}
	rests := slices.Clone(addForms[n.f.Path])
	if n.f.Key != "" {
		rests = slices.DeleteFunc(rests, func(r string) bool { return r == n.f.Key })
		rests = append([]string{n.f.Key}, rests...)
	}
	for _, rest := range rests {
		for _, f := range settingsSchema {
			if f.Doc == n.f.Doc && f.Path == pat+"."+rest {
				fs = append(fs, addField{field: f, rest: strings.Split(rest, ".")})
			}
		}
	}
	var fields []field
	for _, af := range fs {
		fields = append(fields, field{label: af.field.Label, secret: af.field.Secret, hint: fieldHint(af.field, af.field.Secret)})
	}
	doc := m.set.mdl.docFor(n.f.Doc, n.segs)
	if len(n.segs) == 1 && n.f.Doc == confdoc.KindSources {
		doc = ""
	}
	m.prm = &prompt{kind: pkSetting, crumb: lastSeg(n.segs), title: oneLine("Add to " + n.f.Label), hint: "enter goes to the next field, the last one previews; the rest is set afterwards, row by row",
		fields: fields,
		sbuild: func(v []string) (string, []confdoc.Edit, error) {
			rec := map[string]any{}
			key := ""
			for i, af := range fs {
				switch {
				case af.rest == nil:
					key = v[i]
				case v[i] != "":
					setNested(rec, af.rest, v[i])
					if af.rest[len(af.rest)-1] == n.f.Key && len(af.rest) == 1 {
						key = v[i]
					}
				}
			}
			if key == "" && (n.f.Key != "" || n.f.Type == confdoc.TypeMap) {
				return "", nil, errors.New("give the new item a " + strings.ToLower(fs[0].field.Label))
			}
			for _, seg := range m.set.mdl.children("", n.segs) {
				if strings.EqualFold(itemName(seg), key) && key != "" {
					return "", nil, fmt.Errorf("%s exists already: select it to change it", key)
				}
			}
			label := "add " + key + " to " + n.f.Label
			if key == "" {
				label = "add an item to " + n.f.Label
			}
			if n.f.Type == confdoc.TypeMap {
				return label, []confdoc.Edit{{Doc: doc, Op: confdoc.OpSet, Path: confdoc.FormatPath(append(slices.Clone(n.segs), key)), Value: rec}}, nil
			}
			return label, []confdoc.Edit{{Doc: doc, Op: confdoc.OpAppend, Path: confdoc.FormatPath(n.segs), Value: rec}}, nil
		}}
}

// setNested puts v at rest inside rec, making the mappings on the way.
func setNested(rec map[string]any, rest []string, v any) {
	for _, k := range rest[:len(rest)-1] {
		sub, _ := rec[k].(map[string]any)
		if sub == nil {
			sub = map[string]any{}
			rec[k] = sub
		}
		rec = sub
	}
	rec[rest[len(rest)-1]] = v
}

// ---- the editor ----

// defaultDoc is the document a section lives in; for the feeds, the first file of them.
func (m *setModel) defaultDoc(section string) string {
	switch section {
	case confdoc.SecTechs:
		return confdoc.IDTechs
	case confdoc.SecSources:
		for _, id := range m.userDocs {
			if strings.HasPrefix(id, "sources/") && m.docs[id].Exists {
				return id
			}
		}
		return ""
	}
	return confdoc.IDSettings
}

// editorTarget is the file and line the editor opens at: the problem under the
// cursor, else the document of the row.
func (s *settingsState) editorTarget() (id, file string, line int, why string) {
	if s.mdl == nil {
		return "", "", 0, "the settings are not read yet"
	}
	if r, ok := s.row(); ok {
		switch {
		case r.kind == rowIssue:
			id, line = r.issue.Doc, r.issue.Line
		case r.issue != nil:
			id, line = r.issue.Doc, r.issue.Line
		case r.kind == rowSection:
			id = s.mdl.defaultDoc(r.label)
		default:
			id = r.doc
		}
	}
	if id == "" {
		if lv := s.level(); lv != nil {
			id = s.mdl.defaultDoc(lv.node.section)
		}
	}
	switch {
	case id == "":
		return "", "", 0, "there is no file for this yet; add an entry first"
	case strings.HasPrefix(id, "projects/"):
		return id, "", 0, "that is a project file: select the project on the Projects screen and press E there"
	}
	path, ok := s.mdl.docPath(id)
	if !ok {
		return id, "", 0, displayDoc(id) + " does not exist yet"
	}
	return id, path, line, ""
}

// openSettingsEditor opens the file of the selected row in the editor, then reads
// the settings again. A broken file can only be repaired this way.
func (m *app) openSettingsEditor() tea.Cmd {
	s := &m.set
	if s.denied != "" {
		m.fail("the settings are not available to you")
		return nil
	}
	if s.write != nil && !s.rules {
		m.fail("the files cannot be changed here: " + denyText(s.write))
		return nil
	}
	id, file, line, why := s.editorTarget()
	if why != "" {
		m.fail(why)
		return nil
	}
	return m.launchEditor(file, line, "editing "+displayDoc(id)+"...", reList|reSettings)
}
