package tui

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// The model of the Settings screen: the documents ops hands over, arranged by
// the schema into sections, records and fields. It does no drawing and holds
// no state of the screen, so it can be tested on its own.

var settingsSchema = confdoc.Schema()

// setVal is one value written in a user document. A secret has no text.
type setVal struct {
	doc    string
	kind   string
	segs   []string
	value  string
	items  []string // for a list of plain values
	secret bool
}

// setIssue is a problem with the position-based path of its field replaced by
// the key-based one the values use, and the section it belongs to.
type setIssue struct {
	confdoc.Issue
	kind    string
	segs    []string
	section string
}

type setModel struct {
	vals     []setVal
	docs     map[string]ops.DocView
	userDocs []string // the editable documents, in the order ops lists them
	issues   []setIssue
	interval time.Duration
}

func docKind(id string) string {
	switch {
	case id == confdoc.IDSettings:
		return confdoc.KindSettings
	case id == confdoc.IDTechs:
		return confdoc.KindTechs
	case strings.HasPrefix(id, "sources/"):
		return confdoc.KindSources
	}
	return ""
}

func defaultSection(kind string) string {
	switch kind {
	case confdoc.KindSettings:
		return confdoc.SecCore
	case confdoc.KindTechs:
		return confdoc.SecTechs
	case confdoc.KindSources:
		return confdoc.SecSources
	}
	return ""
}

func newSetModel(v ops.SettingsView) *setModel {
	m := &setModel{docs: map[string]ops.DocView{}, interval: config.Defaults().Interval}
	for _, d := range v.Docs {
		m.docs[d.ID] = d
		if d.Layer != confdoc.LayerUser {
			continue
		}
		m.userDocs = append(m.userDocs, d.ID)
		for _, e := range d.Entries {
			segs, err := confdoc.ParsePath(e.Path)
			if err != nil {
				continue
			}
			val := setVal{doc: d.ID, kind: d.Kind, segs: segs, secret: e.Secret, value: e.Value, items: e.Items}
			m.vals = append(m.vals, val)
			if d.ID == confdoc.IDSettings && e.Path == "interval" {
				if iv, err := time.ParseDuration(e.Value); err == nil && iv > 0 {
					m.interval = iv
				}
			}
		}
	}
	broken := map[string]bool{}
	for _, is := range v.Issues {
		is = horizonIssue(is)
		si := setIssue{Issue: is, kind: docKind(is.Doc)}
		if is.Field != "" && si.kind != "" {
			if segs, err := confdoc.ParsePath(is.Field); err == nil {
				si.segs = m.canon(is.Doc, si.kind, segs)
				si.Field = confdoc.FormatPath(si.segs)
			}
		}
		si.section = defaultSection(si.kind)
		if len(si.segs) > 0 {
			if sec := sectionOf(si.kind, si.segs); sec != "" {
				si.section = sec
			}
		}
		if is.Level == confdoc.LevelError {
			broken[is.Doc] = true
		}
		m.issues = append(m.issues, si)
	}
	// a document that cannot be parsed must show up even when no issue names it
	for _, d := range v.Docs {
		if d.Error != "" && !broken[d.ID] {
			m.issues = append(m.issues, setIssue{Issue: confdoc.Issue{Level: confdoc.LevelError, Doc: d.ID, Message: d.Error},
				kind: docKind(d.ID), section: defaultSection(docKind(d.ID))})
		}
	}
	slices.SortStableFunc(m.issues, func(a, b setIssue) int { return levelRank(b.Level) - levelRank(a.Level) })
	return m
}

func levelRank(l confdoc.Level) int {
	switch l {
	case confdoc.LevelError:
		return 2
	case confdoc.LevelWarning:
		return 1
	}
	return 0
}

// canon writes a path that counts list items by position with the key of the item.
func (m *setModel) canon(doc, kind string, segs []string) []string {
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		if n, err := strconv.Atoi(seg); err == nil && n >= 0 {
			if f, ok := fieldAt(kind, out); ok && f.Type == confdoc.TypeList && f.Elem == confdoc.TypeRecord {
				if kids := m.children(doc, out); n < len(kids) {
					seg = kids[n]
				}
			}
		}
		out = append(out, seg)
	}
	return out
}

func hasPrefix(segs, prefix []string) bool {
	return len(segs) >= len(prefix) && slices.Equal(segs[:len(prefix)], prefix)
}

// children are the next segments below prefix, in the order the document has them.
func (m *setModel) children(doc string, prefix []string) []string {
	var out []string
	for _, v := range m.vals {
		if (doc != "" && v.doc != doc) || len(v.segs) <= len(prefix) || !hasPrefix(v.segs, prefix) {
			continue
		}
		if seg := v.segs[len(prefix)]; !slices.Contains(out, seg) {
			out = append(out, seg)
		}
	}
	return out
}

// has says some value is written at or below segs.
func (m *setModel) has(kind string, segs []string) bool {
	for _, v := range m.vals {
		if v.kind == kind && hasPrefix(v.segs, segs) {
			return true
		}
	}
	return false
}

func (m *setModel) get(kind string, segs []string) (setVal, bool) {
	for _, v := range m.vals {
		if v.kind == kind && slices.Equal(v.segs, segs) {
			return v, true
		}
	}
	return setVal{}, false
}

// docFor is the document an edit of the value at segs goes to. Empty lets
// confdoc choose, which for a new feed is sources/custom.
func (m *setModel) docFor(kind string, segs []string) string {
	switch kind {
	case confdoc.KindSettings:
		return confdoc.IDSettings
	case confdoc.KindTechs:
		return confdoc.IDTechs
	}
	for _, v := range m.vals {
		if v.kind == kind && hasPrefix(v.segs, segs) {
			return v.doc
		}
	}
	for n := len(segs) - 1; n >= 1; n-- {
		for _, v := range m.vals {
			if v.kind == kind && hasPrefix(v.segs, segs[:n]) {
				return v.doc
			}
		}
	}
	return ""
}

// ---- the schema, arranged ----

// fieldAt is the schema row of a concrete path, or the element of a list or
// map field when the path names one item of it.
func fieldAt(kind string, segs []string) (confdoc.Field, bool) {
	if len(segs) == 0 {
		return confdoc.Field{}, false
	}
	if f, ok := confdoc.Lookup(kind, confdoc.FormatPath(segs)); ok {
		return f, true
	}
	if len(segs) >= 2 {
		c, ok := confdoc.Lookup(kind, confdoc.FormatPath(segs[:len(segs)-1]))
		if ok && (c.Type == confdoc.TypeList || c.Type == confdoc.TypeMap) && c.Elem != "" {
			return confdoc.Field{Path: c.Path + ".*", Doc: kind, Section: c.Section, Label: c.Label, Type: c.Elem, Enum: c.Enum, Min: c.Min, Max: c.Max, Key: c.Key}, true
		}
	}
	return confdoc.Field{}, false
}

func sectionOf(kind string, segs []string) string {
	for k := len(segs); k >= 1; k-- {
		if f, ok := fieldAt(kind, segs[:k]); ok && f.Section != "" {
			return f.Section
		}
	}
	return ""
}

// within is whether g lies below f in the document: f is a collection that holds it.
func within(f, g confdoc.Field) bool {
	return f.Doc == g.Doc && f.Path != g.Path && strings.HasPrefix(g.Path, f.Path+".")
}

func sectionRoots(section string) []confdoc.Field {
	var out []confdoc.Field
	for _, f := range settingsSchema {
		if f.Section == section && !slices.ContainsFunc(settingsSchema, func(g confdoc.Field) bool { return within(g, f) }) {
			out = append(out, f)
		}
	}
	return out
}

// childFields are the fields directly in the record with the schema path pat:
// the rows below it that no collection in between holds.
func childFields(kind, pat string) []confdoc.Field {
	var out []confdoc.Field
	for _, f := range settingsSchema {
		if f.Doc != kind || !strings.HasPrefix(f.Path, pat+".") {
			continue
		}
		if !slices.ContainsFunc(settingsSchema, func(g confdoc.Field) bool { return within(g, f) && strings.HasPrefix(g.Path, pat+".") }) {
			out = append(out, f)
		}
	}
	return out
}

func isCollection(f confdoc.Field) bool {
	return (f.Type == confdoc.TypeList || f.Type == confdoc.TypeMap) && f.Elem != ""
}

func isRecords(f confdoc.Field) bool { return isCollection(f) && f.Elem == confdoc.TypeRecord }

// ---- nodes: the places the screen can be in ----

type nodeKind int

const (
	nodeSection nodeKind = iota // the fields of a section
	nodeColl                    // the items of a list or map
	nodeRecord                  // the fields of one item of a list or map of records
)

type setNode struct {
	kind    nodeKind
	crumb   string // what the breadcrumb calls it
	title   string
	section string
	f       confdoc.Field // nodeColl: the collection; nodeRecord: the item
	segs    []string
}

func (n setNode) same(o setNode) bool {
	return n.kind == o.kind && n.f.Doc == o.f.Doc && n.f.Path == o.f.Path && slices.Equal(n.segs, o.segs)
}

// sectionNode is the first level of a section. A section that is only one list
// of records (the policy rules, the access rules, the feeds) opens on its items.
func sectionNode(sec string) setNode {
	roots := sectionRoots(sec)
	if len(roots) == 1 && isCollection(roots[0]) {
		f := roots[0]
		return setNode{kind: nodeColl, crumb: sec, title: f.Label, section: sec, f: f, segs: strings.Split(f.Path, ".")}
	}
	return setNode{kind: nodeSection, crumb: sec, title: sec, section: sec}
}

// nodeAt is the node that lists what is at segs, when there is something to list.
func nodeAt(kind string, segs []string) (setNode, bool) {
	f, ok := fieldAt(kind, segs)
	if !ok {
		return setNode{}, false
	}
	last := segs[len(segs)-1]
	switch {
	case isCollection(f):
		return setNode{kind: nodeColl, crumb: last, title: f.Label, section: f.Section, f: f, segs: segs}, true
	case f.Type == confdoc.TypeRecord:
		return setNode{kind: nodeRecord, crumb: itemName(last), title: itemName(last), section: f.Section, f: f, segs: segs}, true
	}
	return setNode{}, false
}

// itemName is how an item of a list or map is called: its key, else its place.
func itemName(seg string) string {
	if _, v, ok := strings.Cut(seg, "="); ok && v != "" {
		return v
	}
	if n, err := strconv.Atoi(seg); err == nil {
		return "#" + strconv.Itoa(n+1)
	}
	return seg
}

// locate finds the levels that lead to the setting at path and the row that
// stands for it in the last of them.
func (m *setModel) locate(path string) (nodes []setNode, rowID string, ok bool) {
	segs, err := confdoc.ParsePath(path)
	if err != nil || len(segs) == 0 {
		return nil, "", false
	}
	kind := ""
	for _, k := range []string{confdoc.KindSettings, confdoc.KindTechs, confdoc.KindSources} {
		if sectionOf(k, segs) != "" {
			kind = k
			break
		}
	}
	if kind == "" {
		return nil, "", false
	}
	segs = m.canon("", kind, segs)
	nodes = []setNode{sectionNode(sectionOf(kind, segs))}
	for i := 1; i < len(segs); i++ {
		if n, ok := nodeAt(kind, segs[:i]); ok && !n.same(nodes[len(nodes)-1]) {
			nodes = append(nodes, n)
		}
	}
	return nodes, kind + "|" + confdoc.FormatPath(segs), true
}

// ---- rows ----

type rowKind int

const (
	rowField   rowKind = iota // a setting, set or not
	rowItem                   // one item of a list or map
	rowAdd                    // the row that adds an item
	rowSection                // a section on the first level
	rowIssue                  // a problem on the first level
)

type setRow struct {
	id       string
	kind     rowKind
	label    string
	value    string
	typ      string
	f        confdoc.Field
	segs     []string
	doc      string // the document an edit goes to
	set      bool   // the file has a value
	dflt     bool   // value is the default, which the file does not say
	secret   bool
	inactive bool          // the setting has no effect with the other settings as they are
	level    confdoc.Level // the worst problem at or below the row
	issue    *setIssue     // the first problem at or below it; for rowIssue, the problem
	count    int           // rowSection: values set
	errs     int           // rowSection: errors
	warns    int
}

func typeText(f confdoc.Field) string {
	switch {
	case f.Type == confdoc.TypeList && f.Elem == confdoc.TypeRecord:
		return "records"
	case f.Type == confdoc.TypeMap && f.Elem == confdoc.TypeRecord:
		return "records"
	case f.Type == confdoc.TypeList:
		return "list"
	case f.Type == confdoc.TypeMap:
		return "map"
	}
	return string(f.Type)
}

func (m *setModel) issueAt(kind string, segs []string) (lvl confdoc.Level, first *setIssue) {
	for i := range m.issues {
		is := &m.issues[i]
		if is.kind != kind || len(is.segs) == 0 || !hasPrefix(is.segs, segs) {
			continue
		}
		if first == nil || levelRank(is.Level) > levelRank(lvl) {
			lvl, first = is.Level, is
		}
	}
	return lvl, first
}

func rowID(kind string, segs []string) string { return kind + "|" + confdoc.FormatPath(segs) }

// fieldRow is the row of the setting f found at segs.
func (m *setModel) fieldRow(f confdoc.Field, segs []string) setRow {
	r := setRow{id: rowID(f.Doc, segs), kind: rowField, label: f.Label, typ: typeText(f), f: f, segs: segs, doc: m.docFor(f.Doc, segs), secret: f.Secret}
	r.level, r.issue = m.issueAt(f.Doc, segs)
	switch {
	case isRecords(f):
		var names []string
		for _, seg := range m.children("", segs) {
			names = append(names, itemName(seg))
		}
		r.set, r.value = len(names) > 0, strings.Join(names, ", ")
	case f.Type == confdoc.TypeMap:
		var parts []string
		for _, seg := range m.children("", segs) {
			v, _ := m.get(f.Doc, append(slices.Clone(segs), seg))
			parts = append(parts, seg+"="+secretText(v, f.Secret))
		}
		r.set, r.value = len(parts) > 0, strings.Join(parts, ", ")
	default:
		v, ok := m.get(f.Doc, segs)
		r.set = ok
		switch {
		case ok && f.Secret:
			r.value = confdoc.SecretShown
		case ok && len(v.items) > 0:
			r.value = strings.Join(v.items, ", ")
		case ok:
			r.value = v.value
		case f.Secret:
			r.value = "(not set)"
		case f.Default != "":
			r.value, r.dflt = f.Default, true
		}
	}
	if r.value == "" {
		r.value, r.dflt = "-", true
	}
	m.horizonRow(&r)
	return r
}

func secretText(v setVal, secret bool) string {
	if secret {
		return confdoc.SecretShown
	}
	return v.value
}

// itemRow is the row of one item of the collection n.
func (m *setModel) itemRow(n setNode, seg string, plain bool) setRow {
	segs := append(slices.Clone(n.segs), seg)
	r := setRow{id: rowID(n.f.Doc, segs), kind: rowItem, label: itemName(seg), f: n.f, segs: segs, doc: m.docFor(n.f.Doc, segs), set: true}
	r.level, r.issue = m.issueAt(n.f.Doc, segs)
	switch {
	case isRecords(n.f):
		r.value = m.summary(n.f.Doc, n.f.Path+".*", segs, n.f.Key)
	case plain: // a map entry: the value is the row's
		v, _ := m.get(n.f.Doc, segs)
		r.value, r.secret = secretText(v, n.f.Secret), n.f.Secret
	}
	return r
}

// summary lists the scalar values an item has, as short as they can be said.
func (m *setModel) summary(kind, pat string, segs []string, key string) string {
	var parts []string
	for _, c := range childFields(kind, pat) {
		rest := strings.Split(strings.TrimPrefix(c.Path, pat+"."), ".")
		if c.Secret || isCollection(c) || (key != "" && len(rest) == 1 && rest[0] == key) {
			continue
		}
		if v, ok := m.get(kind, append(slices.Clone(segs), rest...)); ok {
			text := v.value
			if len(v.items) > 0 {
				text = strings.Join(v.items, "+")
			}
			parts = append(parts, rest[len(rest)-1]+"="+text)
		}
	}
	return strings.Join(parts, ", ")
}

// rows lists what is in a node.
func (m *setModel) rows(n setNode) []setRow {
	var rows []setRow
	switch n.kind {
	case nodeSection:
		for _, f := range sectionRoots(n.section) {
			rows = append(rows, m.fieldRow(f, strings.Split(f.Path, ".")))
		}
	case nodeRecord:
		pat := n.f.Path
		for _, f := range childFields(n.f.Doc, pat) {
			rows = append(rows, m.fieldRow(f, append(slices.Clone(n.segs), strings.Split(strings.TrimPrefix(f.Path, pat+"."), ".")...)))
		}
	default:
		doc := m.docFor(n.f.Doc, n.segs)
		switch {
		case isRecords(n.f):
			for _, seg := range m.children("", n.segs) {
				rows = append(rows, m.itemRow(n, seg, false))
			}
		case n.f.Type == confdoc.TypeMap:
			for _, seg := range m.children("", n.segs) {
				rows = append(rows, m.itemRow(n, seg, true))
			}
		default:
			v, _ := m.get(n.f.Doc, n.segs)
			for _, it := range v.items {
				segs := append(slices.Clone(n.segs), "="+it)
				r := setRow{id: rowID(n.f.Doc, segs), kind: rowItem, label: it, f: n.f, segs: segs, doc: doc, set: true, secret: n.f.Secret}
				if n.f.Secret {
					r.label = confdoc.SecretShown
				}
				r.level, r.issue = m.issueAt(n.f.Doc, n.segs)
				rows = append(rows, r)
			}
		}
		if len(n.segs) == 1 && n.f.Doc == confdoc.KindSources {
			doc = "" // a new feed goes where confdoc puts it
		}
		rows = append(rows, setRow{id: "+", kind: rowAdd, label: "+ add to " + n.f.Label, f: n.f, segs: n.segs, doc: doc})
	}
	return rows
}

// ---- sections and problems ----

func (m *setModel) sections() []setRow {
	var out []setRow
	for _, name := range confdoc.Sections() {
		r := setRow{id: "sec:" + name, kind: rowSection, label: name}
		for _, v := range m.vals {
			if sectionOf(v.kind, v.segs) == name {
				r.count++
			}
		}
		for _, is := range m.issues {
			if is.section != name {
				continue
			}
			if is.Level == confdoc.LevelError {
				r.errs++
			} else {
				r.warns++
			}
		}
		out = append(out, r)
	}
	return out
}

// problems lists the issues as rows, errors first.
func (m *setModel) problems() []setRow {
	var out []setRow
	for i := range m.issues {
		is := &m.issues[i]
		out = append(out, setRow{id: "issue:" + strconv.Itoa(i) + is.Doc + is.Field + is.Message, kind: rowIssue, issue: is, level: is.Level})
	}
	return out
}

func (m *setModel) errorCount() int {
	n := 0
	for _, is := range m.issues {
		if is.Level == confdoc.LevelError {
			n++
		}
	}
	return n
}

// docPath is the file a document lives in, when it exists.
func (m *setModel) docPath(id string) (string, bool) {
	d, ok := m.docs[id]
	return d.Path, ok && d.Path != "" && d.Exists
}

// candidates are the settings a search can find: every field of a section, and
// every value written below the first level.
func (m *setModel) candidates() []setRow {
	var out []setRow
	seen := map[string]bool{}
	add := func(r setRow) {
		if !seen[r.id] {
			seen[r.id] = true
			out = append(out, r)
		}
	}
	for _, name := range confdoc.Sections() {
		for _, f := range sectionRoots(name) {
			add(m.fieldRow(f, strings.Split(f.Path, ".")))
		}
	}
	for _, v := range m.vals {
		if f, ok := fieldAt(v.kind, v.segs); ok && len(v.segs) > 1 {
			add(m.fieldRow(f, v.segs))
		}
	}
	return out
}

// search lists the settings the text names by label, path or section, for the
// filter on the first level.
func (m *setModel) search(text string) []setRow {
	q := strings.ToLower(strings.TrimSpace(text))
	var out []setRow
	for _, r := range m.candidates() {
		for _, n := range []string{r.f.Label, confdoc.FormatPath(r.segs), r.f.Section + " " + r.f.Label} {
			if strings.Contains(strings.ToLower(n), q) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
