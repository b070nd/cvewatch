package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/ops"
)

const settingsUsage = `usage: cvewatch settings <command>
  list [-json] [SECTION]            the values set in config.yaml, techs.yaml and sources/*.yaml, by section
  get [-json] PATH                  one value (or everything below a path), with the default when unset
  set PATH VALUE [-yes]             change a value
  unset PATH [-yes]                 remove a value, so the default applies
  add PATH VALUE [-yes]             append to a list, for example policy.rules or notify.digest.channels
  diff set|unset|add PATH [VALUE]   show what an edit would change (set, unset and add do this unless -yes)
  schema [-json] [SECTION]          every setting: path, type, allowed values and help
A VALUE that starts with { or [ is read as JSON, for lists and records. Secret values show as (set).
-doc ID picks the document (config, techs, sources/NAME) when the path alone does not say.`

// settingsCmd works on the configuration documents. It opens them without
// loading the configuration, so it also works when config.yaml is broken.
func settingsCmd(root string, args []string) error {
	if len(args) == 0 {
		return errors.New(settingsUsage)
	}
	sub, rest := args[0], args[1:]
	if sub == "schema" {
		return settingsSchema(rest)
	}
	ss, err := ops.OpenSettings(root)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		return settingsList(ss, rest)
	case "get":
		return settingsGet(ss, rest)
	case "set", "unset", "add":
		return settingsEdit(ss, editOp(sub), rest, false)
	case "diff":
		if len(rest) == 0 || !slices.Contains([]string{"set", "unset", "add"}, rest[0]) {
			return errors.New("usage: cvewatch settings diff set|unset|add PATH [VALUE]")
		}
		return settingsEdit(ss, editOp(rest[0]), rest[1:], true)
	}
	return fmt.Errorf("unknown settings command %q\n%s", sub, settingsUsage)
}

// editOp maps the command word to the edit it makes.
func editOp(word string) confdoc.Op {
	if word == "add" {
		return confdoc.OpAppend
	}
	return confdoc.Op(word)
}

type settingRow struct {
	Section string   `json:"section"`
	Doc     string   `json:"doc"`
	Path    string   `json:"path"`
	Value   string   `json:"value,omitempty"`
	Items   []string `json:"items,omitempty"`
	Secret  bool     `json:"secret,omitempty"`
}

func (r settingRow) shown() string {
	if r.Items != nil {
		return strings.Join(r.Items, ", ")
	}
	return r.Value
}

// settingRows flattens the editable documents; shipped ones are reference only.
func settingRows(v ops.SettingsView) []settingRow {
	order := confdoc.Sections()
	var rows []settingRow
	for _, d := range v.Docs {
		if d.Layer != confdoc.LayerUser {
			continue
		}
		for _, e := range d.Entries {
			sec := "Other"
			if f, ok := confdoc.Lookup(d.Kind, e.Path); ok {
				sec = f.Section
			}
			rows = append(rows, settingRow{Section: sec, Doc: d.ID, Path: e.Path, Value: e.Value, Items: e.Items, Secret: e.Secret})
		}
	}
	rank := func(sec string) int {
		if i := slices.Index(order, sec); i >= 0 {
			return i
		}
		return len(order)
	}
	slices.SortStableFunc(rows, func(a, b settingRow) int { return rank(a.Section) - rank(b.Section) })
	return rows
}

func printIssues(issues []confdoc.Issue) {
	for _, i := range issues {
		where := strings.TrimSpace(i.Doc + " " + i.Field)
		fmt.Printf("%s: %s: %s\n", i.Level, where, i.Message)
	}
}

func sectionArg(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	for _, s := range confdoc.Sections() {
		if strings.EqualFold(s, name) {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown section %q (use %s)", name, strings.Join(confdoc.Sections(), ", "))
}

func settingsList(ss *ops.SettingsSession, args []string) error {
	fs := flag.NewFlagSet("settings list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := intermixed(fs, args)
	if err != nil {
		return err
	}
	section := ""
	if len(pos) > 0 {
		if section, err = sectionArg(strings.Join(pos, " ")); err != nil {
			return err
		}
	}
	v, err := ss.View()
	if err != nil {
		return err
	}
	var rows []settingRow
	for _, r := range settingRows(v) {
		if section == "" || r.Section == section {
			rows = append(rows, r)
		}
	}
	if *asJSON {
		return printJSON(map[string]any{"settings": rows, "issues": v.Issues})
	}
	last := ""
	for _, r := range rows {
		if r.Section != last {
			fmt.Println(r.Section)
			last = r.Section
		}
		fmt.Printf("  %s = %s\n", r.Path, r.shown())
	}
	for _, d := range v.Docs {
		if d.Error != "" {
			fmt.Printf("%s: cannot be read: %s\n", d.ID, d.Error)
		}
	}
	printIssues(v.Issues)
	if len(rows) == 0 {
		fmt.Println("nothing set here; the defaults apply. `cvewatch settings schema` lists every setting.")
	}
	return nil
}

func settingsGet(ss *ops.SettingsSession, args []string) error {
	fs := flag.NewFlagSet("settings get", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := intermixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: cvewatch settings get [-json] PATH")
	}
	segs, err := confdoc.ParsePath(pos[0])
	if err != nil {
		return err
	}
	path := confdoc.FormatPath(segs)
	v, err := ss.View()
	if err != nil {
		return err
	}
	var rows []settingRow
	for _, r := range settingRows(v) {
		if r.Path == path || strings.HasPrefix(r.Path, path+".") {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		var field *confdoc.Field
		for _, kind := range []string{confdoc.KindSettings, confdoc.KindTechs, confdoc.KindSources} {
			if f, ok := confdoc.Lookup(kind, path); ok {
				field = &f
				break
			}
		}
		if field == nil {
			return fmt.Errorf("unknown setting %q (cvewatch settings schema lists them)", path)
		}
		if *asJSON {
			return printJSON(map[string]any{"path": path, "set": false, "default": field.Default})
		}
		if field.Default != "" {
			fmt.Printf("%s = %s (default)\n", path, field.Default)
		} else {
			fmt.Printf("%s is not set\n", path)
		}
		return nil
	}
	if *asJSON {
		return printJSON(map[string]any{"path": path, "set": true, "settings": rows})
	}
	for _, r := range rows {
		fmt.Printf("%s = %s\n", r.Path, r.shown())
	}
	return nil
}

func settingsSchema(args []string) error {
	fs := flag.NewFlagSet("settings schema", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := intermixed(fs, args)
	if err != nil {
		return err
	}
	section, err := sectionArg(strings.Join(pos, " "))
	if err != nil {
		return err
	}
	var fields []confdoc.Field
	for _, f := range confdoc.Schema() {
		if section == "" || f.Section == section {
			fields = append(fields, f)
		}
	}
	if *asJSON {
		return printJSON(fields)
	}
	last := ""
	for _, f := range fields {
		if f.Section != last {
			fmt.Println(f.Section)
			last = f.Section
		}
		typ := string(f.Type)
		switch {
		case len(f.Enum) > 0:
			typ += " (" + strings.Join(f.Enum, "|") + ")"
		case f.Elem != "":
			typ += " of " + string(f.Elem)
		}
		extra := ""
		if f.Default != "" {
			extra += " [default " + f.Default + "]"
		}
		if f.Secret {
			extra += " [secret]"
		}
		fmt.Printf("  %-34s %-14s %s%s\n", f.Path, typ, f.Help, extra)
	}
	return nil
}

// settingValue reads a command-line value: JSON for a list or a record, else text
// that the schema converts to the setting's type.
func settingValue(v string) any {
	if t := strings.TrimSpace(v); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var out any
		if json.Unmarshal([]byte(t), &out) == nil {
			return out
		}
	}
	return v
}

func settingsEdit(ss *ops.SettingsSession, op confdoc.Op, args []string, previewOnly bool) error {
	fs := flag.NewFlagSet("settings "+string(op), flag.ContinueOnError)
	yes := fs.Bool("yes", false, "write the change; without it only show the diff")
	doc := fs.String("doc", "", "document ID, when the path does not say (config, techs, sources/NAME)")
	pos, err := intermixed(fs, args)
	if err != nil {
		return err
	}
	want := 2
	if op == confdoc.OpUnset {
		want = 1
	}
	if len(pos) != want {
		if op == confdoc.OpUnset {
			return errors.New("usage: cvewatch settings unset PATH [-yes]")
		}
		word := string(op)
		if op == confdoc.OpAppend {
			word = "add"
		}
		return fmt.Errorf("usage: cvewatch settings %s PATH VALUE [-yes]", word)
	}
	e := confdoc.Edit{Doc: *doc, Op: op, Path: pos[0]}
	if want == 2 {
		e.Value = settingValue(pos[1])
	}
	save := *yes && !previewOnly
	p, err := ss.Edit(ops.SettingsChange{Edits: []confdoc.Edit{e}, Save: save})
	if len(p.Diffs) > 0 {
		fmt.Println(p.Diff)
	}
	printIssues(p.Issues)
	switch {
	case err != nil:
		return err
	case p.Saved:
		fmt.Println("saved", strings.Join(p.Written, ", "))
		fmt.Println(p.Note)
	case len(p.Diffs) == 0:
		fmt.Println("no change")
	case save:
		fmt.Println("not saved")
	default:
		fmt.Println("not saved: add -yes to write this change")
	}
	return nil
}
