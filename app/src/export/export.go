// Package export is the versioned contract for everything that leaves the tool
// as data: the CLI export, list -json, the MCP server, tickets and audit
// packs. The JSON shape is described by docs/schema/export-v1.schema.json; a
// test keeps the two in step. Changing or removing a field means a new
// SchemaVersion; adding an optional one does not.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/query"
)

// SchemaVersion is the version of the JSON document and of the CSV columns.
const SchemaVersion = 1

// Document is a set of issues at one point in time.
type Document struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Count         int           `json:"count"`
	Issues        []query.Issue `json:"issues"`
}

// New wraps issues in a document. Lists that the schema declares as arrays are
// never null: nil targets, matches and articles become empty.
func New(issues []query.Issue, now time.Time) Document {
	out := make([]query.Issue, len(issues))
	for i, is := range issues {
		if is.Untrusted.Articles == nil {
			is.Untrusted.Articles = []query.Article{}
		}
		is.Targets = slices.Clone(is.Targets)
		if is.Targets == nil {
			is.Targets = []query.Target{}
		}
		for j := range is.Targets {
			if is.Targets[j].Matched == nil {
				is.Targets[j].Matched = []string{}
			}
		}
		out[i] = is
	}
	return Document{SchemaVersion: SchemaVersion, GeneratedAt: now.UTC(), Count: len(out), Issues: out}
}

// Formats lists the names Write accepts (markdown is an alias of md).
func Formats() []string { return []string{"json", "csv", "md"} }

// Write renders the document in the named format.
func Write(w io.Writer, format string, d Document) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return d.WriteJSON(w)
	case "csv":
		return d.WriteCSV(w)
	case "md", "markdown":
		return d.WriteMarkdown(w)
	}
	return fmt.Errorf("unknown export format %q (valid: %s)", format, strings.Join(Formats(), ", "))
}

// WriteJSON writes the document indented, fields in struct order.
func (d Document) WriteJSON(w io.Writer) error {
	if d.Issues == nil {
		d.Issues = []query.Issue{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

var csvHeader = []string{
	"id", "aliases", "severity", "cvss", "kev", "kev_due", "epss", "published", "age_hours", "priority",
	"project", "env", "status", "applies", "owner", "due", "overdue", "ticket", "matched", "reasons",
	"fix_available", "official_fix", "articles", "note", "updated", "title", "url",
}

// WriteCSV writes one row per issue and target. Text cells come from public
// feeds and user notes, so they are defused against spreadsheet formulas: a
// cell starting with = + - @ tab or CR gets a leading single quote, and
// newlines become spaces. The articles column is the number of articles.
func (d Document) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, is := range d.Issues {
		targets := is.Targets
		if len(targets) == 0 {
			targets = []query.Target{{}}
		}
		for _, t := range targets {
			noTarget := len(is.Targets) == 0
			applies := string(t.Applies)
			if noTarget {
				applies = ""
			}
			overdue := ""
			if !noTarget {
				overdue = strconv.FormatBool(t.Overdue)
			}
			url := ""
			if len(is.Untrusted.Articles) > 0 {
				url = is.Untrusted.Articles[0].URL
			}
			row := []string{
				cell(is.ID), cell(strings.Join(is.Aliases, "; ")), cell(string(is.Severity)), num(is.CVSS, 1),
				strconv.FormatBool(is.KEV != nil), kevDue(is), epss(is), day(is.Published),
				strconv.Itoa(is.AgeHours), cell(strings.Join(is.Priority, "; ")),
				cell(t.Project), cell(string(t.Env)), cell(string(t.Status)), cell(applies),
				cell(t.Owner), day(t.Due), overdue, cell(t.Ticket),
				cell(strings.Join(t.Matched, "; ")), cell(strings.Join(t.Reasons, "; ")),
				strconv.FormatBool(is.Fix.Available), strconv.FormatBool(is.Fix.Official),
				strconv.Itoa(len(is.Untrusted.Articles)), cell(t.Note), stamp(t.Updated),
				cell(is.Untrusted.Title), cell(url),
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// cell defuses formula injection first (on the original first character),
// then flattens newlines.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

func num(f float64, prec int) string {
	if f == 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', prec, 64)
}

func epss(is query.Issue) string {
	if is.EPSS == nil {
		return ""
	}
	return strconv.FormatFloat(is.EPSS.Score, 'f', 3, 64)
}

func kevDue(is query.Issue) string {
	if is.KEV == nil {
		return ""
	}
	return day(is.KEV.DueDate)
}

func day(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// WriteMarkdown writes a report with one table per project, in order of first
// appearance. Issues without targets go under "(none)".
func (d Document) WriteMarkdown(w io.Writer) error {
	type row struct {
		is query.Issue
		t  query.Target
	}
	var names []string
	groups := map[string][]row{}
	for _, is := range d.Issues {
		if len(is.Targets) == 0 {
			groups["(none)"] = append(groups["(none)"], row{is: is})
			if !slices.Contains(names, "(none)") {
				names = append(names, "(none)")
			}
			continue
		}
		for _, t := range is.Targets {
			if _, ok := groups[t.Project]; !ok {
				names = append(names, t.Project)
			}
			groups[t.Project] = append(groups[t.Project], row{is, t})
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Vulnerability export\n\nGenerated: %s\n\nCount: %d\n", d.GeneratedAt.UTC().Format(time.RFC3339), d.Count)
	for _, name := range names {
		fmt.Fprintf(&b, "\n## %s\n\n", mdCell(name))
		b.WriteString("| ID | Sev | Env | Status | Version | Owner | Due | Age | Fix | KEV | Title |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|\n")
		for _, r := range groups[name] {
			fix := "no"
			switch {
			case r.is.Fix.Official:
				fix = "official"
			case r.is.Fix.Available:
				fix = "yes"
			}
			kev := "no"
			if r.is.KEV != nil {
				kev = "yes"
			}
			due := day(r.t.Due)
			if due != "" && r.t.Overdue {
				due += " (overdue)"
			}
			cells := []string{
				r.is.ID, string(r.is.Severity), string(r.t.Env), string(r.t.Status), strings.Join(r.t.Matched, "; "),
				r.t.Owner, due, r.is.Age, fix, kev, r.is.Untrusted.Title,
			}
			for i := range cells {
				cells[i] = mdCell(cells[i])
			}
			b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
		}
	}
	fmt.Fprintf(&b, "\nSchema version %d\n", SchemaVersion)
	_, err := io.WriteString(w, b.String())
	return err
}

// mdCell clips to 100 runes, then makes the text safe inside a table cell:
// no raw HTML, no cell breaks, no line breaks.
func mdCell(s string) string {
	s = query.Clip(s, 99) // collapses newlines and drops control characters
	return strings.NewReplacer(`\`, `\\`, "<", "&lt;", ">", "&gt;", "|", `\|`).Replace(s)
}
