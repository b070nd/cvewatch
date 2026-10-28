// Package doctor checks that a cvewatch folder will actually alert: that the
// configuration loads, technology names are well formed (and, online, known to
// NVD), feeds are valid, lockfiles can be read, the data directory is usable,
// the audit log is intact and at least one notification channel works. It
// also writes the starter layout for `init`. Nothing here sends a message.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Status is the outcome of one check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Check is one line of the report.
type Check struct {
	Group  string `json:"group"`
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report is everything doctor found, in the order the checks ran.
type Report struct {
	Root   string  `json:"root"`
	Checks []Check `json:"checks"`
}

func (r *Report) add(group, name string, s Status, format string, a ...any) {
	detail := format
	if len(a) > 0 {
		detail = fmt.Sprintf(format, a...)
	}
	r.Checks = append(r.Checks, Check{Group: group, Name: name, Status: s, Detail: oneLine(detail)})
}

// oneLine keeps a check on one line and bounded, whatever an error contained.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[:397] + "..."
	}
	return s
}

// Failed reports whether any check failed. Warnings do not count.
func (r Report) Failed() bool {
	_, _, fail := r.Counts()
	return fail > 0
}

// Counts returns how many checks are ok, warnings and failures. Skipped
// checks are in none of them.
func (r Report) Counts() (ok, warn, fail int) {
	for _, c := range r.Checks {
		switch c.Status {
		case OK:
			ok++
		case Warn:
			warn++
		case Fail:
			fail++
		}
	}
	return
}

var markers = map[Status]string{OK: "[ok]", Warn: "[warn]", Fail: "[FAIL]", Skip: "[skip]"}

// WriteText prints the checks grouped, one line each, then a summary.
func (r Report) WriteText(w io.Writer) {
	var groups []string
	byGroup := map[string][]Check{}
	for _, c := range r.Checks {
		if _, seen := byGroup[c.Group]; !seen {
			groups = append(groups, c.Group)
		}
		byGroup[c.Group] = append(byGroup[c.Group], c)
	}
	fmt.Fprintf(w, "cvewatch doctor: %s\n", r.Root)
	for _, g := range groups {
		fmt.Fprintf(w, "\n%s\n", g)
		for _, c := range byGroup[g] {
			line := c.Name
			if c.Detail != "" {
				line += ": " + c.Detail
			}
			fmt.Fprintf(w, "  %-6s %s\n", markers[c.Status], line)
		}
	}
	ok, warn, fail := r.Counts()
	fmt.Fprintf(w, "\n%d ok, %d warnings, %d failures\n", ok, warn, fail)
	if fail > 0 {
		fmt.Fprintln(w, "Fix the failures above before relying on alerts.")
	}
}

// WriteJSON writes the report with its counts as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	ok, warn, fail := r.Counts()
	checks := r.Checks
	if checks == nil {
		checks = []Check{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Root   string  `json:"root"`
		Failed bool    `json:"failed"`
		OK     int     `json:"ok"`
		Warn   int     `json:"warnings"`
		Fail   int     `json:"failures"`
		Checks []Check `json:"checks"`
	}{r.Root, fail > 0, ok, warn, fail, checks})
}
