package tui

import (
	"strings"
	"testing"
)

// listed fails unless the ids appear on the screen in this order.
func listed(t *testing.T, d *driver, ids ...string) {
	t.Helper()
	v := d.view()
	at := -1
	for _, id := range ids {
		i := strings.Index(v, id)
		if i < 0 || i < at {
			t.Fatalf("want the order %v:\n%s", ids, v)
		}
		at = i
	}
}

func TestFindingsSortByAColumnAndReverse(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	listed(t, d, "CVE-2026-3", "CVE-2026-1", "CVE-2026-4")

	d.press(">")
	d.want("Sort the issues by", "priority", "in use", "severity", "highest first", "title", "A to Z")
	d.pickTo("ID")
	d.press("enter")
	d.want("sort: ID, A to Z", "ID▲", "ok: sorted by ID, A to Z")
	listed(t, d, "CVE-2026-1", "CVE-2026-3", "CVE-2026-4")

	d.press("<")
	d.want("sort: ID, Z to A", "ID▼")
	listed(t, d, "CVE-2026-4", "CVE-2026-3", "CVE-2026-1")

	d.press(">")
	d.want("in use: Z to A")
	d.press("enter")
	d.want("sort: ID, A to Z")

	d.press(">", "home")
	d.pickTo("priority")
	d.press("enter")
	d.wantNot("sort:", "▲", "▼")
	listed(t, d, "CVE-2026-3", "CVE-2026-1", "CVE-2026-4")
	d.press("<")
	d.want("the priority order has no reverse")
}

func TestFindingsFilterByAFieldWithCounts(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("=")
	d.want("Filter the issues by", "Severity", "any", "Environment", "Technology")
	d.wantNot("Clear the filter")
	d.press("enter")
	d.want("[ ] critical  - 1 issue", "[ ] high  - 1 issue", "[ ] low  - 1 issue")
	d.press(" ", "down", " ", "enter")
	d.want("2 of 3 open issues", "filter: severity:critical,high", "CVE-2026-3", "CVE-2026-1")
	d.wantNot("CVE-2026-4")

	d.press("=")
	d.want("critical, high", "Clear the filter")
	d.press("enter")
	d.want("[x] critical", "[x] high", "[ ] low")
	d.press(" ", "down", " ", "enter")
	d.want("3 of 3 open issues")
	d.wantNot("filter:")

	d.press("/")
	d.typ("nginx")
	d.press("enter", "=")
	d.pickTo("Clear the filter")
	d.press("enter")
	d.want("3 of 3 open issues")
}

func TestFindingsFilterHistoryAndBadSyntax(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("/")
	d.typ("nginx")
	d.press("enter", "esc", "/")
	d.typ("php")
	d.press("enter", "esc")
	d.press("/", "up")
	d.want("filter: php")
	d.press("up")
	d.want("filter: nginx", "1 of 3 open issues")
	d.press("down", "down")
	d.want("3 of 3 open issues")
	d.press("esc")

	d.press("/")
	d.typ("colour:red")
	d.want("read as plain words", "unknown field")
}
