package calendar

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

func month(y int, m time.Month) time.Time { return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC) }

func entry(y int, m time.Month, d int, id string, sev model.Severity, techs ...string) Entry {
	return Entry{Date: time.Date(y, m, d, 12, 0, 0, 0, time.UTC), ID: id, Title: "title " + id, Severity: sev, Techs: techs}
}

var cellRe = regexp.MustCompile(`<div class="cell( blank)?[ "]`)

func TestHTMLGrid(t *testing.T) {
	for _, tc := range []struct {
		name         string
		month        time.Time
		lead, days   int
		wantCells    int
		firstWeekday time.Weekday
	}{
		{"starts on Monday", month(2026, time.June), 0, 30, 35, time.Monday},
		{"starts on Sunday", month(2026, time.February), 6, 28, 35, time.Sunday},
		{"leap february", month(2028, time.February), 1, 29, 35, time.Tuesday},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.month.Weekday(); got != tc.firstWeekday {
				t.Fatalf("test data wrong: 1st is %v", got)
			}
			out := HTML(nil, tc.month, time.Time{})
			cells := cellRe.FindAllStringSubmatch(out, -1)
			if len(cells) != tc.wantCells {
				t.Fatalf("got %d cells, want %d", len(cells), tc.wantCells)
			}
			lead := 0
			for lead < len(cells) && cells[lead][1] != "" {
				lead++
			}
			if lead != tc.lead {
				t.Errorf("leading blanks = %d, want %d", lead, tc.lead)
			}
			if got := strings.Count(out, `<div class="dn">`); got != tc.days {
				t.Errorf("day cells = %d, want %d", got, tc.days)
			}
			if !strings.Contains(out, `<div class="dn">`+strconv.Itoa(tc.days)+`</div>`) || strings.Contains(out, `<div class="dn">`+strconv.Itoa(tc.days+1)+`</div>`) {
				t.Errorf("last day is not %d", tc.days)
			}
			for _, wd := range []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"} {
				if !strings.Contains(out, `<div class="wd">`+wd+`</div>`) {
					t.Errorf("missing weekday %s", wd)
				}
			}
		})
	}
}

func TestHTMLStructure(t *testing.T) {
	out := HTML(nil, month(2028, time.February), time.Time{})
	for _, want := range []string{
		`<meta charset="utf-8">`,
		`name="viewport"`,
		`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
		`<title>`,
		`<h1>February 2028</h1>`,
		`prefers-color-scheme:dark`,
		`overflow-x:auto`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestHTMLToday(t *testing.T) {
	m := month(2026, time.October)
	if out := HTML(nil, m, time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)); strings.Count(out, `class="cell today"`) != 1 {
		t.Error("today not highlighted")
	}
	if out := HTML(nil, m, time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)); strings.Contains(out, `class="cell today"`) {
		t.Error("today highlighted outside the month")
	}
}

func TestEntriesOutsideMonthIgnored(t *testing.T) {
	es := []Entry{
		entry(2028, time.February, 10, "CVE-IN", model.SevHigh),
		entry(2028, time.January, 31, "CVE-BEFORE", model.SevHigh),
		entry(2028, time.March, 1, "CVE-AFTER", model.SevHigh),
		entry(2027, time.February, 10, "CVE-YEAR", model.SevHigh),
	}
	m := month(2028, time.February)
	html, text := HTML(es, m, time.Time{}), Text(es, m)
	for _, out := range []string{html, text} {
		if !strings.Contains(out, "CVE-IN") {
			t.Error("entry in month missing")
		}
		for _, id := range []string{"CVE-BEFORE", "CVE-AFTER", "CVE-YEAR"} {
			if strings.Contains(out, id) {
				t.Errorf("%s should be dropped", id)
			}
		}
	}
}

func TestMonthLocation(t *testing.T) {
	plus2 := time.FixedZone("x", 2*3600)
	m := time.Date(2028, time.March, 1, 0, 0, 0, 0, plus2)
	// 23:30 UTC on Feb 29 is already March 1 in the month's zone.
	e := Entry{Date: time.Date(2028, time.February, 29, 23, 30, 0, 0, time.UTC), ID: "CVE-TZ"}
	if !strings.Contains(Text([]Entry{e}, m), "2028-03-01") {
		t.Error("date not compared in the month's location")
	}
}

func TestOverflow(t *testing.T) {
	var es []Entry
	for _, id := range []string{"A", "B", "C", "D", "E", "F"} {
		es = append(es, entry(2028, time.February, 5, id, model.SevLow))
	}
	out := HTML(es, month(2028, time.February), time.Time{})
	if got := strings.Count(out, `<div class="chip `); got != 4 {
		t.Errorf("chips = %d, want 4", got)
	}
	if !strings.Contains(out, "+2 more") {
		t.Error(`missing "+2 more"`)
	}
	if strings.Contains(HTML(es[:4], month(2028, time.February), time.Time{}), "more</div>") {
		t.Error("overflow shown for exactly 4 entries")
	}
	// The legend still lists every id.
	if got := strings.Count(out, `<li class="s3"><span class="date">`); got != 6 {
		t.Errorf("legend ids = %d, want 6", got)
	}
}

func TestChipContent(t *testing.T) {
	e := entry(2028, time.February, 5, "CVE-1", model.SevCritical, "php")
	e.Title, e.Articles, e.Fix = `Bad "bug" & more`, 3, true
	out := HTML([]Entry{e}, month(2028, time.February), time.Time{})
	for _, want := range []string{
		`title="Bad &#34;bug&#34; &amp; more · 3 articles · fix available"`,
		`<span class="badge">C</span><span class="id">CVE-1</span>`,
		`>php</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestChipOrder(t *testing.T) {
	es := []Entry{
		entry(2028, time.February, 5, "CVE-A", model.SevLow),
		entry(2028, time.February, 5, "CVE-C", model.SevCritical),
		entry(2028, time.February, 5, "CVE-B", model.SevCritical),
		entry(2028, time.February, 5, "CVE-D", model.Severity("garbage")),
	}
	out := HTML(es, month(2028, time.February), time.Time{})
	last := -1
	for _, id := range []string{"CVE-B", "CVE-C", "CVE-A", "CVE-D"} {
		i := strings.Index(out, `<span class="id">`+id)
		if i <= last {
			t.Fatalf("%s out of order", id)
		}
		last = i
	}
	if !strings.Contains(out, `<span class="badge">?</span><span class="id">CVE-D`) {
		t.Error("unrecognised severity should show ?")
	}
}

func TestLegend(t *testing.T) {
	es := []Entry{
		entry(2028, time.February, 5, "CVE-1", model.SevCritical, "php", "symfony"),
		entry(2028, time.February, 9, "CVE-2", model.SevLow, "php"),
		entry(2028, time.February, 2, "CVE-0", model.SevUnknown),
		entry(2028, time.March, 2, "CVE-X", model.SevHigh, "outsider"),
	}
	out := HTML(es, month(2028, time.February), time.Time{})
	legend := out[strings.Index(out, `<section class="legend">`):]
	for _, want := range []string{"critical", "high", "medium", "low", "unrated", "Technologies"} {
		if !strings.Contains(legend, want) {
			t.Errorf("legend missing %q", want)
		}
	}
	if !regexp.MustCompile(`<span class="tag t\d">php</span> 2</li>`).MatchString(legend) {
		t.Error("php count missing")
	}
	if !regexp.MustCompile(`<span class="tag t\d">symfony</span> 1</li>`).MatchString(legend) {
		t.Error("symfony count missing")
	}
	if strings.Contains(out, "outsider") {
		t.Error("tech from an entry outside the month listed")
	}
	// Chronological ids.
	i0, i1, i2 := strings.Index(legend, "CVE-0"), strings.Index(legend, "CVE-1"), strings.Index(legend, "CVE-2")
	if !(0 < i0 && i0 < i1 && i1 < i2) {
		t.Errorf("ids not chronological: %d %d %d", i0, i1, i2)
	}
	// Summary counts.
	for _, want := range []string{"critical 1", "high 0", "low 1", "unrated 1", "3 vulnerabilities"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q", want)
		}
	}
}

func TestTechClassStable(t *testing.T) {
	if techClass("php") != techClass("php") {
		t.Fatal("unstable")
	}
	seen := map[string]bool{}
	for _, n := range []string{"php", "symfony", "laravel", "node", "nginx", "mysql", "redis", "react", "vue", "go"} {
		c := techClass(n)
		if !regexp.MustCompile(`^t[0-9]$`).MatchString(c) {
			t.Fatalf("bad class %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 3 {
		t.Errorf("colors poorly spread: %v", seen)
	}
}

func TestHTMLEscapesInput(t *testing.T) {
	xss := `<script>alert(1)</script>`
	attr := `" onmouseover="x`
	e := Entry{
		Date:     time.Date(2028, time.February, 5, 0, 0, 0, 0, time.UTC),
		ID:       xss + attr,
		Title:    xss + attr + `'><img src=x onerror=alert(1)>`,
		Severity: model.SevHigh,
		Techs:    []string{xss, attr},
	}
	out := HTML([]Entry{e}, month(2028, time.February), time.Time{})
	for _, bad := range []string{"<script", `" onmouseover="`, "<img", "'>"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped %q in output", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("payload not shown escaped")
	}
}

func TestHTMLSelfContained(t *testing.T) {
	es := []Entry{entry(2028, time.February, 5, "CVE-1", model.SevHigh, "php")}
	out := strings.ToLower(HTML(es, month(2028, time.February), time.Now()))
	for _, bad := range []string{"<script", "http://", "https://", "url(", "@import", "<link", "<img", "<iframe", " src=", "onclick"} {
		if strings.Contains(out, bad) {
			t.Errorf("found %q", bad)
		}
	}
}

func TestText(t *testing.T) {
	es := []Entry{
		entry(2028, time.February, 7, "CVE-1", model.SevCritical, "symfony", "php"),
		entry(2028, time.February, 7, "CVE-2", model.SevLow),
		entry(2028, time.February, 7, "CVE-3", model.SevLow),
	}
	es[0].Articles, es[0].Fix = 3, true
	es[0].Title = "Remote code execution"
	out := Text(es, month(2028, time.February))
	lines := strings.Split(out, "\n")
	if lines[0] != "February 2028" || !strings.HasPrefix(lines[2], " Mon") {
		t.Errorf("bad header: %q", lines[:3])
	}
	// Feb 2028 starts on Tuesday: the first week has one blank cell.
	if !strings.HasPrefix(lines[3], strings.Repeat(" ", 8)+" "+" 1") {
		t.Errorf("first week: %q", lines[3])
	}
	if !strings.Contains(out, " 7 (3)") {
		t.Errorf("missing day count in\n%s", out)
	}
	want := "2028-02-07  CRITICAL  CVE-1  [php,symfony]  Remote code execution  · 3 articles · fix"
	if !strings.Contains(out, want+"\n") {
		t.Errorf("missing line %q in\n%s", want, out)
	}
	if !strings.Contains(out, "2028-02-07  LOW       CVE-2  title CVE-2\n") {
		t.Errorf("bad plain line in\n%s", out)
	}
}

func TestTextSundayStart(t *testing.T) {
	lines := strings.Split(Text(nil, month(2026, time.February)), "\n")
	if got := lines[3]; got != strings.Repeat(" ", 6*9)+" 1" {
		t.Errorf("first week: %q", got)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "No entries.") {
		t.Error("empty month should say so")
	}
}

func TestTextCleansAndClips(t *testing.T) {
	e := entry(2028, time.February, 5, "CVE-\x1b[1m1", model.SevHigh, "p\x07hp")
	e.Title = "\x1b[31mred\x1b[0m\nline\x00" + strings.Repeat("x", 100)
	out := Text([]Entry{e}, month(2028, time.February))
	for _, r := range out {
		if r < ' ' && r != '\n' || r == 0x7f {
			t.Fatalf("control character %q in output", r)
		}
	}
	if strings.Contains(out, "x…x") || !strings.Contains(out, strings.Repeat("x", 100-len("[31mred[0m line")+0)[:0]+"[php]") {
		t.Errorf("unexpected output:\n%s", out)
	}
	// The title is at most 70 runes, ending in an ellipsis.
	line := out[strings.Index(out, "2028-02-05"):]
	line = strings.SplitN(line, "\n", 2)[0]
	title := line[strings.Index(line, "[php]")+len("[php]  "):]
	if n := len([]rune(title)); n != 70 || !strings.HasSuffix(title, "…") {
		t.Errorf("title %q has %d runes", title, n)
	}
}

func TestDeterministic(t *testing.T) {
	es := []Entry{
		entry(2028, time.February, 5, "CVE-1", model.SevHigh, "php", "go"),
		entry(2028, time.February, 5, "CVE-2", model.SevHigh, "go"),
		entry(2028, time.February, 9, "CVE-3", model.SevLow, "node"),
		entry(2028, time.February, 1, "CVE-4", model.SevCritical),
	}
	m, now := month(2028, time.February), time.Date(2028, 2, 5, 0, 0, 0, 0, time.UTC)
	rev := slices.Clone(es)
	slices.Reverse(rev)
	if HTML(es, m, now) != HTML(es, m, now) || HTML(es, m, now) != HTML(rev, m, now) {
		t.Error("HTML not deterministic")
	}
	if Text(es, m) != Text(es, m) || Text(es, m) != Text(rev, m) {
		t.Error("Text not deterministic")
	}
}
