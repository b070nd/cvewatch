package projectfile

import (
	"regexp"
	"slices"
	"strings"
)

// edit is one step of a line diff: op is ' ' (same), '-' (only in a) or '+'
// (only in b); i and j are the line indexes in a and b, -1 when absent.
type edit struct {
	op   byte
	i, j int
}

// diffLines is a plain longest-common-subsequence line diff. In a changed
// stretch the removed lines come before the added ones.
func diffLines(a, b []string) []edit {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []edit
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			out = append(out, edit{' ', i, j})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, edit{'-', i, -1})
			i++
		default:
			out = append(out, edit{'+', -1, j})
			j++
		}
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// Diff renders the change from before to after: "+ " added, "- " removed,
// "  " unchanged, with two lines of context and "..." between distant changes.
func Diff(before, after []byte) string {
	if string(before) == string(after) {
		return "(no changes)"
	}
	a, b := splitLines(string(before)), splitLines(string(after))
	edits := diffLines(a, b)
	show := make([]bool, len(edits))
	for k, e := range edits {
		if e.op == ' ' {
			continue
		}
		for c := max(0, k-2); c <= min(len(edits)-1, k+2); c++ {
			show[c] = true
		}
	}
	var sb strings.Builder
	skipped := false
	for k, e := range edits {
		if !show[k] {
			skipped = true
			continue
		}
		if skipped && sb.Len() > 0 {
			sb.WriteString("...\n")
		}
		skipped = false
		if e.op == '+' {
			sb.WriteString("+ " + b[e.j] + "\n")
		} else {
			sb.WriteString(string(e.op) + " " + a[e.i] + "\n")
		}
	}
	return sb.String()
}

var (
	commentGap = regexp.MustCompile(`(\S) {2,}#`)
	flowComma  = regexp.MustCompile(`,\}( |$)`)
	flowItem   = regexp.MustCompile(`^\s*- \{.*,\}( +#.*)?$`)
)

// layoutKey is a line with the spacing the encoder changes ignored, so an
// untouched line matches its original.
func layoutKey(l string) string {
	l = strings.TrimRight(l, " ")
	if t := strings.TrimLeft(l, " "); strings.HasPrefix(t, "#") {
		return t // the encoder moves a comment line that continues a trailing comment to column 0
	}
	if loc := commentGap.FindStringSubmatchIndex(l); loc != nil {
		l = l[:loc[3]] + " #" + l[loc[1]:]
	}
	return flowComma.ReplaceAllString(l, "}$1")
}

// mergeLayout takes the encoder's output and brings back the original line
// wherever only spacing differs, plus blank lines the encoder dropped.
func mergeLayout(orig, out string) string {
	a, b := splitLines(orig), splitLines(out)
	ka, kb := make([]string, len(a)), make([]string, len(b))
	for i, l := range a {
		ka[i] = layoutKey(l)
	}
	for j, l := range b {
		kb[j] = layoutKey(l)
	}
	edits := diffLines(ka, kb)
	var res []string
	for k := 0; k < len(edits); {
		if edits[k].op == ' ' {
			res = append(res, a[edits[k].i])
			k++
			continue
		}
		var dels, ins []int
		for ; k < len(edits) && edits[k].op != ' '; k++ {
			if edits[k].op == '-' {
				dels = append(dels, edits[k].i)
			} else {
				ins = append(ins, edits[k].j)
			}
		}
		res = append(res, gap(a, b, dels, ins)...)
	}
	return strings.Join(res, "\n") + "\n"
}

// gap resolves a changed stretch: blank lines before and after the removed
// lines stay where they were, around the new lines.
func gap(a, b []string, dels, ins []int) []string {
	lead, trail := 0, 0
	for lead < len(dels) && a[dels[lead]] == "" {
		lead++
	}
	if lead == len(dels) { // only blank lines: they belong after the new lines
		lead, trail = 0, len(dels)
	}
	for lead+trail < len(dels) && a[dels[len(dels)-1-trail]] == "" {
		trail++
	}
	var res []string
	if lead+trail > 0 && !slices.ContainsFunc(ins, func(j int) bool { return b[j] != "" }) {
		return []string{""} // one blank line is enough where something was removed
	}
	for range lead {
		res = append(res, "")
	}
	for _, j := range ins {
		l := b[j]
		if l == "" { // the encoder adds blank lines after comments; blank lines come from the original
			continue
		}
		if flowItem.MatchString(l) { // the encoder writes ",}" before a following comment
			l = strings.Replace(l, ",}", "}", 1)
		}
		res = append(res, l)
	}
	for range trail {
		res = append(res, "")
	}
	return res
}
