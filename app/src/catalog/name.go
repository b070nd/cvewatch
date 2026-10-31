package catalog

import (
	"fmt"
	"regexp"
	"strings"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// CheckName says whether name can be the key of a technology: lowercase
// letters, digits, - and _, at most 63 characters.
func CheckName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid technology name %q: use lowercase letters, digits, - and _, at most 63 characters", name)
	}
	return nil
}

// Slug turns a typed term such as "Acme Gateway" into a name: lowercase, with
// every run of other characters replaced by one dash.
func Slug(term string) string {
	var b strings.Builder
	dash := true // no leading dash
	for _, r := range strings.ToLower(strings.TrimSpace(term)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}
