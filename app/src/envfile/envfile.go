// Package envfile reads .env files into the process environment, so the
// secrets a source or channel names (GITHUB_TOKEN, SLACK_WEBHOOK_URL) need not
// be exported by hand. Real environment variables win over the files, and of
// several files the later one wins. Values are never returned or logged.
package envfile

import (
	"bufio"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Defaults are the files read when none is named, in this order.
var Defaults = []string{".env", ".env.local"}

// Files is a repeatable flag value: -env-file a -env-file b.
type Files []string

func (f *Files) String() string { return strings.Join(*f, ",") }

func (f *Files) Set(v string) error {
	if v == "" {
		return fmt.Errorf("an env file needs a path")
	}
	*f = append(*f, v)
	return nil
}

// Result says what Apply did. It holds names only, never values.
type Result struct {
	Files []string // files read, in order
	Set   []string // variables set from them, sorted
	Loose []string // files other users can read (Unix permission bits)
}

// Apply loads the named files, or when none is named the Defaults found in
// each of dirs (duplicates and missing files skipped). A named file that does
// not exist is an error.
func Apply(named []string, dirs ...string) (Result, error) {
	var res Result
	paths := slices.Clone(named)
	if len(paths) == 0 {
		seen := map[string]bool{}
		for _, d := range dirs {
			for _, name := range Defaults {
				p, err := filepath.Abs(filepath.Join(d, name))
				if err != nil || seen[p] {
					continue
				}
				seen[p] = true
				if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
					paths = append(paths, p)
				}
			}
		}
	}
	merged := map[string]string{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return res, fmt.Errorf("env file: %w", err)
		}
		vars, err := parse(f, p)
		f.Close()
		if err != nil {
			return res, err
		}
		for k, v := range vars {
			merged[k] = v
		}
		res.Files = append(res.Files, p)
		if st, err := os.Stat(p); err == nil && loose(st.Mode()) {
			res.Loose = append(res.Loose, p)
		}
	}
	for k, v := range merged {
		if _, ok := os.LookupEnv(k); ok {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return res, fmt.Errorf("env file: set %s: %w", k, err)
		}
		res.Set = append(res.Set, k)
	}
	slices.Sort(res.Set)
	return res, nil
}

// Setup is what both programs do at start: Apply for the working directory and
// the configuration folder, with the files and the number of variables logged
// (never their values) and a warning for a file other users can read.
func Setup(named []string, root string, log *slog.Logger) error {
	wd, _ := os.Getwd()
	res, err := Apply(named, wd, root)
	if err != nil {
		return err
	}
	if len(res.Files) > 0 {
		log.Debug("env files read", "files", strings.Join(res.Files, ","), "variables set", len(res.Set))
	}
	for _, p := range res.Loose {
		log.Warn("env file can be read by other users; run chmod 600 on it", "file", p)
	}
	return nil
}

func loose(m fs.FileMode) bool { return runtime.GOOS != "windows" && m.Perm()&0o077 != 0 }

// parse reads KEY=VALUE lines. It knows comments, `export`, single quotes
// (literal), double quotes (\n \r \t \" \\ \$) and a trailing " # comment" on
// unquoted values. There is no variable expansion. Errors name file and line,
// never the value.
func parse(f *os.File, name string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export "); ok {
			line = strings.TrimSpace(rest)
		}
		key, raw, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !validKey(key) {
			return nil, fmt.Errorf("env file %s line %d: expected NAME=value", name, n)
		}
		val, err := value(strings.TrimLeft(raw, " \t"))
		if err != nil {
			return nil, fmt.Errorf("env file %s line %d: %v", name, n, err)
		}
		out[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("env file %s: %w", name, err)
	}
	return out, nil
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func value(s string) (string, error) {
	switch {
	case strings.HasPrefix(s, "'"):
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", fmt.Errorf("unterminated single quote")
		}
		return s[1 : 1+end], tail(s[2+end:])
	case strings.HasPrefix(s, `"`):
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch c := s[i]; {
			case c == '\\' && i+1 < len(s):
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 'r':
					b.WriteByte('\r')
				case 't':
					b.WriteByte('\t')
				case '"', '\\', '$':
					b.WriteByte(s[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(s[i])
				}
			case c == '"':
				return b.String(), tail(s[i+1:])
			default:
				b.WriteByte(c)
			}
		}
		return "", fmt.Errorf("unterminated double quote")
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "\t#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s), nil
}

// tail accepts what may follow a closing quote: nothing or a comment.
func tail(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return nil
	}
	return fmt.Errorf("unexpected text after the closing quote")
}
