package matrix

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// parseGoMod reads the require and replace directives of a go.mod file.
// Everything else (go, toolchain, exclude, retract, ...) is ignored.
func parseGoMod(data []byte) (Result, error) {
	type mod struct{ path, version string }
	var (
		res    Result
		reqs   []mod
		repls  = map[mod]mod{} // old path (+ version, or "" for any) -> replacement
		block  string
		handle = func(verb string, args []string) {
			switch verb {
			case "require":
				if len(args) >= 2 {
					reqs = append(reqs, mod{args[0], args[1]})
				}
			case "replace":
				arrow := -1
				for i, a := range args {
					if a == "=>" {
						arrow = i
						break
					}
				}
				if arrow < 1 || arrow > 2 || arrow == len(args)-1 {
					return
				}
				old, repl := args[:arrow], args[arrow+1:]
				if len(repl) != 2 || strings.HasPrefix(repl[0], ".") || strings.HasPrefix(repl[0], "/") {
					res.Skipped = append(res.Skipped, fmt.Sprintf("replace %s is a local path, not applied", short(strings.Join(args, " "))))
					return
				}
				k := mod{path: old[0]}
				if len(old) == 2 {
					k.version = old[1]
				}
				repls[k] = mod{repl[0], repl[1]}
			}
		}
	)

	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := goFields(line)
		if len(f) == 0 {
			continue
		}
		if block != "" {
			if f[0] == ")" {
				block = ""
			} else {
				handle(block, f)
			}
			continue
		}
		if len(f) >= 2 && f[len(f)-1] == "(" {
			block = f[0]
			continue
		}
		handle(f[0], f[1:])
	}

	for _, r := range reqs {
		if to, ok := repls[r]; ok {
			r = to
		} else if to, ok := repls[mod{path: r.path}]; ok {
			r = to
		}
		res.Packages = append(res.Packages, model.Package{Name: r.path, Version: r.version, Ecosystem: model.EcoGo})
	}
	return res, nil
}

// goFields splits a go.mod line into tokens and unquotes quoted ones.
func goFields(line string) []string {
	f := strings.Fields(line)
	for i, s := range f {
		if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
			if u, err := strconv.Unquote(s); err == nil {
				f[i] = u
			}
		}
	}
	return f
}
