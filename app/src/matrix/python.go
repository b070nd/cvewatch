package matrix

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

var (
	pinnedReq  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s,;*]+)$`)
	inlineHash = regexp.MustCompile(`\s#.*$`)
)

// parseRequirements reads a requirements.txt. Only exactly pinned lines count.
func parseRequirements(data []byte) (Result, error) {
	var (
		res  Result
		cont strings.Builder
	)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			line = ""
		}
		line = strings.TrimSpace(inlineHash.ReplaceAllString(line, ""))
		if rest, ok := strings.CutSuffix(line, `\`); ok {
			cont.WriteString(rest)
			cont.WriteString(" ")
			continue
		}
		cont.WriteString(line)
		req := strings.TrimSpace(cont.String())
		cont.Reset()
		if req == "" {
			continue
		}
		if pkg, skip := requirement(req); skip != "" {
			res.Skipped = append(res.Skipped, skip)
		} else if pkg.Name != "" {
			res.Packages = append(res.Packages, pkg)
		}
	}
	return res, nil
}

// requirement turns one logical requirements line into a package, a skip
// reason, or neither (settings that do not name a package).
func requirement(req string) (model.Package, string) {
	if strings.HasPrefix(req, "-") {
		f := strings.Fields(req)
		switch f[0] {
		case "-r", "--requirement", "-c", "--constraint", "-e", "--editable":
			return model.Package{}, fmt.Sprintf("option %q is not followed", short(req))
		}
		return model.Package{}, "" // --index-url, --hash lines and the like
	}
	// Environment markers and per-requirement options (--hash=...) are not part of the pin.
	if i := strings.Index(req, ";"); i >= 0 {
		req = req[:i]
	}
	if i := strings.Index(req, " --"); i >= 0 {
		req = req[:i]
	}
	req = strings.TrimSpace(req)
	m := pinnedReq.FindStringSubmatch(req)
	if m == nil {
		return model.Package{}, fmt.Sprintf("unpinned requirement %q", short(req))
	}
	return model.Package{Name: m[1], Version: m[2], Ecosystem: model.EcoPyPI}, ""
}

// parsePoetry reads the [[package]] tables of a poetry.lock with a line-oriented
// TOML subset: only top-level string keys of each package table are looked at.
func parsePoetry(data []byte) (Result, error) {
	var (
		res     Result
		active  bool // inside a [[package]] table's own keys
		started bool
		name    string
		version string
		dev     bool
	)
	flush := func() {
		if !started {
			return
		}
		switch {
		case name == "":
			res.Skipped = append(res.Skipped, "poetry package without a name")
		case version == "":
			res.Skipped = append(res.Skipped, fmt.Sprintf("poetry package %q has no version", name))
		default:
			res.Packages = append(res.Packages, model.Package{Name: name, Version: version, Ecosystem: model.EcoPyPI, Dev: dev})
		}
		started, name, version, dev = false, "", "", false
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			active = line == "[[package]]"
			started = active
			continue
		}
		if !active {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "name":
			name = tomlString(val)
		case "version":
			version = tomlString(val)
		case "category": // poetry 1.x
			dev = tomlString(val) == "dev"
		case "groups": // poetry 2.x: dev unless it is in the main group
			dev = !strings.Contains(val, `"main"`)
		}
	}
	flush()
	return res, nil
}

// tomlString returns the contents of a quoted TOML string value.
func tomlString(v string) string {
	if len(v) >= 2 && v[0] == '"' {
		if i := strings.LastIndex(v, `"`); i > 0 {
			if u, err := strconv.Unquote(v[:i+1]); err == nil {
				return u
			}
		}
	}
	if len(v) >= 2 && v[0] == '\'' {
		if i := strings.LastIndex(v, "'"); i > 0 {
			return v[1:i]
		}
	}
	return ""
}

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"`
}

func parsePipfileLock(data []byte) (Result, error) {
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var res Result
	add := func(entries map[string]pipfileEntry, dev bool) {
		for _, name := range slices.Sorted(maps.Keys(entries)) {
			v := strings.TrimLeft(strings.TrimSpace(entries[name].Version), "=<>!~ ")
			if v == "" {
				res.Skipped = append(res.Skipped, fmt.Sprintf("pipfile entry %q has no version (git or path source)", name))
				continue
			}
			res.Packages = append(res.Packages, model.Package{Name: name, Version: v, Ecosystem: model.EcoPyPI, Dev: dev})
		}
	}
	add(lock.Default, false)
	add(lock.Develop, true)
	return res, nil
}
