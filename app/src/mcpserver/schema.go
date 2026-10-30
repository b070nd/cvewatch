package mcpserver

import "github.com/b070nd/cvewatch/app/src/projectfile"

// projectInSchema is the input schema of preview_project_change and
// edit_project. It is written out, instead of inferred from projectIn, so the
// kinds and what each input means come from projectfile.OpTable.
func projectInSchema() map[string]any {
	text := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	kinds := make([]any, 0, len(projectfile.OpTable))
	for _, k := range projectfile.Kinds() {
		kinds = append(kinds, k)
	}
	lockfile := map[string]any{
		"type":        "object",
		"description": "the lockfile as one object, as check_projects fixes give it; instead of the lockfile_* fields",
		"properties": map[string]any{
			"type": text(projectfile.ParamHelp("lockfile.type")),
			"path": text(projectfile.ParamHelp("lockfile.path")),
			"env":  text(projectfile.ParamHelp("lockfile.env")),
			"dev":  map[string]any{"type": "boolean", "description": projectfile.ParamHelp("lockfile.dev")},
		},
		"additionalProperties": false,
	}
	change := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"kind":    map[string]any{"type": "string", "enum": kinds, "description": "what to do; the inputs each kind takes are in parentheses, ? marks an optional one:\n" + projectfile.KindHelp()},
			"tech":    text(projectfile.ParamHelp("tech")),
			"version": text(projectfile.ParamHelp("version")),
			"env":     text(projectfile.ParamHelp("env")),
			"envs": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": projectfile.ParamHelp("envs")},
			"image":         text(projectfile.ParamHelp("image")),
			"since":         text(projectfile.ParamHelp("since")),
			"lockfile_type": text(projectfile.ParamHelp("lockfile.type")),
			"lockfile_path": text(projectfile.ParamHelp("lockfile.path")),
			"lockfile_env":  text(projectfile.ParamHelp("lockfile.env")),
			"lockfile_dev":  map[string]any{"type": "boolean", "description": projectfile.ParamHelp("lockfile.dev")},
			"lockfile":      lockfile,
		},
		"required":             []any{"kind"},
		"additionalProperties": false,
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project": text("project name; lowercase letters, digits and dashes"),
			"changes": map[string]any{"type": "array", "items": change, "description": "the edits, applied in order; none are applied if one fails"},
		},
		"required":             []any{"project", "changes"},
		"additionalProperties": false,
	}
}
