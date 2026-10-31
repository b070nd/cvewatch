package tui

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// editorEnv is what choosing an editor looks at; tests replace it.
type editorEnv struct {
	goos string
	env  func(string) string
	have func(string) bool // whether a program is on the path
}

// editorSys is the machine the TUI runs on.
var editorSys = editorEnv{
	goos: runtime.GOOS,
	env:  os.Getenv,
	have: func(name string) bool { _, err := exec.LookPath(name); return err == nil },
}

// editorChoice is the editor to run: a program with its options, and where
// the choice came from.
type editorChoice struct {
	Command string
	Source  string
	// Fallback is true when nothing was configured and the first usual editor was taken.
	Fallback bool
}

// fallbackEditors are the usual editors of a platform, in the order tried.
func fallbackEditors(goos string) []string {
	switch goos {
	case "windows":
		return []string{"notepad"}
	case "darwin":
		// open -W -t waits for TextEdit to close, so the TUI comes back when the file is done
		return []string{"nano", "vim", "vi", "open -W -t"}
	}
	return []string{"sensible-editor", "editor", "nano", "vim", "vi"}
}

// resolveEditor picks the editor: the tui.editor setting (configured), then
// $VISUAL, then $EDITOR, then the first usual editor of the platform that is
// on the path. Set values are used as they are, even when the program is not
// there, so a mistake shows up as the editor's own error.
func resolveEditor(configured string, e editorEnv) (editorChoice, bool) {
	for _, c := range []editorChoice{
		{Command: configured, Source: "tui.editor"},
		{Command: e.env("VISUAL"), Source: "$VISUAL"},
		{Command: e.env("EDITOR"), Source: "$EDITOR"},
	} {
		if c.Command = strings.TrimSpace(c.Command); c.Command != "" {
			return c, true
		}
	}
	for _, cmd := range fallbackEditors(e.goos) {
		if e.have(strings.Fields(cmd)[0]) {
			return editorChoice{Command: cmd, Source: "fallback", Fallback: true}, true
		}
	}
	return editorChoice{}, false
}

// noEditorText says what to do when resolveEditor found nothing.
func noEditorText(file string) string {
	return "no editor found: set tui.editor in the Settings screen or export EDITOR (such as EDITOR=nano); the file is " + file
}

// editorNote is what the TUI says once a fallback editor has run; empty when
// the user chose the editor.
func (c editorChoice) note() string {
	if !c.Fallback {
		return ""
	}
	return "edited with " + c.Command + ", the first editor found; set tui.editor to choose another"
}
