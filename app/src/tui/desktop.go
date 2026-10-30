package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// desktop is what the TUI asks of the machine it runs on: show a link in the
// browser and put text on the clipboard. Tests replace it with a fake.
type desktop interface {
	Open(url string) error
	// Copy returns the tool that took the text, or errNoClipboard.
	Copy(text string) (tool string, err error)
}

var errNoClipboard = errors.New("no clipboard tool found")

// openArgv is the command that shows url in the default browser. The url is
// an argument and never goes through a shell. On Windows rundll32 is used
// instead of "cmd /c start", which would read & and ^ in the address.
func openArgv(goos, url string) []string {
	switch goos {
	case "darwin":
		return []string{"open", url}
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", url}
	}
	return []string{"xdg-open", url}
}

// clipboardArgv is the command that reads the text to copy from its standard
// input, or nil when none of the usual tools is installed. have says whether
// a program is on the path.
func clipboardArgv(goos string, have func(string) bool, env func(string) string) []string {
	switch goos {
	case "darwin":
		return []string{"pbcopy"}
	case "windows":
		return []string{"clip"}
	}
	switch {
	case env("WAYLAND_DISPLAY") != "" && have("wl-copy"):
		return []string{"wl-copy"}
	case have("xclip"):
		return []string{"xclip", "-selection", "clipboard"}
	case have("xsel"):
		return []string{"xsel", "--clipboard", "--input"}
	case have("wl-copy"):
		return []string{"wl-copy"}
	case have("clip.exe"): // WSL
		return []string{"clip.exe"}
	}
	return nil
}

// sysDesktop runs the real commands. The functions are fields so a test can
// watch what would be run.
type sysDesktop struct {
	goos  string
	have  func(string) bool
	env   func(string) string
	start func(argv []string) error               // fire and forget
	pipe  func(argv []string, stdin string) error // wait for it
}

func newSysDesktop() *sysDesktop {
	return &sysDesktop{
		goos: runtime.GOOS,
		have: func(name string) bool { _, err := exec.LookPath(name); return err == nil },
		env:  os.Getenv,
		start: func(argv []string) error {
			cmd := exec.Command(argv[0], argv[1:]...)
			if err := cmd.Start(); err != nil {
				return err
			}
			go cmd.Wait() // reap it; the launcher's own exit status says nothing useful
			return nil
		},
		pipe: func(argv []string, stdin string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			cmd.Stdin = strings.NewReader(stdin)
			return cmd.Run() // output goes nowhere: xclip would hold a pipe open while it serves the selection
		},
	}
}

func (s *sysDesktop) Open(url string) error {
	argv := openArgv(s.goos, url)
	if !s.have(argv[0]) {
		return fmt.Errorf("%s is not installed, so the link cannot be opened", argv[0])
	}
	return s.start(argv)
}

func (s *sysDesktop) Copy(text string) (string, error) {
	argv := clipboardArgv(s.goos, s.have, s.env)
	if argv == nil {
		return "", errNoClipboard
	}
	if err := s.pipe(argv, text); err != nil {
		return "", fmt.Errorf("%s: %w", argv[0], err)
	}
	return argv[0], nil
}
