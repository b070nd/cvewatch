//go:build unix

package host

import (
	"os/exec"
	"syscall"
)

func Detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func Terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
