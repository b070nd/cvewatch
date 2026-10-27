//go:build unix

package host

import (
	"os"
	"syscall"
)

// StopSignals returns the signals that should shut the program down:
// on unix os.Interrupt and SIGTERM; on Windows only os.Interrupt (Ctrl+C).
func StopSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
