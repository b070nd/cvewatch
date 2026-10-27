//go:build windows

package host

import "os"

// StopSignals returns the signals that should shut the program down:
// on unix os.Interrupt and SIGTERM; on Windows only os.Interrupt (Ctrl+C).
func StopSignals() []os.Signal { return []os.Signal{os.Interrupt} }
