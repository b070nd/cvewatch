package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/host"
)

const (
	lockName = "daemon.lock"
	pidName  = "daemon.pid"
	logName  = "daemon.log"
)

// Info is what a running daemon says about itself.
type Info struct {
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Host    string    `json:"host"`
}

// LogPath is where a daemon started by Start writes its log.
func LogPath(dataDir string) string { return filepath.Join(dataDir, logName) }

// Claim makes this process the daemon of the data in dataDir for as long as it
// runs: a lock the system drops if the process dies, and a file saying who
// holds it. It fails when another daemon holds the lock.
func Claim(dataDir string) (release func(), err error) {
	unlock, err := host.Lock(filepath.Join(dataDir, lockName))
	if err != nil {
		if errors.Is(err, host.ErrLocked) {
			if info, ok := Running(dataDir); ok {
				return nil, fmt.Errorf("a daemon is already running for %s (pid %d)", dataDir, info.PID)
			}
			return nil, fmt.Errorf("a daemon is already running for %s", dataDir)
		}
		return nil, err
	}
	name, _ := os.Hostname()
	b, _ := json.Marshal(Info{PID: os.Getpid(), Started: time.Now().UTC(), Host: name})
	pidPath := filepath.Join(dataDir, pidName)
	if err := host.WriteFileAtomic(pidPath, b); err != nil {
		unlock()
		return nil, err
	}
	return func() { os.Remove(pidPath); unlock() }, nil
}

// Running reports the daemon that holds the data in dataDir, if any. The lock
// is the proof, so a daemon that was killed is never reported.
func Running(dataDir string) (Info, bool) {
	unlock, err := host.Lock(filepath.Join(dataDir, lockName))
	if err == nil {
		unlock()
		return Info{}, false
	}
	if !errors.Is(err, host.ErrLocked) {
		return Info{}, false
	}
	var info Info
	if b, err := os.ReadFile(filepath.Join(dataDir, pidName)); err == nil {
		json.Unmarshal(b, &info)
	}
	return info, true
}

// Executable finds the cvewatch program that runs the daemon: the one next to
// the running program, else the one on the path.
func Executable() (string, error) {
	name := "cvewatch"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(self), name); fileExists(p) {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("%s was not found next to this program or on the path", name)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// Start runs "exe -root root daemon" in the background, detached from this
// process and writing its log to LogPath, and returns once it holds the data.
func Start(exe, root, dataDir string) (Info, error) {
	if info, ok := Running(dataDir); ok {
		return info, fmt.Errorf("a daemon is already running (pid %d)", info.PID)
	}
	logf, err := host.OpenAppend(LogPath(dataDir))
	if err != nil {
		return Info{}, err
	}
	defer logf.Close()
	abs, err := filepath.Abs(root)
	if err != nil {
		return Info{}, err
	}
	cmd := exec.Command(exe, "-root", abs, "daemon")
	cmd.Stdout, cmd.Stderr = logf, logf
	host.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return Info{}, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			return Info{}, fmt.Errorf("the daemon stopped at once%s; see %s", exitWhy(err, LogPath(dataDir)), LogPath(dataDir))
		case <-time.After(100 * time.Millisecond):
		}
		if info, ok := Running(dataDir); ok && info.PID == cmd.Process.Pid {
			return info, nil
		}
	}
	return Info{}, fmt.Errorf("the daemon did not take the data within 10s; see %s", LogPath(dataDir))
}

func exitWhy(err error, log string) string {
	b, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	switch {
	case last != "":
		return ": " + last
	case err != nil:
		return ": " + err.Error()
	}
	return ""
}

// Stop asks the daemon to end, as Ctrl+C would, and waits up to wait for it to
// let go of the data. A daemon on another host is not touched.
func Stop(dataDir string, wait time.Duration) error {
	info, ok := Running(dataDir)
	if !ok {
		return errors.New("no daemon is running")
	}
	if name, _ := os.Hostname(); info.PID == 0 || (info.Host != "" && info.Host != name) {
		return fmt.Errorf("the daemon runs on %q (pid %d), not here; stop it there", info.Host, info.PID)
	}
	if err := host.Terminate(info.PID); err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if _, ok := Running(dataDir); !ok {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("the daemon (pid %d) was asked to stop and is still finishing its cycle", info.PID)
}
