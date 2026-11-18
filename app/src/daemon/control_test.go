package daemon_test

import (
	"bufio"
	"os"
	"os/exec"
	"os/signal"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/daemon"
	"github.com/b070nd/cvewatch/app/src/host"
)

func TestHelperDaemon(t *testing.T) {
	dir := os.Getenv("CVEWATCH_TEST_DAEMON")
	if dir == "" {
		t.Skip("only runs as the child of another test")
	}
	release, err := daemon.Claim(dir)
	if err != nil {
		os.Stdout.WriteString("failed: " + err.Error() + "\n")
		os.Exit(2)
	}
	defer release()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, host.StopSignals()...)
	os.Stdout.WriteString("ready\n")
	<-stop
}

func startHelper(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperDaemon$")
	cmd.Env = append(os.Environ(), "CVEWATCH_TEST_DAEMON="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, _ := bufio.NewReader(out).ReadString('\n')
	if line != "ready\n" {
		t.Fatalf("the helper daemon said %q", line)
	}
	return cmd
}

func TestRunningSeesADaemonOnlyWhileItHoldsTheData(t *testing.T) {
	dir := t.TempDir()
	if _, ok := daemon.Running(dir); ok {
		t.Fatal("nothing runs yet")
	}
	cmd := startHelper(t, dir)
	info, ok := daemon.Running(dir)
	if !ok || info.PID != cmd.Process.Pid {
		t.Fatalf("running = %+v, %v; want pid %d", info, ok, cmd.Process.Pid)
	}
	if _, err := daemon.Claim(dir); err == nil {
		t.Fatal("a second daemon must not take the data")
	}
	cmd.Process.Kill()
	cmd.Wait()
	if _, ok := daemon.Running(dir); ok {
		t.Fatal("a daemon that was killed must not be reported")
	}
	release, err := daemon.Claim(dir)
	if err != nil {
		t.Fatalf("the data is free again: %v", err)
	}
	release()
}

func TestStopEndsTheDaemonAndWaits(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.Stop(dir, time.Second); err == nil {
		t.Fatal("stopping nothing is an error")
	}
	cmd := startHelper(t, dir)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	if err := daemon.Stop(dir, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the process is still alive")
	}
	if _, ok := daemon.Running(dir); ok {
		t.Fatal("still reported running")
	}
}
