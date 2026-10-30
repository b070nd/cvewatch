// Command cvewatch-tui is the full-screen interface. It is a separate program
// because its terminal library asks the terminal for its colours when the
// program starts, which every plain cvewatch command should not pay for;
// `cvewatch tui` starts this program.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/tui"
)

func main() {
	root := flag.String("root", ".", "configuration folder")
	dir := flag.String("dir", "", "start the setup flow on this repository folder")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), host.StopSignals()...)
	defer stop()
	// The screen is the interface, so only errors go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	b := tui.NewBackend(*root, log)
	set := b.TUISettings()
	if err := tui.Run(ctx, b, tui.Options{Dir: *dir, Refresh: set.Refresh, Fetch: set.Fetch}); err != nil {
		fmt.Fprintln(os.Stderr, "cvewatch-tui:", err)
		os.Exit(1)
	}
}
