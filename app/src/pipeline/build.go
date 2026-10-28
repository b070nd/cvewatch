package pipeline

import (
	"log/slog"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/notify"
)

// NewRunner wires the production dependencies: the rate-limited HTTP client
// and every channel whose secret is present in the environment. A channel is
// active when its environment variable is set, so one config file can be
// shared between machines and people without leaking secrets into it.
func NewRunner(cfg *config.Bundle, l *ledger.Ledger, save func() error, log *slog.Logger) (*Runner, error) {
	r := &Runner{
		Cfg: cfg, Ledger: l, Save: save, Log: log, Now: time.Now, Audit: audit.Open(cfg.DataDir),
		Getter: cfg.HTTP.Client(),
	}
	channels, err := Channels(cfg, log)
	if err != nil {
		return nil, err
	}
	r.Channels = channels
	if len(channels) == 0 {
		log.Info("no notification channel active", "hint", "set "+cfg.Slack.WebhookEnv+" or configure notify.webhook / notify.email")
	}
	return r, nil
}

// Channels returns the ready channels. A configured channel that is invalid
// is an error, so a typo in a webhook URL stops the run instead of silently
// dropping alerts.
func Channels(cfg *config.Bundle, log *slog.Logger) ([]Delivery, error) {
	var out []Delivery
	for _, e := range notify.FromConfig(cfg) {
		if e.Err != nil {
			return nil, e.Err
		}
		if e.Channel != nil {
			out = append(out, Delivery{Channel: e.Channel, Min: e.Min})
		}
	}
	return out, nil
}
