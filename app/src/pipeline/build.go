package pipeline

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/notify"
)

// NewRunner wires the production dependencies: the rate-limited HTTP client
// and, when the configured environment variable holds a webhook, Slack.
func NewRunner(cfg *config.Bundle, l *ledger.Ledger, save func() error, log *slog.Logger) (*Runner, error) {
	h := cfg.HTTP
	r := &Runner{
		Cfg: cfg, Ledger: l, Save: save, Log: log, Now: time.Now, Audit: audit.Open(cfg.DataDir),
		Getter: httpx.New(httpx.Options{
			UserAgent: h.UserAgent, Timeout: h.Timeout, Retries: h.Retries, RetryDelay: h.RetryDelay,
			Rate: h.Rate, HostRates: h.HostRates, MaxBody: h.MaxBody,
			Threshold429: h.Threshold429, Cooldown429: h.Cooldown429, AllowPrivate: h.AllowPrivate,
		}),
	}
	if url := os.Getenv(cfg.Slack.WebhookEnv); url != "" {
		slack, err := notify.NewSlack(url)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cfg.Slack.WebhookEnv, err)
		}
		r.Notifier = slack
	} else {
		log.Info("slack disabled", "reason", cfg.Slack.WebhookEnv+" is not set")
	}
	return r, nil
}
