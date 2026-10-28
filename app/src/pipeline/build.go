package pipeline

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/notify"
)

// NewRunner wires the production dependencies: the rate-limited HTTP client
// and every channel whose secret is present in the environment. A channel is
// active when its environment variable is set, so one config file can be
// shared between machines and people without leaking secrets into it.
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

// Channels builds the active notification channels from configuration and environment.
func Channels(cfg *config.Bundle, log *slog.Logger) ([]Delivery, error) {
	var out []Delivery
	if url := os.Getenv(cfg.Slack.WebhookEnv); url != "" {
		ch, err := notify.NewSlack(url)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cfg.Slack.WebhookEnv, err)
		}
		out = append(out, Delivery{Channel: ch, Min: cfg.Slack.MinSeverity})
	}
	if w := cfg.Notify.Webhook; w.URLEnv != "" {
		if url := os.Getenv(w.URLEnv); url != "" {
			ch, err := notify.NewWebhook(url, os.Getenv(w.SecretEnv), w.AllowPrivate)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", w.URLEnv, err)
			}
			out = append(out, Delivery{Channel: ch, Min: w.MinSeverity})
		}
	}
	if e := cfg.Notify.Email; e.Host != "" {
		ch, err := notify.NewEmail(notify.EmailConfig{
			Host: e.Host, Port: e.Port, From: e.From, To: e.To,
			Username: os.Getenv(e.UsernameEnv), Password: os.Getenv(e.PasswordEnv),
		})
		if err != nil {
			return nil, fmt.Errorf("notify.email: %w", err)
		}
		out = append(out, Delivery{Channel: ch, Min: e.MinSeverity})
	}
	if names := names(out); len(names) > 0 {
		log.Debug("notification channels", "active", strings.Join(names, ","))
	}
	return out, nil
}

func names(ds []Delivery) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Channel.Name()
	}
	return out
}
