package notify

import (
	"fmt"
	"os"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Entry is what the configuration amounts to for one channel: unconfigured,
// configured but invalid (Err), or ready (Channel). Err never contains a
// secret. The pipeline delivers through the ready ones and doctor reports on
// all of them, so channel construction exists in one place.
type Entry struct {
	Name       string
	Configured bool
	Hint       string // why it is not configured
	Channel    Channel
	Min        model.Severity
	Err        error
}

func envHint(name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf(" (environment variable %s is not set)", name)
}

// FromConfig builds the Slack, webhook and email entries. A channel is active
// when its secret is present in the environment, so one config file can be
// shared between machines and people without leaking secrets into it.
func FromConfig(cfg *config.Bundle) []Entry {
	var out []Entry

	slack := Entry{Name: "slack", Min: cfg.Slack.MinSeverity}
	if raw := os.Getenv(cfg.Slack.WebhookEnv); cfg.Slack.WebhookEnv != "" && raw != "" {
		slack.Configured = true
		if ch, err := NewSlack(raw); err != nil {
			slack.Err = fmt.Errorf("%s: %w", cfg.Slack.WebhookEnv, err)
		} else {
			slack.Channel = ch
		}
	} else {
		slack.Hint = envHint(cfg.Slack.WebhookEnv)
	}
	out = append(out, slack)

	w := cfg.Notify.Webhook
	hook := Entry{Name: "webhook", Min: w.MinSeverity}
	if raw := os.Getenv(w.URLEnv); w.URLEnv != "" && raw != "" {
		hook.Configured = true
		secret := ""
		if w.SecretEnv != "" {
			secret = os.Getenv(w.SecretEnv)
		}
		if ch, err := NewWebhook(raw, secret, w.AllowPrivate); err != nil {
			hook.Err = fmt.Errorf("%s: %w", w.URLEnv, err)
		} else {
			hook.Channel = ch
		}
	} else {
		hook.Hint = envHint(w.URLEnv)
	}
	out = append(out, hook)

	e := cfg.Notify.Email
	mail := Entry{Name: "email", Min: e.MinSeverity}
	if e.Host != "" {
		mail.Configured = true
		ch, err := NewEmail(EmailConfig{Host: e.Host, Port: e.Port, From: e.From, To: e.To,
			Username: os.Getenv(e.UsernameEnv), Password: os.Getenv(e.PasswordEnv)})
		if err != nil {
			mail.Err = fmt.Errorf("notify.email: %w", err)
		} else {
			mail.Channel = ch
		}
	} else {
		mail.Hint = " (notify.email.host is empty)"
	}
	out = append(out, mail)
	return out
}
