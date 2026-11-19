package main

import (
	"os"

	"github.com/ORIBData/scrstack/internal/mailer"
)

// newMailer builds the transactional email sender from SMTP_* so a bad value
// stops the process at startup instead of at the first message. With
// SMTP_HOST unset the sender is disabled and Send returns mailer.ErrDisabled.
func newMailer() (mailer.Sender, error) {
	cfg, err := mailer.FromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	return mailer.New(cfg)
}
