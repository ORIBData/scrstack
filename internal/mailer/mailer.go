// Package mailer sends transactional email through a provider chosen at
// startup. Callers depend on Sender only; New builds the driver named in the
// configuration, so supporting another provider means registering one more
// driver and changing no caller.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Message is one transactional email. Text is required; HTML is optional and
// is sent as the alternative part.
type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

// Sender delivers a message or returns why it could not.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Config is the runtime configuration, read from SMTP_* variables.
type Config struct {
	// Driver selects the implementation: "smtp" (default when SMTP_HOST is
	// set), "log" (writes nothing to the network) or "none" (disabled).
	Driver   string
	Host     string
	Port     int
	Username string
	Password string
	// From is the sender, "address" or "Name <address>".
	From string
	// UseTLS requires an encrypted channel: implicit TLS on port 465, STARTTLS
	// elsewhere. When false, STARTTLS is still used if the server offers it.
	UseTLS  bool
	Timeout time.Duration
}

// ErrDisabled is returned by the disabled sender, so a caller can tell "email
// is not configured" from a delivery failure.
var ErrDisabled = errors.New("email is not configured (set SMTP_HOST)")

// FromEnv reads the configuration through getenv (os.Getenv in production).
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		Driver:   strings.ToLower(strings.TrimSpace(getenv("SMTP_DRIVER"))),
		Host:     strings.TrimSpace(getenv("SMTP_HOST")),
		Username: getenv("SMTP_USERNAME"),
		Password: getenv("SMTP_PASSWORD"),
		From:     strings.TrimSpace(getenv("SMTP_FROM")),
		Timeout:  15 * time.Second,
	}
	if v := strings.TrimSpace(getenv("SMTP_USE_TLS")); v != "" {
		switch strings.ToLower(v) {
		case "true":
			c.UseTLS = true
		case "false":
		default:
			return c, fmt.Errorf("SMTP_USE_TLS must be true or false, got %q", v)
		}
	}
	c.Port = 587
	if v := strings.TrimSpace(getenv("SMTP_PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return c, fmt.Errorf("SMTP_PORT must be 1-65535, got %q", v)
		}
		c.Port = p
	}
	if c.Driver == "" {
		c.Driver = "none"
		if c.Host != "" {
			c.Driver = "smtp"
		}
	}
	return c, nil
}

// Constructor builds a driver from validated configuration.
type Constructor func(Config) (Sender, error)

var drivers = map[string]Constructor{
	"smtp": newSMTP,
	"log":  func(Config) (Sender, error) { return logSender{}, nil },
	"none": func(Config) (Sender, error) { return disabled{}, nil },
}

// Register adds a driver, for a provider that is not SMTP (an HTTP API).
// It panics on a duplicate name, like database/sql.
func Register(name string, c Constructor) {
	if _, dup := drivers[name]; dup {
		panic("mailer: driver " + name + " registered twice")
	}
	drivers[name] = c
}

// New is the factory: it builds the driver named in c.Driver.
func New(c Config) (Sender, error) {
	build, ok := drivers[c.Driver]
	if !ok {
		names := make([]string, 0, len(drivers))
		for n := range drivers {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("unknown SMTP_DRIVER %q (available: %s)", c.Driver, strings.Join(names, ", "))
	}
	return build(c)
}

// Enabled reports whether the sender delivers anything.
func Enabled(s Sender) bool { _, off := s.(disabled); return !off }

type disabled struct{}

func (disabled) Send(context.Context, Message) error { return ErrDisabled }

// logSender accepts and discards messages, for local development and tests.
type logSender struct{}

func (logSender) Send(_ context.Context, m Message) error { return m.validate() }

// validate rejects what could not be sent and anything that could inject a
// header: addresses and the subject must be single-line.
func (m Message) validate() error {
	if len(m.To) == 0 {
		return errors.New("message has no recipient")
	}
	if len(m.To) > 50 {
		return errors.New("message has more than 50 recipients")
	}
	for _, a := range m.To {
		if _, err := parseAddress(a); err != nil {
			return err
		}
	}
	if strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("subject must be a single line")
	}
	if strings.TrimSpace(m.Text) == "" {
		return errors.New("message has no text body")
	}
	return nil
}

func parseAddress(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("address %q must be a single line", s)
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q", s)
	}
	return a, nil
}
