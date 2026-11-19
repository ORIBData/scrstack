package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"time"
)

type smtpSender struct {
	cfg  Config
	from *mail.Address
	// tlsConfig is replaceable so tests can trust a local certificate.
	tlsConfig *tls.Config
}

func newSMTP(c Config) (Sender, error) {
	if c.Host == "" {
		return nil, errors.New("SMTP_HOST is required for the smtp driver")
	}
	if c.From == "" {
		return nil, errors.New("SMTP_FROM is required for the smtp driver")
	}
	from, err := parseAddress(c.From)
	if err != nil {
		return nil, fmt.Errorf("SMTP_FROM: %w", err)
	}
	if (c.Username == "") != (c.Password == "") {
		return nil, errors.New("set both SMTP_USERNAME and SMTP_PASSWORD, or neither")
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Second
	}
	return &smtpSender{cfg: c, from: from, tlsConfig: &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}}, nil
}

func (s *smtpSender) Send(ctx context.Context, m Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	rcpt := make([]string, len(m.To))
	for i, a := range m.To {
		p, _ := parseAddress(a)
		rcpt[i] = p.Address
	}
	body, err := s.build(m)
	if err != nil {
		return err
	}
	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Mail(s.from.Address); err != nil {
		return fmt.Errorf("smtp sender rejected: %w", err)
	}
	for _, r := range rcpt {
		if err := client.Rcpt(r); err != nil {
			return fmt.Errorf("smtp recipient %s rejected: %w", r, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// connect opens the connection, secures it and authenticates. Implicit TLS is
// used on port 465, STARTTLS otherwise; with SMTP_USE_TLS=true a server that
// cannot encrypt is refused rather than sent credentials in the clear.
func (s *smtpSender) connect(ctx context.Context) (*smtp.Client, error) {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp connect %s: %w", addr, err)
	}
	deadline := time.Now().Add(2 * s.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	implicit := s.cfg.UseTLS && s.cfg.Port == 465
	if implicit {
		conn = tls.Client(conn, s.tlsConfig)
	}
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smtp greeting from %s: %w", addr, err)
	}
	secured := implicit
	if !implicit {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(s.tlsConfig); err != nil {
				client.Close()
				return nil, fmt.Errorf("smtp starttls: %w", err)
			}
			secured = true
		} else if s.cfg.UseTLS {
			client.Close()
			return nil, errors.New("smtp server does not offer STARTTLS and SMTP_USE_TLS is true")
		}
	}
	if s.cfg.Username != "" {
		if !secured {
			client.Close()
			return nil, errors.New("refusing to send SMTP credentials over an unencrypted connection")
		}
		if err := client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			client.Close()
			return nil, fmt.Errorf("smtp authentication failed: %w", err)
		}
	}
	return client, nil
}

func (s *smtpSender) build(m Message) ([]byte, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	domain := "scrs.local"
	if at := bytes.LastIndexByte([]byte(s.from.Address), '@'); at >= 0 {
		domain = s.from.Address[at+1:]
	}
	to := make([]string, len(m.To))
	for i, a := range m.To {
		p, _ := parseAddress(a)
		to[i] = p.String()
	}
	var buf bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	h("From", s.from.String())
	h("To", joinAddresses(to))
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	if m.HTML == "" {
		h("Content-Type", "text/plain; charset=utf-8")
		h("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQP(&buf, m.Text); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	mw := multipart.NewWriter(&buf)
	h("Content-Type", "multipart/alternative; boundary="+mw.Boundary())
	buf.WriteString("\r\n")
	for _, part := range []struct{ kind, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		pw, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {part.kind + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		if err != nil {
			return nil, err
		}
		if err := writeQP(pw, part.body); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeQP(w interface{ Write([]byte) (int, error) }, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(s)); err != nil {
		return err
	}
	return qp.Close()
}

func joinAddresses(a []string) string {
	var out bytes.Buffer
	for i, s := range a {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteString(s)
	}
	return out.String()
}
