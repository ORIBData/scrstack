package mailer

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestFromEnvDefaultsAndDriverChoice(t *testing.T) {
	c, err := FromEnv(env(nil))
	if err != nil || c.Driver != "none" || c.Port != 587 || c.UseTLS {
		t.Fatalf("unset: %+v %v", c, err)
	}
	c, err = FromEnv(env(map[string]string{"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "465", "SMTP_USE_TLS": "true"}))
	if err != nil || c.Driver != "smtp" || c.Port != 465 || !c.UseTLS {
		t.Fatalf("host set: %+v %v", c, err)
	}
	for _, bad := range []map[string]string{{"SMTP_PORT": "x"}, {"SMTP_PORT": "70000"}, {"SMTP_USE_TLS": "yes"}} {
		if _, err := FromEnv(env(bad)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestFactory(t *testing.T) {
	s, err := New(Config{Driver: "none"})
	if err != nil || Enabled(s) || !errors.Is(s.Send(context.Background(), Message{}), ErrDisabled) {
		t.Fatalf("none driver: %v", err)
	}
	if s, _ := New(Config{Driver: "log"}); !Enabled(s) {
		t.Fatal("log driver should be enabled")
	}
	if _, err := New(Config{Driver: "carrier-pigeon"}); err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("unknown driver: %v", err)
	}
	for name, c := range map[string]Config{
		"no host":   {Driver: "smtp", From: "a@b.co"},
		"no from":   {Driver: "smtp", Host: "h"},
		"bad from":  {Driver: "smtp", Host: "h", From: "nope"},
		"half auth": {Driver: "smtp", Host: "h", From: "a@b.co", Username: "u"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestValidateRejectsInjectionAndEmpty(t *testing.T) {
	ok := Message{To: []string{"a@example.com"}, Subject: "hi", Text: "body"}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]Message{
		"no recipient":   {Subject: "s", Text: "t"},
		"bad address":    {To: []string{"nope"}, Text: "t"},
		"newline in to":  {To: []string{"a@example.com\r\nBcc: x@y.z"}, Text: "t"},
		"newline in sub": {To: []string{"a@example.com"}, Subject: "s\r\nBcc: x@y.z", Text: "t"},
		"no body":        {To: []string{"a@example.com"}, Subject: "s"},
	} {
		if m.validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// fakeServer speaks just enough SMTP, without STARTTLS, and records the DATA.
func fakeServer(t *testing.T) (port int, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { c.Write([]byte(s + "\r\n")) }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					got <- data.String()
					say("250 queued")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			switch cmd := strings.ToUpper(line); {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				inData = true
				say("354 go")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func TestSMTPSendsPlainAndMultipart(t *testing.T) {
	port, got := fakeServer(t)
	s, err := New(Config{Driver: "smtp", Host: "127.0.0.1", Port: port, From: "SCRS <scrs@example.com>", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), Message{To: []string{"Dev <dev@example.com>"}, Subject: "Ünicode subject", Text: "plain body", HTML: "<b>html body</b>"})
	if err != nil {
		t.Fatal(err)
	}
	raw := <-got
	for _, want := range []string{"From: \"SCRS\" <scrs@example.com>", "To: \"Dev\" <dev@example.com>", "multipart/alternative", "plain body", "<b>html body</b>", "Message-ID: <", "=?utf-8?q?"} {
		if !strings.Contains(raw, want) {
			t.Errorf("message lacks %q:\n%s", want, raw)
		}
	}
}

func TestSMTPPlainBodyIsPresent(t *testing.T) {
	port, got := fakeServer(t)
	s, _ := New(Config{Driver: "smtp", Host: "127.0.0.1", Port: port, From: "scrs@example.com"})
	if err := s.Send(context.Background(), Message{To: []string{"dev@example.com"}, Subject: "s", Text: "only text"}); err != nil {
		t.Fatal(err)
	}
	if raw := <-got; !strings.Contains(raw, "only text") || strings.Contains(raw, "multipart") {
		t.Fatalf("unexpected message:\n%s", raw)
	}
}

func TestSMTPNeverSendsCredentialsInTheClear(t *testing.T) {
	port, _ := fakeServer(t)
	s, _ := New(Config{Driver: "smtp", Host: "127.0.0.1", Port: port, From: "scrs@example.com", Username: "u", Password: "p"})
	err := s.Send(context.Background(), Message{To: []string{"dev@example.com"}, Text: "t"})
	if err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestSMTPUseTLSRequiresStartTLS(t *testing.T) {
	port, _ := fakeServer(t)
	s, _ := New(Config{Driver: "smtp", Host: "127.0.0.1", Port: port, From: "scrs@example.com", UseTLS: true})
	err := s.Send(context.Background(), Message{To: []string{"dev@example.com"}, Text: "t"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected STARTTLS refusal on port %s, got %v", strconv.Itoa(port), err)
	}
}
