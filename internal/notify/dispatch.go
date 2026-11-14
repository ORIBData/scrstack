package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxAttempts = 8

// Sign returns the X-SCRS-Signature value: HMAC-SHA256 of the exact body.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// AuthHeader is a static per-subscription credential derived from the signing
// secret. Receivers that can only compare a header value (n8n Header Auth,
// API gateways) check it instead of computing the HMAC. It authenticates the
// sender but, unlike X-SCRS-Signature, does not bind the body.
const AuthHeader = "X-SCRS-Auth"

// AuthToken returns the X-SCRS-Auth value for a subscription secret.
func AuthToken(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("scrs-webhook-header-auth-v1"))
	return "scrs_" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header in constant time (for receivers and tests).
func Verify(secret string, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(secret, body)), []byte(header))
}

// Special-purpose ranges that are not reachable public destinations
// (RFC 6890): "this network", carrier-grade NAT, IETF protocol assignments,
// benchmarking, reserved, and NAT64 (which can front private IPv4).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
}

func publicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Retry delay after a failed attempt: 30s doubling, capped at one hour.
func backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return min(30*time.Second<<(attempt-1), time.Hour)
}

// Dispatcher delivers pending outbox rows. Several dispatchers may run; rows
// are claimed with SKIP LOCKED and a lease, so each attempt has one sender.
type Dispatcher struct {
	Store  *Store
	Logger *slog.Logger
	// Document optionally replaces an assessment event's data with a richer
	// profile document (full/agent). It must apply that profile's safeguards.
	Document func(ctx context.Context, assessment uuid.UUID, sub Subscription) (json.RawMessage, error)
	client   *http.Client
}

// SafeClient connects only to addresses it validated itself, so DNS cannot
// rebind a public name to an internal service between check and connect.
func (s *Store) SafeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, errors.New("destination unresolvable")
			}
			private := s.PrivateHosts[strings.ToLower(host)]
			for _, ip := range ips {
				if !private && !publicIP(ip) {
					return nil, errors.New("destination address not permitted")
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type claimed struct {
	id, subscription, event uuid.UUID
	eventType               string
	payload                 []byte
	attempts                int
}

func (d *Dispatcher) Run(ctx context.Context) {
	if d.client == nil {
		d.client = d.Store.SafeClient()
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := d.Tick(ctx); err != nil && ctx.Err() == nil {
			d.Logger.Warn("webhook dispatch deferred", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick claims and sends one batch of due deliveries.
func (d *Dispatcher) Tick(ctx context.Context) error {
	if d.client == nil {
		d.client = d.Store.SafeClient()
	}
	s := d.Store
	rows, err := s.pool.Query(ctx, `UPDATE `+s.schema+`.webhook_deliveries SET status='sending',lease_until=clock_timestamp()+interval '2 minutes',attempts=attempts+1 WHERE id IN (SELECT id FROM `+s.schema+`.webhook_deliveries WHERE (status='pending' AND next_attempt_at<=clock_timestamp()) OR (status='sending' AND lease_until<clock_timestamp()) ORDER BY next_attempt_at LIMIT 16 FOR UPDATE SKIP LOCKED) RETURNING id,subscription_id,event_id,event_type,payload,attempts`)
	if err != nil {
		return err
	}
	var batch []claimed
	for rows.Next() {
		var c claimed
		if err := rows.Scan(&c.id, &c.subscription, &c.event, &c.eventType, &c.payload, &c.attempts); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, c := range batch {
		wg.Add(1)
		slots <- struct{}{}
		go func(c claimed) {
			defer wg.Done()
			defer func() { <-slots }()
			d.deliver(ctx, c)
		}(c)
	}
	wg.Wait()
	return nil
}

func (d *Dispatcher) deliver(ctx context.Context, c claimed) {
	s := d.Store
	status, failure := d.send(ctx, c)
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var err error
	switch {
	case failure == "":
		_, err = s.pool.Exec(recordCtx, `UPDATE `+s.schema+`.webhook_deliveries SET status='delivered',delivered_at=clock_timestamp(),lease_until=NULL,last_status=$2,last_error='' WHERE id=$1`, c.id, status)
	case c.attempts >= maxAttempts || failure == "subscription disabled":
		_, err = s.pool.Exec(recordCtx, `UPDATE `+s.schema+`.webhook_deliveries SET status='dead',lease_until=NULL,last_status=$2,last_error=$3 WHERE id=$1`, c.id, status, failure)
		d.Logger.Warn("webhook delivery dead-lettered", "delivery_id", c.id, "event_type", c.eventType, "error", failure)
	default:
		_, err = s.pool.Exec(recordCtx, `UPDATE `+s.schema+`.webhook_deliveries SET status='pending',lease_until=NULL,next_attempt_at=clock_timestamp()+($2*interval '1 second'),last_status=$3,last_error=$4 WHERE id=$1`, c.id, int(backoff(c.attempts).Seconds()), status, failure)
	}
	if err != nil {
		d.Logger.Error("webhook delivery result not recorded", "delivery_id", c.id, "error", err)
	}
}

// send returns the HTTP status and a short failure reason ("" on success).
func (d *Dispatcher) send(ctx context.Context, c claimed) (int, string) {
	s := d.Store
	var sub Subscription
	var ciphertext []byte
	var events []byte
	err := s.pool.QueryRow(ctx, `SELECT `+subscriptionColumns+`,secret_ciphertext FROM `+s.schema+`.webhook_subscriptions WHERE id=$1`, c.subscription).Scan(&sub.ID, &sub.Name, &sub.URL, &events, &sub.Profile, &sub.EgressAck, &sub.IncludeContacts, &sub.Enabled, &sub.Revision, &sub.CreatedAt, &sub.UpdatedAt, &ciphertext)
	if err != nil {
		return 0, "subscription unavailable"
	}
	if !sub.Enabled {
		return 0, "subscription disabled"
	}
	secret, err := s.open(sub.ID, ciphertext)
	if err != nil {
		return 0, "subscription secret unavailable"
	}
	body := c.payload
	if c.eventType == "assessment.completed" && sub.Profile != "summary" && d.Document != nil {
		if body, err = d.profileBody(ctx, c.payload, sub); err != nil {
			return 0, "profile document unavailable"
		}
	}
	if !s.validURL(sub.URL) {
		return 0, "subscription URL no longer permitted"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(body))
	if err != nil {
		return 0, "invalid request"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SCRS-Webhook/1")
	req.Header.Set("X-SCRS-Event", c.eventType)
	req.Header.Set("X-SCRS-Event-Version", strconv.Itoa(SchemaVersion))
	req.Header.Set("X-SCRS-Delivery", c.id.String())
	req.Header.Set("Idempotency-Key", c.event.String())
	req.Header.Set("X-SCRS-Signature", Sign(secret, body))
	req.Header.Set(AuthHeader, AuthToken(secret))
	resp, err := d.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, "dispatcher stopped"
		}
		return 0, "connection failed"
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, ""
}

func (d *Dispatcher) profileBody(ctx context.Context, payload []byte, sub Subscription) ([]byte, error) {
	var envelope struct {
		Event map[string]any `json:"event"`
		Data  struct {
			Assessment struct {
				ID uuid.UUID `json:"id"`
			} `json:"assessment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Data.Assessment.ID == uuid.Nil {
		return nil, errors.New("event has no assessment")
	}
	doc, err := d.Document(ctx, envelope.Data.Assessment.ID, sub)
	if err != nil {
		return nil, err
	}
	envelope.Event["profile"] = sub.Profile
	return json.Marshal(map[string]any{"event": envelope.Event, "data": doc})
}

// HostOf is used in audit records: destination host only, never the full URL.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
