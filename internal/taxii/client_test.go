package taxii

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serverCA returns the PEM of a test server's self-signed certificate.
func serverCA(s *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
}

// clientCertificate issues a client certificate from a new CA.
func clientCertificate(t *testing.T) (certPEM, keyPEM string, roots *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	roots = x509.NewCertPool()
	roots.AddCert(caCert)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "scrs"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), roots
}

var local = map[string]bool{"127.0.0.1": true}

func indicator(n int) string {
	return fmt.Sprintf(`{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-%012d","pattern":"[domain-name:value = 'h%d.example']","pattern_type":"stix"}`, n, n)
}

func TestObjectsPagingAndAPIKey(t *testing.T) {
	var queries []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer opencti-token" || r.Header.Get("Accept") != MediaType {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/taxii2/root/collections/col-1/":
			fmt.Fprint(w, `{"id":"col-1","title":"OpenCTI export","can_read":true}`)
			return
		case "/taxii2/root/collections/col-1/objects/":
		default:
			w.WriteHeader(404)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", MediaType)
		if r.URL.Query().Get("next") == "" {
			w.Header().Set("X-TAXII-Date-Added-Last", "2026-11-14T10:00:00.000Z")
			fmt.Fprintf(w, `{"more":true,"next":"page-2","objects":[%s]}`, indicator(1))
			return
		}
		w.Header().Set("X-TAXII-Date-Added-Last", "2026-11-14T11:00:00.000Z")
		fmt.Fprintf(w, `{"more":false,"objects":[%s]}`, indicator(2))
	}))
	defer server.Close()
	feed := Feed{APIRoot: server.URL + "/taxii2/root/", Collection: "col-1", AuthType: "api_key", Header: "Authorization", CAPEM: serverCA(server), PageSize: 500}
	client, err := NewClient(feed, Secret{APIKey: "Bearer opencti-token"}, local)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if c, err := client.Check(ctx); err != nil || !c.CanRead || c.Title != "OpenCTI export" {
		t.Fatal("collection check", c, err)
	}
	page, err := client.Objects(ctx, "2026-11-01T00:00:00Z", "")
	if err != nil || !page.More || page.Next != "page-2" || page.AddedLast != "2026-11-14T10:00:00.000Z" || len(page.Objects) != 1 {
		t.Fatalf("first page %+v %v", page, err)
	}
	if page, err = client.Objects(ctx, "2026-11-01T00:00:00Z", page.Next); err != nil || page.More || len(page.Objects) != 1 {
		t.Fatalf("second page %+v %v", page, err)
	}
	if !strings.Contains(queries[0], "added_after=2026-11-01T00%3A00%3A00Z") || !strings.Contains(queries[0], "limit=500") || !strings.Contains(queries[0], "match%5Btype%5D=indicator") || !strings.Contains(queries[1], "next=page-2") {
		t.Fatal("query parameters", queries)
	}
	// Wrong key: the error names the cause.
	bad, _ := NewClient(feed, Secret{APIKey: "Bearer wrong"}, local)
	if _, err := bad.Objects(ctx, "", ""); err == nil || !strings.Contains(err.Error(), "refused the credentials") {
		t.Fatal(err)
	}
	// Without the private-host allowance, the loopback server is not dialed.
	guarded, _ := NewClient(feed, Secret{APIKey: "Bearer opencti-token"}, nil)
	if _, err := guarded.Check(ctx); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatal("netguard must refuse a loopback feed", err)
	}
	// The server certificate is verified: without ca_pem it is untrusted.
	feed.CAPEM = ""
	untrusted, _ := NewClient(feed, Secret{APIKey: "Bearer opencti-token"}, local)
	if _, err := untrusted.Check(ctx); err == nil {
		t.Fatal("self-signed server certificate accepted")
	}
}

func TestBasicAuthClientCertificateAndErrors(t *testing.T) {
	certPEM, keyPEM, roots := clientCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		switch {
		case len(r.TLS.PeerCertificates) == 0:
			w.WriteHeader(403)
		case !ok || user != "ais-user" || pass != "s3cret":
			w.WriteHeader(401)
		case strings.HasSuffix(r.URL.Path, "/moved/"):
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		case strings.Contains(r.URL.Path, "/busy/"):
			w.WriteHeader(429)
		default:
			fmt.Fprint(w, `{"id":"ais","title":"AIS indicators","can_read":true}`)
		}
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	feed := Feed{APIRoot: server.URL + "/taxii2/", Collection: "ais", AuthType: "basic", CAPEM: serverCA(server), PageSize: 100}
	secret := Secret{Username: "ais-user", Password: "s3cret", CertPEM: certPEM, KeyPEM: keyPEM}
	client, err := NewClient(feed, secret, local)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if c, err := client.Check(ctx); err != nil || c.ID != "ais" {
		t.Fatal("client certificate and basic auth", c, err)
	}
	noCert, _ := NewClient(feed, Secret{Username: "ais-user", Password: "s3cret"}, local)
	if _, err := noCert.Check(ctx); err == nil {
		t.Fatal("server requiring a client certificate accepted none")
	}
	for collection, want := range map[string]string{"moved": "redirected", "busy": "rate limit"} {
		feed.Collection = collection
		c, _ := NewClient(feed, secret, local)
		if _, err := c.Check(ctx); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", collection, err)
		}
	}
}

func TestValidate(t *testing.T) {
	certPEM, keyPEM, _ := clientCertificate(t)
	ok := Feed{APIRoot: "https://cti.example/taxii2/root/", Collection: "c", AuthType: "none", PageSize: 1000}
	if err := Validate(ok, Secret{}); err != nil {
		t.Fatal(err)
	}
	if err := Validate(ok, Secret{CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatal("certificate alone is allowed with auth none", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*Feed)
		secret Secret
	}{
		"http":             {func(f *Feed) { f.APIRoot = "http://cti.example/taxii2/" }, Secret{}},
		"credentials":      {func(f *Feed) { f.APIRoot = "https://u:p@cti.example/taxii2/" }, Secret{}},
		"no slash":         {func(f *Feed) { f.APIRoot = "https://cti.example/taxii2" }, Secret{}},
		"collection path":  {func(f *Feed) { f.Collection = "../x" }, Secret{}},
		"page size":        {func(f *Feed) { f.PageSize = 0 }, Secret{}},
		"key missing":      {func(f *Feed) { f.AuthType, f.Header = "api_key", "X-API-Key" }, Secret{}},
		"host header":      {func(f *Feed) { f.AuthType, f.Header = "api_key", "Host" }, Secret{APIKey: "k"}},
		"header injection": {func(f *Feed) { f.AuthType, f.Header = "api_key", "X-API-Key" }, Secret{APIKey: "k\r\nX: y"}},
		"basic colon":      {func(f *Feed) { f.AuthType = "basic" }, Secret{Username: "a:b", Password: "p"}},
		"half cert":        {func(f *Feed) {}, Secret{CertPEM: certPEM}},
		"bad pair":         {func(f *Feed) {}, Secret{CertPEM: certPEM, KeyPEM: "nope"}},
		"bad ca":           {func(f *Feed) { f.CAPEM = "nope" }, Secret{}},
		"auth type":        {func(f *Feed) { f.AuthType = "oauth" }, Secret{}},
	} {
		f := ok
		tc.mutate(&f)
		if err := Validate(f, tc.secret); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
