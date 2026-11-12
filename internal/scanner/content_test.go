package scanner

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeClamd(t *testing.T, reply string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				command, err := r.ReadString(0)
				if err != nil || command != "zINSTREAM\x00" {
					return
				}
				for {
					var n uint32
					if binary.Read(r, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
						return
					}
				}
				_, _ = io.WriteString(c, reply+"\x00")
			}()
		}
	}()
	return listener.Addr().String()
}
func TestClamdProtocolAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		reply string
		hit   bool
		fail  bool
	}{{"stream: OK", false, false}, {"stream: Eicar-Signature FOUND", true, false}, {"stream: INSTREAM size limit exceeded. ERROR", false, true}, {"stream: Heuristics.Limits.Exceeded.MaxFiles FOUND", false, true}, {"unexpected", false, true}} {
		t.Run(tc.reply, func(t *testing.T) {
			sig, err := clamd(context.Background(), fakeClamd(t, tc.reply), strings.NewReader("sample"))
			if (err != nil) != tc.fail || (sig != "") != tc.hit {
				t.Fatalf("signature=%q error=%v", sig, err)
			}
		})
	}
}
func TestContentFindingsSurviveSCAFailure(t *testing.T) {
	root := t.TempDir()
	workflow := "steps:\n - run: echo '${{ toJSON(secrets) }}'\n"
	bundle := IndicatorBundle{Version: "fixture-v1", Indicators: []Indicator{{ID: "match", Type: "domain", Value: "bad.example", ValidUntil: time.Now().Add(time.Hour)}, {ID: "expired", Type: "domain", Value: "expired.example", ValidUntil: time.Now().Add(-time.Hour)}}}
	rules, _ := json.Marshal(bundle)
	filename := filepath.Join(root, "indicators.json")
	if err := os.WriteFile(filename, rules, 0600); err != nil {
		t.Fatal(err)
	}
	archive := archiveFor(t, "root/.github/workflows/check.yml", tar.TypeReg, workflow+"# bad.example expired.example\n")
	e := Engine{WorkRoot: root, Database: filepath.Join(root, "missing"), ClamdAddress: fakeClamd(t, "stream: Eicar-Signature FOUND"), IndicatorFile: filename}
	result, err := e.Run(context.Background(), archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || len(result.Findings) != 3 || len(result.SBOM) != 0 {
		t.Fatalf("lost file findings: %+v", result)
	}
	for _, f := range result.Findings {
		if f.AdvisoryID == "expired" || bytes.Contains(f.Evidence, []byte("toJSON")) {
			t.Fatal("expired IOC or raw source leaked")
		}
	}
}

func TestLiveClamdEICAR(t *testing.T) {
	address := os.Getenv("SCRS_TEST_CLAMD_ADDRESS")
	if address == "" {
		t.Skip("requires disposable ClamAV")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if signature, err := clamd(ctx, address, strings.NewReader("harmless fixture")); err != nil || signature != "" {
		t.Fatal("clean scan failed", signature, err)
	}
	if version, dated, err := clamdVersion(ctx, address); err != nil || version == "" || dated.IsZero() {
		t.Fatal("version metadata unavailable", err)
	}
	sample, err := os.ReadFile("../../eicar.test")
	if err != nil {
		t.Fatal(err)
	}
	if signature, err := clamd(ctx, address, bytes.NewReader(sample)); err != nil || signature == "" {
		t.Fatal("EICAR not detected", signature, err)
	}
}
