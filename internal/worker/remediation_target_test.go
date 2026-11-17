package worker

import "testing"

func TestRemediationTarget(t *testing.T) {
	w := Worker{ScannerURL: "http://scrs-scanner:8081/scan", ScannerToken: "scanner-token"}
	if url, token := w.remediationTarget(); url != "http://scrs-scanner:8081/scan" || token != "scanner-token" {
		t.Fatalf("without a sandbox remediation uses the scanner: %s %s", url, token)
	}
	w.RemediationURL, w.RemediationToken = "http://scrs-remediator:8081/remediate", "sandbox-token"
	if url, token := w.remediationTarget(); url != "http://scrs-remediator:8081/remediate" || token != "sandbox-token" {
		t.Fatalf("with a sandbox it goes there with its own token: %s %s", url, token)
	}
	// The scanner's token is never sent to the sandbox, even when no sandbox token is set.
	w.RemediationToken = ""
	if _, token := w.remediationTarget(); token == "scanner-token" {
		t.Fatal("the scanner token must not reach the remediation sandbox")
	}
}
