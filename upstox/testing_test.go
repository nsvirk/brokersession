package upstox

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// defaultTestClient returns the same *http.Client a real flowState would
// use (cookie jar, manual-redirect handler) so tests exercise the production
// HTTP plumbing.
func defaultTestClient() *http.Client {
	return internal.NewHTTPClient(nil)
}

// withEndpoints temporarily overrides package-level URL vars and registers
// a t.Cleanup to restore them. Pass a map of *target → newValue.
func withEndpoints(t *testing.T, m map[*string]string) {
	t.Helper()
	saved := make(map[*string]string, len(m))
	for p := range m {
		saved[p] = *p
	}
	t.Cleanup(func() {
		for p, v := range saved {
			*p = v
		}
	})
	for p, v := range m {
		*p = v
	}
}

// pointAllToServer redirects every Upstox flow URL to srv.URL with the same
// path component as the production URL, so a single httptest.Server can
// route all six steps via one mux.
func pointAllToServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	withEndpoints(t, map[*string]string{
		&urlDialog:        srv.URL + "/dialog",
		&urlOTPGenerate:   srv.URL + "/otp/generate",
		&urlOTPVerify:     srv.URL + "/otp/verify",
		&urlPINSubmit:     srv.URL + "/pin",
		&urlOAuthApprove:  srv.URL + "/oauth/approve",
		&urlTokenExchange: srv.URL + "/token",
		&urlProfile:       srv.URL + "/profile",
		&urlLogout:        srv.URL + "/logout",
	})
}

// assertBSError walks err, asserts it is a *brokersession.Error with the
// expected broker, step and status, and that Message contains wantMsgSubstr.
// Pass wantStatus = -1 to skip the status check.
func assertBSError(t *testing.T, err error, wantBroker brokersession.BrokerName, wantStep brokersession.Step, wantStatus int, wantMsgSubstr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *brokersession.Error, got nil")
	}
	var bsErr *brokersession.Error
	if !errors.As(err, &bsErr) {
		t.Fatalf("err is not *brokersession.Error: %T (%v)", err, err)
	}
	if bsErr.Broker != wantBroker {
		t.Errorf("Broker = %q, want %q", bsErr.Broker, wantBroker)
	}
	if bsErr.Step != wantStep {
		t.Errorf("Step = %q, want %q", bsErr.Step, wantStep)
	}
	if wantStatus >= 0 && bsErr.StatusCode != wantStatus {
		t.Errorf("StatusCode = %d, want %d", bsErr.StatusCode, wantStatus)
	}
	if wantMsgSubstr != "" && !strings.Contains(bsErr.Message, wantMsgSubstr) {
		t.Errorf("Message = %q, want substring %q", bsErr.Message, wantMsgSubstr)
	}
}

// b64 is a small helper for asserting the base64-encoded PIN sent in step 4.
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
