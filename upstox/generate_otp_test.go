package upstox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nsvirk/brokersession"
)

// otpServer returns a httptest.Server with /otp/generate and /otp/verify
// endpoints configured by the supplied handlers.
func otpServer(t *testing.T, gen, verify http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if gen == nil {
		gen = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected call to /otp/generate")
		}
	}
	if verify == nil {
		verify = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected call to /otp/verify")
		}
	}
	mux.Handle("/otp/generate", gen)
	mux.Handle("/otp/verify", verify)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{
		&urlOTPGenerate: srv.URL + "/otp/generate",
		&urlOTPVerify:   srv.URL + "/otp/verify",
	})
	return srv
}

func TestDoOTPGenerate_HappyPath(t *testing.T) {
	var (
		gotHeaders http.Header
		gotBody    map[string]any
	)
	otpServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Errorf("decode req body: %v", err)
		}
		gotBody = env.Data
		_, _ = w.Write([]byte(`{"success":true,"data":{"validateOTPToken":"vtok-123","isTotpEnabled":true}}`))
	}, nil)

	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), leadUserID: "lead-uid-456"}
	if err := c.doOTPGenerate(context.Background(), s); err != nil {
		t.Fatalf("doOTPGenerate error: %v", err)
	}
	if s.validateToken != "vtok-123" {
		t.Errorf("validateToken = %q, want vtok-123", s.validateToken)
	}
	for _, h := range []string{"Origin", "Referer", "X-Device-Details", "X-Request-Id", "User-Agent", "Content-Type"} {
		if gotHeaders.Get(h) == "" {
			t.Errorf("header %s missing", h)
		}
	}
	if gotHeaders.Get("Origin") != loginOrigin {
		t.Errorf("Origin = %q, want %q", gotHeaders.Get("Origin"), loginOrigin)
	}
	if !strings.HasPrefix(gotHeaders.Get("X-Request-Id"), "WPRO-") {
		t.Errorf("X-Request-Id = %q, want WPRO- prefix", gotHeaders.Get("X-Request-Id"))
	}
	if gotBody["mobileNumber"] != validCreds().Mobile {
		t.Errorf("mobileNumber = %v, want %s", gotBody["mobileNumber"], validCreds().Mobile)
	}
	if gotBody["userId"] != "lead-uid-456" {
		t.Errorf("userId = %v, want lead-uid-456", gotBody["userId"])
	}
}

func TestDoOTPGenerate_TotpNotEnabled(t *testing.T) {
	otpServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"validateOTPToken":"vtok-123","isTotpEnabled":false}}`))
	}, nil)

	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), leadUserID: "u"}
	err := c.doOTPGenerate(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOTPGenerate, -1, "authenticator-app 2FA not enabled")
}

func TestDoOTPGenerate_EmptyValidateToken(t *testing.T) {
	otpServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"validateOTPToken":"","isTotpEnabled":true}}`))
	}, nil)
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), leadUserID: "u"}
	err := c.doOTPGenerate(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOTPGenerate, -1, "empty validateOTPToken")
}

func TestDoOTPGenerate_FormatA_ErrorsArray(t *testing.T) {
	otpServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","errors":[{"errorCode":"UDAPI100050","message":"Invalid mobile"}]}`))
	}, nil)
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), leadUserID: "u"}
	err := c.doOTPGenerate(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOTPGenerate, http.StatusBadRequest, "Invalid mobile")

	// Raw should round-trip.
	var bsErr *brokersession.Error
	_ = bsErrAs(err, &bsErr)
	if bsErr.Raw["status"] != "error" {
		t.Errorf("Raw[status] = %v, want error", bsErr.Raw["status"])
	}
}

func TestDoOTPGenerate_FormatB_ErrorObject(t *testing.T) {
	otpServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"error":{"errorCode":"UDAPI100","message":"Bad creds"}}`))
	}, nil)
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), leadUserID: "u"}
	err := c.doOTPGenerate(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOTPGenerate, http.StatusUnauthorized, "Bad creds")
}

func TestDoOTPGenerate_NonJSON5xx(t *testing.T) {
	otpServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html><body>cloudflare</body></html>`))
	}, nil)
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), leadUserID: "u"}
	err := c.doOTPGenerate(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOTPGenerate, http.StatusBadGateway, "unparseable body")
}

func TestDoOTPVerify_HappyPath(t *testing.T) {
	var gotBody map[string]any
	otpServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Errorf("decode req body: %v", err)
		}
		gotBody = env.Data
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	c := New()
	s := &flowState{
		hc:               defaultTestClient(),
		creds:            validCreds(),
		validateToken:    "vtok-123",
		internalClientID: "internal-cid-123",
	}
	if err := c.doOTPVerify(context.Background(), s); err != nil {
		t.Fatalf("doOTPVerify error: %v", err)
	}
	if got, _ := gotBody["otp"].(string); len(got) != 6 {
		t.Errorf("otp = %q, want 6 digits", got)
	}
	if gotBody["validateOtpToken"] != "vtok-123" {
		t.Errorf("validateOtpToken = %v, want vtok-123", gotBody["validateOtpToken"])
	}
	if gotBody["clientId"] != "internal-cid-123" {
		t.Errorf("clientId = %v, want internal-cid-123", gotBody["clientId"])
	}
}

// TestDoOTPVerify_TOTPValuePassthrough proves that when Credentials.TOTPValue
// is set, the library forwards it verbatim as the JSON `otp` field and skips
// TOTP generation (so TOTPSecret is allowed to be empty).
func TestDoOTPVerify_TOTPValuePassthrough(t *testing.T) {
	var gotBody map[string]any
	otpServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Errorf("decode req body: %v", err)
		}
		gotBody = env.Data
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	c := New()
	creds := validCreds()
	creds.TOTPSecret = ""
	creds.TOTPValue = "654321"
	s := &flowState{
		hc:               defaultTestClient(),
		creds:            creds,
		validateToken:    "vtok-123",
		internalClientID: "internal-cid-123",
	}
	if err := c.doOTPVerify(context.Background(), s); err != nil {
		t.Fatalf("doOTPVerify error: %v", err)
	}
	if gotBody["otp"] != "654321" {
		t.Errorf("otp = %v, want 654321", gotBody["otp"])
	}
}

// bsErrAs wraps errors.As(err, target) so individual tests don't all need
// to import "errors". Returns true when extraction succeeds.
func bsErrAs(err error, target **brokersession.Error) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for cur := err; cur != nil; {
		if v, ok := cur.(*brokersession.Error); ok {
			*target = v
			return true
		}
		u, ok := cur.(unwrapper)
		if !ok {
			return false
		}
		cur = u.Unwrap()
	}
	return false
}
