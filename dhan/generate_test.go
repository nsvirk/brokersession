package dhan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// captureQuery is filled in by the happy-path test's HTTP handler so the
// test can assert the exact query parameters Dhan saw.
type captureQuery struct {
	method, dhanClientID, pin, totp string
}

func TestGenerateSession_HappyPath(t *testing.T) {
	const (
		clientID   = "1000000001"
		pin        = "123456"
		totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	)
	// Match the broker's "2006-01-02T15:04:05.000" wire format.
	rawExpiry := "2026-05-12T21:46:16.999"
	wantExpiryWire := "2026-05-12 21:46:16"

	var got captureQuery
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		q := r.URL.Query()
		got.dhanClientID = q.Get("dhanClientId")
		got.pin = q.Get("pin")
		got.totp = q.Get("totp")
		_, _ = w.Write([]byte(`{
			"dhanClientId": "1000000001",
			"dhanClientName": "JOHN DOE",
			"dhanClientUcc": "ABCD12345E",
			"givenPowerOfAttorney": false,
			"accessToken": "eyJ-fake-jwt",
			"expiryTime": "` + rawExpiry + `"
		}`))
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/auth/generateAccessToken"})

	creds := Credentials{ClientID: clientID, PIN: pin, TOTPSecret: totpSecret}
	sess, err := New().GenerateSession(context.Background(), creds)
	if err != nil {
		t.Fatalf("GenerateSession error: %v", err)
	}

	// Request shape assertions.
	if got.method != http.MethodPost {
		t.Errorf("HTTP method = %s, want POST", got.method)
	}
	if got.dhanClientID != clientID {
		t.Errorf("dhanClientId = %q, want %q", got.dhanClientID, clientID)
	}
	if got.pin != pin {
		t.Errorf("pin = %q, want %q", got.pin, pin)
	}
	if got.totp == "" || len(got.totp) != 6 {
		t.Errorf("totp = %q, want 6 digits", got.totp)
	}

	// Session shape assertions.
	if sess.Broker != brokersession.BrokerDhan {
		t.Errorf("Broker = %q, want %q", sess.Broker, brokersession.BrokerDhan)
	}
	if sess.ClientID != "1000000001" || sess.ClientName != "JOHN DOE" || sess.ClientUcc != "ABCD12345E" {
		t.Errorf("identity wrong: %+v", sess)
	}
	if sess.AccessToken != "eyJ-fake-jwt" {
		t.Errorf("AccessToken = %q, want eyJ-fake-jwt", sess.AccessToken)
	}
	if sess.GivenPowerOfAttorney != false {
		t.Errorf("GivenPowerOfAttorney = %v, want false", sess.GivenPowerOfAttorney)
	}
	if sess.ExpiryTime != wantExpiryWire {
		t.Errorf("ExpiryTime = %q, want %q", sess.ExpiryTime, wantExpiryWire)
	}
	if sess.IssuedAt == nil {
		t.Errorf("IssuedAt = nil, want non-nil")
	}
	if sess.ExpiresAt == nil {
		t.Errorf("ExpiresAt = nil, want non-nil")
	} else {
		want, _ := time.ParseInLocation("2006-01-02T15:04:05.000", rawExpiry, internal.IST)
		if !sess.ExpiresAt.Equal(want) {
			t.Errorf("ExpiresAt = %v, want %v", sess.ExpiresAt, want)
		}
		if sess.ExpiresAt.Location().String() != internal.IST.String() {
			t.Errorf("ExpiresAt location = %s, want %s", sess.ExpiresAt.Location(), internal.IST)
		}
	}
}

func TestGenerateSession_UsesProvidedTOTPValue(t *testing.T) {
	var sawTOTP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTOTP = r.URL.Query().Get("totp")
		_, _ = w.Write([]byte(`{
			"dhanClientId": "1", "dhanClientName": "x", "dhanClientUcc": "x",
			"givenPowerOfAttorney": false, "accessToken": "tok",
			"expiryTime": "2026-05-12T21:46:16.999"
		}`))
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/"})

	creds := Credentials{ClientID: "1000000001", PIN: "123456", TOTPValue: "987654"}
	if _, err := New().GenerateSession(context.Background(), creds); err != nil {
		t.Fatalf("GenerateSession error: %v", err)
	}
	if sawTOTP != "987654" {
		t.Errorf("totp = %q, want 987654 (pre-computed value)", sawTOTP)
	}
}

func TestGenerateSession_HTTPError_ParsedMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorType":"Auth","errorCode":"DH-901","errorMessage":"Invalid OTP"}`))
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/"})

	_, err := New().GenerateSession(context.Background(), validCreds())
	assertBSError(t, err, brokersession.BrokerDhan, StepGenerateToken, http.StatusBadRequest, "Invalid OTP")

	// Raw must carry the decoded body so callers can read errorCode.
	var bsErr *brokersession.Error
	if !errors.As(err, &bsErr) {
		t.Fatalf("err is not *brokersession.Error: %v", err)
	}
	if bsErr.Raw == nil {
		t.Fatalf("Raw = nil, want decoded body map")
	}
	if got, _ := bsErr.Raw["errorCode"].(string); got != "DH-901" {
		t.Errorf("Raw.errorCode = %q, want %q", got, "DH-901")
	}
}

func TestGenerateSession_HTTPError_UnparseableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<html>500</html>`))
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/"})

	_, err := New().GenerateSession(context.Background(), validCreds())
	// Fallback message includes status text and byte count.
	assertBSError(t, err, brokersession.BrokerDhan, StepGenerateToken, http.StatusInternalServerError, "Internal Server Error")
}

func TestGenerateSession_TransportError(t *testing.T) {
	withEndpoints(t, map[*string]string{&urlGenerateToken: "http://127.0.0.1:1/"})
	_, err := New().GenerateSession(context.Background(), validCreds())
	var bsErr *brokersession.Error
	if !errors.As(err, &bsErr) {
		t.Fatalf("err is not *brokersession.Error: %v", err)
	}
	if bsErr.Step != StepGenerateToken {
		t.Errorf("Step = %q, want %q", bsErr.Step, StepGenerateToken)
	}
	if bsErr.Err == nil {
		t.Errorf("Err = nil, want wrapped transport cause")
	}
}

func TestGenerateSession_MalformedExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"dhanClientId": "1", "dhanClientName": "x", "dhanClientUcc": "x",
			"givenPowerOfAttorney": false, "accessToken": "tok",
			"expiryTime": "not-a-date"
		}`))
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/"})

	_, err := New().GenerateSession(context.Background(), validCreds())
	assertBSError(t, err, brokersession.BrokerDhan, StepGenerateToken, -1, "parse expiry_time")
}

func TestGenerateSession_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"dhanClientId": "1", "dhanClientName": "x", "dhanClientUcc": "x",
			"givenPowerOfAttorney": false, "accessToken": "",
			"expiryTime": "2026-05-12T21:46:16.999"
		}`))
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/"})

	_, err := New().GenerateSession(context.Background(), validCreds())
	assertBSError(t, err, brokersession.BrokerDhan, StepGenerateToken, -1, "empty access_token")
}

func TestGenerateSession_ValidationShortCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP call should happen on validation failure: got %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlGenerateToken: srv.URL + "/"})

	bad := validCreds()
	bad.PIN = "12" // too short
	_, err := New().GenerateSession(context.Background(), bad)
	assertBSError(t, err, brokersession.BrokerDhan, brokersession.StepValidate, -1, "PIN")
}
