package dhan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsvirk/brokersession"
)

func verifyServer(t *testing.T, status int, gotAuth *string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotAuth != nil {
			*gotAuth = r.Header.Get("access-token")
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlProfile: srv.URL + "/profile"})
}

func TestVerifySession_OK(t *testing.T) {
	var gotAuth string
	verifyServer(t, http.StatusOK, &gotAuth)
	ok, err := New().VerifySession(context.Background(), &Session{AccessToken: "the-token"})
	if err != nil {
		t.Fatalf("VerifySession error: %v", err)
	}
	if !ok {
		t.Errorf("ok = false, want true")
	}
	if gotAuth != "the-token" {
		t.Errorf("access-token header = %q, want %q", gotAuth, "the-token")
	}
}

func TestVerifySession_401(t *testing.T) {
	verifyServer(t, http.StatusUnauthorized, nil)
	ok, err := New().VerifySession(context.Background(), &Session{AccessToken: "x"})
	if err != nil {
		t.Fatalf("VerifySession error: %v", err)
	}
	if ok {
		t.Errorf("ok = true, want false")
	}
}

func TestVerifySession_NilSession(t *testing.T) {
	ok, err := New().VerifySession(context.Background(), nil)
	if ok {
		t.Errorf("ok = true, want false")
	}
	assertBSError(t, err, brokersession.BrokerDhan, brokersession.StepValidate, -1, "session: required")
}

func TestVerifySession_TransportError(t *testing.T) {
	// Non-routable URL → transport-level error.
	withEndpoints(t, map[*string]string{&urlProfile: "http://127.0.0.1:1/profile"})
	ok, err := New().VerifySession(context.Background(), &Session{AccessToken: "x"})
	if ok {
		t.Errorf("ok = true on transport error")
	}
	var bsErr *brokersession.Error
	if !errors.As(err, &bsErr) {
		t.Fatalf("err is not *brokersession.Error: %v", err)
	}
	if bsErr.Step != brokersession.StepVerify {
		t.Errorf("Step = %q, want %q", bsErr.Step, brokersession.StepVerify)
	}
	if bsErr.Err == nil {
		t.Errorf("Err = nil, want wrapped transport cause")
	}
}
