package zerodha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsvirk/brokersession"
)

func verifyServer(t *testing.T, status int, gotAuth, gotPath *string) {
	t.Helper()
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		if gotAuth != nil {
			*gotAuth = r.Header.Get("Authorization")
		}
		if gotPath != nil {
			*gotPath = r.URL.Path
		}
		w.WriteHeader(status)
	}
	mux.HandleFunc("/oms/user/profile", handler)
	mux.HandleFunc("/user/profile", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{
		&urlProfile:    srv.URL + "/oms/user/profile",
		&urlAPIProfile: srv.URL + "/user/profile",
	})
}

func TestVerifySession_OMSMode_OK(t *testing.T) {
	var gotAuth, gotPath string
	verifyServer(t, http.StatusOK, &gotAuth, &gotPath)
	ok, err := New().VerifySession(context.Background(), &brokersession.Session{Enctoken: "enc-tok"})
	if err != nil {
		t.Fatalf("VerifySession error: %v", err)
	}
	if !ok {
		t.Errorf("ok = false, want true")
	}
	if gotAuth != "enctoken enc-tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "enctoken enc-tok")
	}
	if gotPath != "/oms/user/profile" {
		t.Errorf("path = %q, want /oms/user/profile (OMS endpoint)", gotPath)
	}
}

func TestVerifySession_APIMode_OK(t *testing.T) {
	var gotAuth, gotPath string
	verifyServer(t, http.StatusOK, &gotAuth, &gotPath)
	ok, err := New().VerifySession(context.Background(), &brokersession.Session{
		APIKey: "abc123", AccessToken: "acc-tok",
	})
	if err != nil {
		t.Fatalf("VerifySession error: %v", err)
	}
	if !ok {
		t.Errorf("ok = false, want true")
	}
	if gotAuth != "token abc123:acc-tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "token abc123:acc-tok")
	}
	if gotPath != "/user/profile" {
		t.Errorf("path = %q, want /user/profile (API endpoint)", gotPath)
	}
}

func TestVerifySession_401(t *testing.T) {
	verifyServer(t, http.StatusUnauthorized, nil, nil)
	ok, err := New().VerifySession(context.Background(), &brokersession.Session{Enctoken: "x"})
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
	assertBSError(t, err, brokersession.BrokerZerodha, brokersession.StepValidate, -1, "session: required")
}

func TestVerifySession_TransportError(t *testing.T) {
	withEndpoints(t, map[*string]string{
		&urlProfile:    "http://127.0.0.1:1/profile",
		&urlAPIProfile: "http://127.0.0.1:1/profile",
	})
	ok, err := New().VerifySession(context.Background(), &brokersession.Session{Enctoken: "x"})
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
