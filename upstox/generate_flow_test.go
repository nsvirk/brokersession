package upstox

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nsvirk/brokersession"
)

// TestGenerateSession_FullFlow drives all six steps end-to-end against an
// httptest.Server. Asserts the final *brokersession.Session is fully
// populated and that broker/raw/issued_at/expires_at all wire up correctly.
func TestGenerateSession_FullFlow(t *testing.T) {
	creds := validCreds()
	iat := time.Now().Unix()
	exp := iat + 86400
	jwt := fakeJWT(t, map[string]any{
		"iat": iat, "exp": exp, "user_id": "AB1234", "user_type": "individual", "plan": "PRO",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/dialog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://login.upstox.com/?client_id=cid&user_id=lead-uid")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/otp/generate", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"validateOTPToken":"vtok","isTotpEnabled":true}}`))
	})
	mux.HandleFunc("/otp/verify", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	mux.HandleFunc("/pin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	mux.HandleFunc("/oauth/approve", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"isApproved":true,"redirectUri":"https://example.com/cb?code=auth-code-987"}}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"access_token":"%s","extended_token":"ext","user_id":"AB1234","user_name":"User","user_type":"individual","email":"u@x.com","exchanges":["NSE"],"products":["I"],"order_types":["MARKET"]}`, jwt)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	pointAllToServer(t, srv)

	sess, err := New().GenerateSession(context.Background(), creds)
	if err != nil {
		t.Fatalf("GenerateSession error: %v", err)
	}
	if sess.Broker != brokersession.BrokerUpstox {
		t.Errorf("Broker = %s, want %s", sess.Broker, brokersession.BrokerUpstox)
	}
	if sess.UserID != "AB1234" || sess.UserName != "User" || sess.Email != "u@x.com" {
		t.Errorf("identity wrong: %+v", sess)
	}
	if sess.AccessToken != jwt {
		t.Errorf("access_token mismatch")
	}
	if sess.APIKey != creds.APIKey {
		t.Errorf("APIKey = %q, want %q", sess.APIKey, creds.APIKey)
	}
	if sess.IssuedAt == nil || sess.IssuedAt.Unix() != iat {
		t.Errorf("IssuedAt wrong")
	}
	if sess.ExpiresAt == nil || sess.ExpiresAt.Unix() != exp {
		t.Errorf("ExpiresAt wrong")
	}
	if len(sess.Exchanges) != 1 || sess.Exchanges[0] != "NSE" {
		t.Errorf("Exchanges = %v", sess.Exchanges)
	}
	if sess.Raw["access_token"] != jwt {
		t.Errorf("Raw.access_token mismatch")
	}
}

// TestGenerateSession_StopsAtFirstFailure asserts that a mid-flow error
// prevents subsequent steps from running and is surfaced as a structured
// *brokersession.Error.
func TestGenerateSession_StopsAtFirstFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dialog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://login.upstox.com/?client_id=cid&user_id=lead-uid")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/otp/generate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"errorCode":"X","message":"bad mobile"}]}`))
	})
	mux.HandleFunc("/otp/verify", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("/otp/verify must not be called after /otp/generate fails")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	pointAllToServer(t, srv)

	_, err := New().GenerateSession(context.Background(), validCreds())
	assertBSError(t, err, brokersession.BrokerUpstox, StepOTPGenerate, http.StatusBadRequest, "bad mobile")
}

// TestGenerateSession_ValidationShortCircuit asserts that a credential
// validation failure prevents any HTTP call.
func TestGenerateSession_ValidationShortCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP call should happen on validation failure: got %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	pointAllToServer(t, srv)

	bad := validCreds()
	bad.PIN = "12" // too short
	_, err := New().GenerateSession(context.Background(), bad)
	assertBSError(t, err, brokersession.BrokerUpstox, brokersession.StepValidate, -1, "PIN")
}
