package zerodha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nsvirk/brokersession"
)

// apiLegServer routes /connect/login, /connect/finish, and /session/token
// through one mux. Pass nil for any handler to assert it isn't called.
func apiLegServer(t *testing.T, login, finish, token http.HandlerFunc) {
	t.Helper()
	mux := http.NewServeMux()
	if login == nil {
		login = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected /connect/login")
		}
	}
	if finish == nil {
		finish = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected /connect/finish")
		}
	}
	if token == nil {
		token = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected /session/token")
		}
	}
	mux.Handle("/connect/login", login)
	mux.Handle("/connect/finish", finish)
	mux.Handle("/session/token", token)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{
		&urlConnectLogin:  srv.URL + "/connect/login",
		&urlConnectFinish: srv.URL + "/connect/finish",
		&urlSessionToken:  srv.URL + "/session/token",
	})
}

func TestDoGetSessID_HappyPath(t *testing.T) {
	creds := apiCreds()
	apiLegServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api_key") != creds.APIKey {
			t.Errorf("api_key query = %q, want %q", r.URL.Query().Get("api_key"), creds.APIKey)
		}
		w.Header().Set("Location", "https://kite.zerodha.com/connect/login/SESSID-42")
		// 302 with sess_id in the query; build that URL explicitly.
		u, _ := url.Parse("https://kite.zerodha.com/connect/login")
		q := u.Query()
		q.Set("sess_id", "SESSID-42")
		u.RawQuery = q.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusFound)
	}, nil, nil)
	c := New()
	got, err := c.doGetSessID(context.Background(), defaultTestClient(), c.defaultHeaders(), creds)
	if err != nil {
		t.Fatalf("doGetSessID error: %v", err)
	}
	if got != "SESSID-42" {
		t.Errorf("sess_id = %q, want SESSID-42", got)
	}
}

func TestDoGetSessID_Non302(t *testing.T) {
	apiLegServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, nil, nil)
	c := New()
	_, err := c.doGetSessID(context.Background(), defaultTestClient(), c.defaultHeaders(), apiCreds())
	assertBSError(t, err, brokersession.BrokerZerodha, StepGetSessID, http.StatusOK, "expected 302")
}

func TestDoGetRequestToken_HappyPath(t *testing.T) {
	apiLegServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sess_id") != "SESSID-42" {
			t.Errorf("sess_id query = %q, want SESSID-42", r.URL.Query().Get("sess_id"))
		}
		u, _ := url.Parse("https://example.com/cb")
		q := u.Query()
		q.Set("request_token", "REQTOK-xyz")
		u.RawQuery = q.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusFound)
	}, nil)
	c := New()
	got, err := c.doGetRequestToken(context.Background(), defaultTestClient(), c.defaultHeaders(), apiCreds(), "SESSID-42")
	if err != nil {
		t.Fatalf("doGetRequestToken error: %v", err)
	}
	if got != "REQTOK-xyz" {
		t.Errorf("request_token = %q, want REQTOK-xyz", got)
	}
}

func TestDoGetRequestToken_MissingToken(t *testing.T) {
	apiLegServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/cb")
		w.WriteHeader(http.StatusFound)
	}, nil)
	c := New()
	_, err := c.doGetRequestToken(context.Background(), defaultTestClient(), c.defaultHeaders(), apiCreds(), "x")
	assertBSError(t, err, brokersession.BrokerZerodha, StepGetRequestToken, -1, "request_token missing")
}

func TestDoSessionToken_HappyPath_ChecksumCorrect(t *testing.T) {
	creds := apiCreds()
	wantChecksum := func() string {
		sum := sha256.Sum256([]byte(creds.APIKey + "REQTOK-xyz" + creds.APISecret))
		return hex.EncodeToString(sum[:])
	}()

	var gotForm url.Values
	apiLegServer(t, nil, nil, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		_, _ = w.Write([]byte(`{"status":"success","data":{
			"user_id":"AB1234","user_name":"User","user_type":"individual","email":"u@x.com",
			"broker":"ZERODHA","exchanges":["NSE","BSE"],"products":["CNC","MIS"],
			"order_types":["MARKET","LIMIT"],"api_key":"abc123","access_token":"acc-tok",
			"refresh_token":"ref-tok","enctoken":"enc-from-api","login_time":"2026-05-03 09:30:00"
		}}`))
	})
	c := New()
	tokResp, raw, err := c.doSessionToken(context.Background(), defaultTestClient(), c.defaultHeaders(), creds, "REQTOK-xyz")
	if err != nil {
		t.Fatalf("doSessionToken error: %v", err)
	}
	if gotForm.Get("checksum") != wantChecksum {
		t.Errorf("checksum = %q, want %q", gotForm.Get("checksum"), wantChecksum)
	}
	if gotForm.Get("api_key") != creds.APIKey {
		t.Errorf("api_key form = %q, want %q", gotForm.Get("api_key"), creds.APIKey)
	}
	if gotForm.Get("request_token") != "REQTOK-xyz" {
		t.Errorf("request_token form = %q, want REQTOK-xyz", gotForm.Get("request_token"))
	}
	if tokResp.Data.AccessToken != "acc-tok" {
		t.Errorf("AccessToken = %q, want acc-tok", tokResp.Data.AccessToken)
	}
	if data, ok := raw["data"].(map[string]any); !ok || data["access_token"] != "acc-tok" {
		t.Errorf("Raw.data.access_token mismatch")
	}
}

func TestDoSessionToken_KiteErrorEnvelope(t *testing.T) {
	apiLegServer(t, nil, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":"error","message":"Token is invalid","error_type":"TokenException"}`))
	})
	c := New()
	_, _, err := c.doSessionToken(context.Background(), defaultTestClient(), c.defaultHeaders(), apiCreds(), "x")
	assertBSError(t, err, brokersession.BrokerZerodha, StepSessionToken, http.StatusUnauthorized, "Token is invalid")
}

// apiCreds returns a Credentials value with both APIKey and APISecret set,
// triggering the API leg.
func apiCreds() Credentials {
	c := validCreds()
	c.APIKey = "abc123"
	c.APISecret = "supersecret"
	return c
}
