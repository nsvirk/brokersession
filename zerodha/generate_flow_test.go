package zerodha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nsvirk/brokersession"
)

// TestGenerateSession_API_FullFlow drives the full OMS+API flow.
func TestGenerateSession_API_FullFlow(t *testing.T) {
	creds := apiCreds()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "kf_session", Value: "kf-val", Path: "/"})
		_, _ = w.Write([]byte(`{"status":"success","data":{"user_id":"AB1234","request_id":"req-987"}}`))
	})
	mux.HandleFunc("/api/twofa", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "enc-tok", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "public_token", Value: "pub-tok", Path: "/"})
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	mux.HandleFunc("/oms/user/profile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{
			"user_id":"AB1234","user_name":"OMS Name","user_type":"individual",
			"email":"u@x.com","broker":"ZERODHA",
			"exchanges":["NSE"],"products":["CNC"],"order_types":["MARKET"]
		}}`))
	})
	mux.HandleFunc("/connect/login", func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse("https://example.com/login")
		q := u.Query()
		q.Set("sess_id", "SESSID-42")
		u.RawQuery = q.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/connect/finish", func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse("https://example.com/cb")
		q := u.Query()
		q.Set("request_token", "REQTOK-xyz")
		u.RawQuery = q.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/session/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{
			"user_id":"AB1234","user_name":"API Name","user_type":"individual","email":"api@x.com",
			"broker":"ZERODHA","exchanges":["NSE","BSE"],"products":["CNC","MIS"],
			"order_types":["MARKET","LIMIT"],"api_key":"abc123","access_token":"acc-tok",
			"refresh_token":"ref-tok","enctoken":"enc-from-api","login_time":"2026-05-03 09:30:00"
		}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	pointAllToServer(t, srv)

	sess, err := New().GenerateSession(context.Background(), creds)
	if err != nil {
		t.Fatalf("GenerateSession error: %v", err)
	}
	if sess.Broker != brokersession.BrokerZerodha {
		t.Errorf("Broker = %s, want zerodha", sess.Broker)
	}
	// API leg overrides OMS-derived identity.
	if sess.UserName != "API Name" {
		t.Errorf("UserName = %q, want API Name (API-leg override)", sess.UserName)
	}
	if sess.Email != "api@x.com" {
		t.Errorf("Email = %q, want api@x.com (API-leg override)", sess.Email)
	}
	// Enctoken stays as OMS cookie value (the canonical one).
	if sess.Enctoken != "enc-tok" {
		t.Errorf("Enctoken = %q, want enc-tok (OMS cookie canonical)", sess.Enctoken)
	}
	if sess.AccessToken != "acc-tok" {
		t.Errorf("AccessToken = %q, want acc-tok", sess.AccessToken)
	}
	if sess.APIKey != "abc123" {
		t.Errorf("APIKey = %q, want abc123", sess.APIKey)
	}
	if sess.IssuedAt == nil || sess.IssuedAt.Format("2006-01-02 15:04:05") != "2026-05-03 09:30:00" {
		t.Errorf("IssuedAt = %v, want parsed login_time 2026-05-03 09:30:00 IST", sess.IssuedAt)
	}
	// Raw is the verbatim API-leg session/token body.
	if data, ok := sess.Raw["data"].(map[string]any); !ok || data["access_token"] != "acc-tok" {
		t.Errorf("Raw.data.access_token mismatch")
	}
}

// TestGenerateSession_API_ChecksumPropagatedCorrectly proves the actual
// checksum hits the wire as SHA256(api_key + request_token + api_secret).
func TestGenerateSession_API_ChecksumPropagatedCorrectly(t *testing.T) {
	creds := apiCreds()
	wantChecksum := hex.EncodeToString(sha256Sum(creds.APIKey + "REQTOK-xyz" + creds.APISecret))
	var gotChecksum string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"request_id":"req-987"}}`))
	})
	mux.HandleFunc("/api/twofa", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "enc-tok", Path: "/"})
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	mux.HandleFunc("/oms/user/profile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{}}`))
	})
	mux.HandleFunc("/connect/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/login?sess_id=S")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/connect/finish", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/cb?request_token=REQTOK-xyz")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/session/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotChecksum = r.PostForm.Get("checksum")
		_, _ = w.Write([]byte(`{"status":"success","data":{"access_token":"a"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	pointAllToServer(t, srv)

	if _, err := New().GenerateSession(context.Background(), creds); err != nil {
		t.Fatalf("GenerateSession error: %v", err)
	}
	if gotChecksum != wantChecksum {
		t.Errorf("checksum on wire = %q, want %q", gotChecksum, wantChecksum)
	}
}

func TestGenerateSession_ValidationShortCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP call should happen on validation failure: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	pointAllToServer(t, srv)

	bad := validCreds()
	bad.UserID = ""
	_, err := New().GenerateSession(context.Background(), bad)
	assertBSError(t, err, brokersession.BrokerZerodha, brokersession.StepValidate, -1, "UserID")
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
