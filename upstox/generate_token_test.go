package upstox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nsvirk/brokersession"
)

func tokenServer(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/token", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlTokenExchange: srv.URL + "/token"})
}

func TestDoTokenExchange_HappyPath(t *testing.T) {
	iat := time.Now().Unix()
	exp := iat + 86400
	jwt := fakeJWT(t, map[string]any{
		"sub":           "X",
		"iat":           iat,
		"exp":           exp,
		"isMultiClient": false,
		"isPlusPlan":    true,
		"plan":          "PRO",
		"user_type":     "individual",
		"user_id":       "AB1234",
	})
	respBody := fmt.Sprintf(`{
		"access_token":"%s",
		"extended_token":"ext-tok",
		"user_id":"AB1234",
		"user_name":"Some User",
		"user_type":"individual",
		"email":"u@example.com",
		"exchanges":["NSE","BSE"],
		"products":["D","I"],
		"order_types":["MARKET","LIMIT"]
	}`, jwt)

	var (
		gotForm url.Values
		gotCT   string
	)
	tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		f, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotForm = f
		_, _ = w.Write([]byte(respBody))
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), authCode: "auth-code-987"}
	sess, err := c.doTokenExchange(context.Background(), s)
	if err != nil {
		t.Fatalf("doTokenExchange error: %v", err)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", gotCT)
	}
	if gotForm.Get("code") != "auth-code-987" {
		t.Errorf("form.code = %q, want auth-code-987", gotForm.Get("code"))
	}
	if gotForm.Get("client_id") != validCreds().APIKey {
		t.Errorf("form.client_id = %q, want %q", gotForm.Get("client_id"), validCreds().APIKey)
	}
	if gotForm.Get("client_secret") != validCreds().APISecret {
		t.Errorf("form.client_secret = %q, want %q", gotForm.Get("client_secret"), validCreds().APISecret)
	}
	if gotForm.Get("grant_type") != "authorization_code" {
		t.Errorf("form.grant_type = %q, want authorization_code", gotForm.Get("grant_type"))
	}
	if sess.UserID != "AB1234" || sess.UserName != "Some User" {
		t.Errorf("session identity wrong: %+v", sess)
	}
	if sess.AccessToken != jwt {
		t.Errorf("access_token mismatch")
	}
	if sess.IssuedAt == nil || sess.IssuedAt.Unix() != iat {
		t.Errorf("IssuedAt = %v, want unix=%d", sess.IssuedAt, iat)
	}
	if sess.ExpiresAt == nil || sess.ExpiresAt.Unix() != exp {
		t.Errorf("ExpiresAt = %v, want unix=%d", sess.ExpiresAt, exp)
	}
	if sess.IssuedAt.Location().String() != "Asia/Kolkata" && sess.IssuedAt.Location().String() != "IST" {
		t.Errorf("IssuedAt location = %s, want IST", sess.IssuedAt.Location())
	}
	// Raw round-trips.
	var rawCheck map[string]any
	if err := json.Unmarshal([]byte(respBody), &rawCheck); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if sess.Raw["access_token"] != rawCheck["access_token"] {
		t.Errorf("Raw.access_token mismatch")
	}
}

func TestDoTokenExchange_EmptyAccessToken(t *testing.T) {
	tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":""}`))
	})
	c := New()
	_, err := c.doTokenExchange(context.Background(), &flowState{
		hc: defaultTestClient(), creds: validCreds(), authCode: "x",
	})
	assertBSError(t, err, brokersession.BrokerUpstox, StepTokenExchange, http.StatusOK, "empty access_token")
}

func TestDoTokenExchange_NonJWT(t *testing.T) {
	tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"not-a-jwt"}`))
	})
	c := New()
	_, err := c.doTokenExchange(context.Background(), &flowState{
		hc: defaultTestClient(), creds: validCreds(), authCode: "x",
	})
	assertBSError(t, err, brokersession.BrokerUpstox, StepTokenExchange, http.StatusOK, "3 segments")
}

func TestDoTokenExchange_HTTPError(t *testing.T) {
	tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"errorCode":"UDAPI100050","message":"Invalid token"}]}`))
	})
	c := New()
	_, err := c.doTokenExchange(context.Background(), &flowState{
		hc: defaultTestClient(), creds: validCreds(), authCode: "x",
	})
	assertBSError(t, err, brokersession.BrokerUpstox, StepTokenExchange, http.StatusUnauthorized, "Invalid token")
}
