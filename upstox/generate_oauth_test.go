package upstox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsvirk/brokersession"
)

func oauthServer(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/oauth/approve", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlOAuthApprove: srv.URL + "/oauth/approve"})
}

func TestDoOAuthApprove_HappyPath(t *testing.T) {
	oauthServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"isApproved":true,"redirectUri":"https://example.com/cb?code=auth-code-987&state=x"}}`))
	})
	c := New()
	s := &flowState{
		hc:               defaultTestClient(),
		creds:            validCreds(),
		internalClientID: "internal-cid-123",
	}
	if err := c.doOAuthApprove(context.Background(), s); err != nil {
		t.Fatalf("doOAuthApprove error: %v", err)
	}
	if s.authCode != "auth-code-987" {
		t.Errorf("authCode = %q, want auth-code-987", s.authCode)
	}
}

func TestDoOAuthApprove_BadRedirectURI(t *testing.T) {
	oauthServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"isApproved":true,"redirectUri":":://not-a-url"}}`))
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), internalClientID: "x"}
	err := c.doOAuthApprove(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOAuthApprove, -1, "parse redirectUri")
}

func TestDoOAuthApprove_MissingCode(t *testing.T) {
	oauthServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"isApproved":true,"redirectUri":"https://example.com/cb?state=x"}}`))
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds(), internalClientID: "x"}
	err := c.doOAuthApprove(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepOAuthApprove, -1, "auth code missing")
}
