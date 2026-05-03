package upstox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nsvirk/brokersession"
)

// dialogServer returns a httptest.Server whose /dialog handler is configured
// by the provided handler. Useful for asserting on the request and shaping
// the redirect response per test.
func dialogServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/dialog", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlDialog: srv.URL + "/dialog"})
	return srv
}

func TestDoDialog_HappyPath(t *testing.T) {
	var gotQuery url.Values
	dialogServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Location",
			"https://login.upstox.com/?client_id=internal-cid-123&user_id=lead-uid-456")
		w.WriteHeader(http.StatusFound)
	})

	creds := validCreds()
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: creds}
	if err := c.doDialog(context.Background(), s); err != nil {
		t.Fatalf("doDialog error: %v", err)
	}
	if s.internalClientID != "internal-cid-123" {
		t.Errorf("internalClientID = %q, want internal-cid-123", s.internalClientID)
	}
	if s.leadUserID != "lead-uid-456" {
		t.Errorf("leadUserID = %q, want lead-uid-456", s.leadUserID)
	}
	if got := gotQuery.Get("client_id"); got != creds.APIKey {
		t.Errorf("client_id query = %q, want %q", got, creds.APIKey)
	}
	if got := gotQuery.Get("redirect_uri"); got != creds.RedirectURL {
		t.Errorf("redirect_uri query = %q, want %q", got, creds.RedirectURL)
	}
	if got := gotQuery.Get("response_type"); got != "code" {
		t.Errorf("response_type query = %q, want code", got)
	}
}

func TestDoDialog_Non302Status(t *testing.T) {
	dialogServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"errorCode":"X","message":"unexpected 200"}]}`))
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds()}
	err := c.doDialog(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepDialog, http.StatusOK, "unexpected 200")
}

func TestDoDialog_EmptyLocation(t *testing.T) {
	dialogServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds()}
	err := c.doDialog(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepDialog, http.StatusFound, "empty Location header")
}

func TestDoDialog_MissingClientID(t *testing.T) {
	dialogServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://login.upstox.com/?user_id=lead-uid-456")
		w.WriteHeader(http.StatusFound)
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds()}
	err := c.doDialog(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepDialog, http.StatusFound, "client_id missing")
}

func TestDoDialog_MissingUserID(t *testing.T) {
	dialogServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://login.upstox.com/?client_id=internal-cid-123")
		w.WriteHeader(http.StatusFound)
	})
	c := New()
	s := &flowState{hc: defaultTestClient(), creds: validCreds()}
	err := c.doDialog(context.Background(), s)
	assertBSError(t, err, brokersession.BrokerUpstox, StepDialog, http.StatusFound, "user_id missing")
}
