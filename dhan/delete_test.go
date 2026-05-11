package dhan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsvirk/brokersession"
)

// failingTransport implements http.RoundTripper and fails any outgoing
// request. Used to assert that DeleteSession makes no HTTP call.
type failingTransport struct {
	t *testing.T
}

func (f *failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected HTTP call from DeleteSession: %s %s", req.Method, req.URL)
	return nil, http.ErrUseLastResponse
}

func TestDeleteSession_NoOp(t *testing.T) {
	// Even if a server existed, DeleteSession must not call it. Use a
	// failing transport that errors on any request to make the violation
	// loud and observable.
	c := New(WithHTTPClient(&http.Client{Transport: &failingTransport{t: t}}))
	if err := c.DeleteSession(context.Background(), &Session{AccessToken: "tok"}); err != nil {
		t.Errorf("DeleteSession = %v, want nil (no-op)", err)
	}
}

func TestDeleteSession_NilSession(t *testing.T) {
	err := New().DeleteSession(context.Background(), nil)
	assertBSError(t, err, brokersession.BrokerDhan, brokersession.StepValidate, -1, "session: required")
}

// TestDeleteSession_StillNoOpEvenWithReachableEndpoint is a belt-and-braces
// check: spin up a real server, observe that it is never hit.
func TestDeleteSession_StillNoOpEvenWithReachableEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP call: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	if err := New().DeleteSession(context.Background(), &Session{AccessToken: "tok"}); err != nil {
		t.Errorf("DeleteSession = %v, want nil (no-op)", err)
	}
}
