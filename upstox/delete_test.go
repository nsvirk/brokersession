package upstox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsvirk/brokersession"
)

func deleteServer(t *testing.T, status int, body string, gotAuth *string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if gotAuth != nil {
			*gotAuth = r.Header.Get("Authorization")
		}
		if body != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlLogout: srv.URL + "/logout"})
}

func TestDeleteSession_HappyPath(t *testing.T) {
	var gotAuth string
	deleteServer(t, http.StatusOK, `{}`, &gotAuth)
	if err := New().DeleteSession(context.Background(), &brokersession.Session{AccessToken: "tok"}); err != nil {
		t.Fatalf("DeleteSession error: %v", err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
}

func TestDeleteSession_401_Idempotent(t *testing.T) {
	deleteServer(t, http.StatusUnauthorized, `{"errors":[{"message":"already gone"}]}`, nil)
	if err := New().DeleteSession(context.Background(), &brokersession.Session{AccessToken: "tok"}); err != nil {
		t.Errorf("DeleteSession returned %v on 401, want nil (idempotent)", err)
	}
}

func TestDeleteSession_404_Idempotent(t *testing.T) {
	deleteServer(t, http.StatusNotFound, ``, nil)
	if err := New().DeleteSession(context.Background(), &brokersession.Session{AccessToken: "tok"}); err != nil {
		t.Errorf("DeleteSession returned %v on 404, want nil (idempotent)", err)
	}
}

func TestDeleteSession_500(t *testing.T) {
	deleteServer(t, http.StatusInternalServerError, `{"errors":[{"message":"oops"}]}`, nil)
	err := New().DeleteSession(context.Background(), &brokersession.Session{AccessToken: "tok"})
	assertBSError(t, err, brokersession.BrokerUpstox, brokersession.StepDelete, http.StatusInternalServerError, "oops")
}

func TestDeleteSession_NilSession(t *testing.T) {
	err := New().DeleteSession(context.Background(), nil)
	assertBSError(t, err, brokersession.BrokerUpstox, brokersession.StepValidate, -1, "session: required")
}
