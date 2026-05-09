package zerodha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nsvirk/brokersession"
)

func deleteServer(t *testing.T, status int, body string, gotQuery *map[string][]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if gotQuery != nil {
			*gotQuery = r.URL.Query()
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlSessionToken: srv.URL + "/session/token"})
}

func TestDeleteSession_API_HappyPath(t *testing.T) {
	var gotQuery map[string][]string
	deleteServer(t, http.StatusOK, `{"status":"success"}`, &gotQuery)
	sess := &Session{APIKey: "abc123", AccessToken: "acc-tok"}
	if err := New().DeleteSession(context.Background(), sess); err != nil {
		t.Fatalf("DeleteSession error: %v", err)
	}
	if gotQuery["api_key"][0] != "abc123" {
		t.Errorf("api_key query = %v, want abc123", gotQuery["api_key"])
	}
	if gotQuery["access_token"][0] != "acc-tok" {
		t.Errorf("access_token query = %v, want acc-tok", gotQuery["access_token"])
	}
}

func TestDeleteSession_API_401_Idempotent(t *testing.T) {
	deleteServer(t, http.StatusUnauthorized, `{"status":"error"}`, nil)
	sess := &Session{APIKey: "abc", AccessToken: "tok"}
	if err := New().DeleteSession(context.Background(), sess); err != nil {
		t.Errorf("DeleteSession returned %v on 401, want nil (idempotent)", err)
	}
}

func TestDeleteSession_API_404_Idempotent(t *testing.T) {
	deleteServer(t, http.StatusNotFound, ``, nil)
	sess := &Session{APIKey: "abc", AccessToken: "tok"}
	if err := New().DeleteSession(context.Background(), sess); err != nil {
		t.Errorf("DeleteSession returned %v on 404, want nil (idempotent)", err)
	}
}

func TestDeleteSession_API_500(t *testing.T) {
	deleteServer(t, http.StatusInternalServerError,
		`{"status":"error","message":"oops","error_type":"GeneralException"}`, nil)
	sess := &Session{APIKey: "abc", AccessToken: "tok"}
	err := New().DeleteSession(context.Background(), sess)
	assertBSError(t, err, brokersession.BrokerZerodha, brokersession.StepDelete, http.StatusInternalServerError, "oops")
}

func TestDeleteSession_OMSOnly_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("OMS-only DeleteSession must not call broker, got %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlSessionToken: srv.URL + "/session/token"})

	sess := &Session{Enctoken: "enc-tok"} // APIKey empty → OMS-only
	if err := New().DeleteSession(context.Background(), sess); err != nil {
		t.Errorf("OMS-only DeleteSession returned %v, want nil (no-op)", err)
	}
}

func TestDeleteSession_NilSession(t *testing.T) {
	err := New().DeleteSession(context.Background(), nil)
	assertBSError(t, err, brokersession.BrokerZerodha, brokersession.StepValidate, -1, "session: required")
}
