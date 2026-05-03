package upstox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func pinServer(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/pin", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{&urlPINSubmit: srv.URL + "/pin"})
}

func TestDoPINSubmit_HappyPath(t *testing.T) {
	var (
		gotQuery url.Values
		gotData  map[string]any
	)
	pinServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		raw, _ := io.ReadAll(r.Body)
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Errorf("decode req: %v", err)
		}
		gotData = env.Data
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	c := New()
	s := &flowState{
		hc:               defaultTestClient(),
		creds:            validCreds(),
		internalClientID: "internal-cid-123",
	}
	if err := c.doPINSubmit(context.Background(), s); err != nil {
		t.Fatalf("doPINSubmit error: %v", err)
	}
	if gotQuery.Get("client_id") != "internal-cid-123" {
		t.Errorf("client_id query = %q, want internal-cid-123", gotQuery.Get("client_id"))
	}
	if gotQuery.Get("redirect_uri") != internalRedirectURI {
		t.Errorf("redirect_uri query = %q, want %q", gotQuery.Get("redirect_uri"), internalRedirectURI)
	}
	if gotData["twoFAMethod"] != "SECRET_PIN" {
		t.Errorf("twoFAMethod = %v, want SECRET_PIN", gotData["twoFAMethod"])
	}
	if gotData["inputText"] != b64(validCreds().PIN) {
		t.Errorf("inputText = %v, want base64(PIN)=%q", gotData["inputText"], b64(validCreds().PIN))
	}
}
