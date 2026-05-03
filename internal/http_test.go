package internal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPClient_Defaults(t *testing.T) {
	t.Parallel()
	c := NewHTTPClient(nil)
	if c.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0 (context-driven)", c.Timeout)
	}
	if c.Jar == nil {
		t.Errorf("Jar = nil, want non-nil cookie jar")
	}
	if c.CheckRedirect == nil {
		t.Errorf("CheckRedirect = nil, want ErrUseLastResponse")
	}
	// Verify the redirect callback returns ErrUseLastResponse.
	if got := c.CheckRedirect(nil, nil); got != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect() = %v, want %v", got, http.ErrUseLastResponse)
	}
}

func TestNewHTTPClient_CookieIsolation(t *testing.T) {
	t.Parallel()
	a := NewHTTPClient(nil)
	b := NewHTTPClient(nil)
	if a.Jar == b.Jar {
		t.Errorf("two NewHTTPClient calls share a jar; expected isolated jars")
	}
}

func TestNewHTTPClient_RedirectNotFollowed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere?code=ABC", http.StatusFound)
	}))
	defer srv.Close()

	c := NewHTTPClient(nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "code=ABC") {
		t.Errorf("Location = %q, want it to contain code=ABC", loc)
	}
}

func TestDo_Success_DecodesJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"alice","age":30}`)
	}))
	defer srv.Close()

	var out struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err := Do(context.Background(), srv.Client(), req, &out); err != nil {
		t.Fatalf("Do error: %v", err)
	}
	if out.Name != "alice" || out.Age != 30 {
		t.Errorf("decoded = %+v, want {alice 30}", out)
	}
}

func TestDo_Success_NilOutSkipsDecode(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `not valid json`)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err := Do(context.Background(), srv.Client(), req, nil); err != nil {
		t.Errorf("Do with nil out should ignore body; got error %v", err)
	}
}

func TestDo_HTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":"error","message":"invalid token"}`)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	err := Do(context.Background(), srv.Client(), req, nil)
	if err == nil {
		t.Fatalf("Do on 401 returned nil, want *HTTPError")
	}
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("err is not *HTTPError: %v", err)
	}
	if he.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", he.StatusCode)
	}
	if !strings.Contains(string(he.Body), `"invalid token"`) {
		t.Errorf("Body = %q, want it to contain the error message", he.Body)
	}
	if !strings.Contains(he.Error(), "401") {
		t.Errorf("HTTPError.Error() = %q, want it to mention status code", he.Error())
	}
}

func TestDo_5xxAlsoHTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	err := Do(context.Background(), srv.Client(), req, nil)
	he := AsHTTPError(err)
	if he == nil {
		t.Fatalf("err is not *HTTPError: %v", err)
	}
	if he.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", he.StatusCode)
	}
}

func TestDo_NonJSONBody_DecodeError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `not valid json`)
	}))
	defer srv.Close()

	var out map[string]any
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	err := Do(context.Background(), srv.Client(), req, &out)
	if err == nil {
		t.Fatalf("Do with non-JSON body and out!=nil returned nil")
	}
	if AsHTTPError(err) != nil {
		t.Errorf("err should be a decode error, not *HTTPError")
	}
}

func TestDo_ContextCancellation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	err := Do(ctx, srv.Client(), req, nil)
	if err == nil {
		t.Fatalf("Do with cancelled context returned nil")
	}
	if AsHTTPError(err) != nil {
		t.Errorf("transport error misreported as *HTTPError")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err does not wrap context.DeadlineExceeded: %v", err)
	}
}

func TestDo_FormPayload(t *testing.T) {
	t.Parallel()
	var got struct {
		ContentType string
		Body        string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.ContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		got.Body = string(b)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	body := strings.NewReader("user_id=AB1234&password=secret")
	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := Do(context.Background(), srv.Client(), req, nil); err != nil {
		t.Fatalf("Do error: %v", err)
	}
	if got.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got.ContentType)
	}
	if got.Body != "user_id=AB1234&password=secret" {
		t.Errorf("Body = %q, want form-encoded", got.Body)
	}
}
