package upstox

import (
	"encoding/json"
	"testing"
)

func TestWrapDataEnvelope(t *testing.T) {
	t.Parallel()
	got := wrapDataEnvelope(map[string]any{"foo": "bar", "n": 42})
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if decoded.Data["foo"] != "bar" {
		t.Errorf("data.foo = %v, want bar", decoded.Data["foo"])
	}
	if decoded.Data["n"].(float64) != 42 {
		t.Errorf("data.n = %v, want 42", decoded.Data["n"])
	}
}

func TestParseErrorBody_FormatA_ErrorsArray(t *testing.T) {
	t.Parallel()
	body := []byte(`{"status":"error","errors":[{"errorCode":"UDAPI100050","message":"Invalid token used to access API","propertyPath":null,"invalidValue":null}]}`)
	msg, raw, ok := parseErrorBody(body)
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if msg != "Invalid token used to access API" {
		t.Errorf("message = %q, want %q", msg, "Invalid token used to access API")
	}
	if raw["status"] != "error" {
		t.Errorf("raw[status] = %v, want error", raw["status"])
	}
	errs, ok := raw["errors"].([]any)
	if !ok || len(errs) != 1 {
		t.Errorf("raw[errors] = %v, want one-item array", raw["errors"])
	}
}

func TestParseErrorBody_FormatA_ErrorObject(t *testing.T) {
	t.Parallel()
	body := []byte(`{"status":"error","error":{"errorCode":"UDAPI100050","message":"Bad request"}}`)
	msg, raw, ok := parseErrorBody(body)
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if msg != "Bad request" {
		t.Errorf("message = %q, want %q", msg, "Bad request")
	}
	if raw == nil {
		t.Errorf("raw = nil, want decoded body")
	}
}

func TestParseErrorBody_EmptyErrorsArray(t *testing.T) {
	t.Parallel()
	body := []byte(`{"status":"error","errors":[]}`)
	msg, raw, ok := parseErrorBody(body)
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if msg != "" {
		t.Errorf("message = %q, want empty (fallback)", msg)
	}
	if raw == nil {
		t.Errorf("raw = nil, want decoded body")
	}
}

func TestParseErrorBody_NonJSON(t *testing.T) {
	t.Parallel()
	body := []byte(`<html><body>Cloudflare interstitial</body></html>`)
	msg, raw, ok := parseErrorBody(body)
	if ok {
		t.Errorf("ok = true, want false for non-JSON body")
	}
	if msg != "" {
		t.Errorf("message = %q, want empty", msg)
	}
	if raw != nil {
		t.Errorf("raw = %v, want nil", raw)
	}
}

func TestParseErrorBody_EmptyBody(t *testing.T) {
	t.Parallel()
	msg, raw, ok := parseErrorBody(nil)
	if ok {
		t.Errorf("ok = true on empty body, want false")
	}
	if msg != "" {
		t.Errorf("message = %q, want empty", msg)
	}
	if raw != nil {
		t.Errorf("raw = %v, want nil", raw)
	}
}
