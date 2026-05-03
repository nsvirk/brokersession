package upstox

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// fakeJWT builds a header.payload.signature JWT string with the given
// claims as the (base64url-encoded, unpadded) payload.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".sig"
}

func TestDecodeJWTPayload_AllClaims(t *testing.T) {
	t.Parallel()
	token := fakeJWT(t, map[string]any{
		"sub":           "PROFILE123",
		"jti":           "TOKEN-XYZ",
		"iat":           1714630800,
		"exp":           1714717200,
		"isMultiClient": true,
		"isPlusPlan":    false,
		"plan":          "PRO",
		"user_type":     "individual",
		"user_id":       "AB1234",
	})
	got, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatalf("decodeJWTPayload error: %v", err)
	}
	if got.Sub != "PROFILE123" {
		t.Errorf("Sub = %q, want %q", got.Sub, "PROFILE123")
	}
	if got.Jti != "TOKEN-XYZ" {
		t.Errorf("Jti = %q, want %q", got.Jti, "TOKEN-XYZ")
	}
	if got.Iat != 1714630800 {
		t.Errorf("Iat = %d, want 1714630800", got.Iat)
	}
	if got.Exp != 1714717200 {
		t.Errorf("Exp = %d, want 1714717200", got.Exp)
	}
	if !got.IsMultiClient {
		t.Errorf("IsMultiClient = false, want true")
	}
	if got.IsPlusPlan {
		t.Errorf("IsPlusPlan = true, want false")
	}
	if got.Plan != "PRO" {
		t.Errorf("Plan = %q, want %q", got.Plan, "PRO")
	}
	if got.UserType != "individual" {
		t.Errorf("UserType = %q, want %q", got.UserType, "individual")
	}
	if got.UserID != "AB1234" {
		t.Errorf("UserID = %q, want %q", got.UserID, "AB1234")
	}
}

func TestDecodeJWTPayload_WrongSegmentCount(t *testing.T) {
	t.Parallel()
	tests := []string{
		"only.two",
		"a.b.c.d",
		"single",
		"",
	}
	for _, tok := range tests {
		_, err := decodeJWTPayload(tok)
		if err == nil {
			t.Errorf("decodeJWTPayload(%q) = nil error, want error", tok)
			continue
		}
		if !strings.Contains(err.Error(), "3 segments") {
			t.Errorf("decodeJWTPayload(%q) error = %v, want segment count error", tok, err)
		}
	}
}

func TestDecodeJWTPayload_BadBase64Payload(t *testing.T) {
	t.Parallel()
	_, err := decodeJWTPayload("aGVhZGVy.@@not-base64@@.sig")
	if err == nil {
		t.Fatalf("decodeJWTPayload with bad base64 returned nil")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error = %v, want it to mention base64", err)
	}
}

func TestDecodeJWTPayload_NonJSONPayload(t *testing.T) {
	t.Parallel()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not valid json`))
	_, err := decodeJWTPayload(header + "." + payload + ".sig")
	if err == nil {
		t.Fatalf("decodeJWTPayload with non-JSON payload returned nil")
	}
	if !strings.Contains(err.Error(), "json") {
		t.Errorf("error = %v, want it to mention json", err)
	}
}

func TestDecodeJWTPayload_MissingIat(t *testing.T) {
	t.Parallel()
	tok := fakeJWT(t, map[string]any{
		"sub": "X",
		"exp": 1714717200,
	})
	_, err := decodeJWTPayload(tok)
	if err == nil || !strings.Contains(err.Error(), "iat") {
		t.Errorf("decodeJWTPayload missing iat: err = %v, want iat error", err)
	}
}

func TestDecodeJWTPayload_MissingExp(t *testing.T) {
	t.Parallel()
	tok := fakeJWT(t, map[string]any{
		"sub": "X",
		"iat": 1714630800,
	})
	_, err := decodeJWTPayload(tok)
	if err == nil || !strings.Contains(err.Error(), "exp") {
		t.Errorf("decodeJWTPayload missing exp: err = %v, want exp error", err)
	}
}
