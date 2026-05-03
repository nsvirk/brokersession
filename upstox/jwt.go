package upstox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// jwtPayload holds the decoded claims from the OAuth access_token JWT
// returned by api.upstox.com's /v2/login/authorization/token endpoint.
type jwtPayload struct {
	Sub           string `json:"sub"`
	Jti           string `json:"jti"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
	IsMultiClient bool   `json:"isMultiClient"`
	IsPlusPlan    bool   `json:"isPlusPlan"`
	Plan          string `json:"plan"`
	UserType      string `json:"user_type"`
	UserID        string `json:"user_id"`
}

// decodeJWTPayload splits the token on '.', base64url-decodes the middle
// segment, and JSON-unmarshals it into a jwtPayload. No signature
// verification — TLS delivery is trusted, matching the reference
// goupstoxsession behavior.
func decodeJWTPayload(token string) (*jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("access_token is not a JWT (expected 3 segments, got %d)", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload base64: %w", err)
	}
	var p jwtPayload
	if err := json.Unmarshal(decoded, &p); err != nil {
		return nil, fmt.Errorf("decode JWT payload json: %w", err)
	}
	if p.Iat == 0 {
		return nil, fmt.Errorf("JWT missing iat claim")
	}
	if p.Exp == 0 {
		return nil, fmt.Errorf("JWT missing exp claim")
	}
	return &p, nil
}
