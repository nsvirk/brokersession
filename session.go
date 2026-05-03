package brokersession

import (
	"time"

	"github.com/nsvirk/brokersession/internal"
)

// BrokerName identifies which broker generated a session or error.
type BrokerName string

// Canonical broker identifiers. Wire format is the underlying string value.
const (
	BrokerZerodha BrokerName = "zerodha"
	BrokerUpstox  BrokerName = "upstox"
)

// Session is the unified output of a successful GenerateSession call.
//
// Common fields are top-level. Raw retains the verbatim JSON-decoded
// response body returned by the broker's session/token-exchange API
// (synthetic for Zerodha OMS-only flow, where no token-exchange call
// occurs); duplicate keys between top-level fields and Raw are
// intentional.
//
// All time.Time values are IST (Asia/Kolkata). ExpiresAt is a pointer so
// encoding/json's omitempty drops the field when nil — a zero time.Time
// is not "empty" to encoding/json.
type Session struct {
	Broker        BrokerName     `json:"broker"`
	UserID        string         `json:"user_id,omitempty"`
	UserName      string         `json:"user_name,omitempty"`
	UserType      string         `json:"user_type,omitempty"`
	Email         string         `json:"email,omitempty"`
	APIKey        string         `json:"api_key,omitempty"`
	AccessToken   string         `json:"access_token,omitempty"`
	ExtendedToken string         `json:"extended_token,omitempty"`
	Enctoken      string         `json:"enctoken,omitempty"`
	Exchanges     []string       `json:"exchanges,omitempty"`
	Products      []string       `json:"products,omitempty"`
	OrderTypes    []string       `json:"order_types,omitempty"`
	IssuedAt      *time.Time     `json:"issued_at,omitempty"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
	Raw           map[string]any `json:"raw"`
}

// GenerateTOTPValue derives the 6-digit RFC-6238 TOTP code for a base32
// secret at time t (SHA1, 30-second period — the defaults both Zerodha and
// Upstox 2FA expect). The returned value is suitable for the TOTPValue
// field on either broker's Credentials, so callers using that input path
// can compute codes from a stored secret without depending on a separate
// OTP library.
func GenerateTOTPValue(secret string, t time.Time) (string, error) {
	return internal.GenerateTOTP(secret, t)
}
