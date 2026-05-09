package upstox

import (
	"time"

	"github.com/nsvirk/brokersession"
)

// Session is the result of a successful Upstox GenerateSession call.
//
// Field shape mirrors the Upstox /v2/login/authorization/token response
// JSON, with snake_case JSON tags suitable for storage.
//
// IssuedAt and ExpiresAt are derived (IST) by decoding the access-token
// JWT payload (`iat` / `exp` claims). The Upstox API itself does not
// return these as fields.
type Session struct {
	Broker        brokersession.BrokerName `json:"broker"`
	UserID        string                   `json:"user_id"`
	UserName      string                   `json:"user_name,omitempty"`
	UserType      string                   `json:"user_type,omitempty"`
	Email         string                   `json:"email,omitempty"`
	Exchanges     []string                 `json:"exchanges,omitempty"`
	Products      []string                 `json:"products,omitempty"`
	OrderTypes    []string                 `json:"order_types,omitempty"`
	POA           bool                     `json:"poa"`
	IsActive      bool                     `json:"is_active"`
	APIKey        string                   `json:"api_key,omitempty"`
	AccessToken   string                   `json:"access_token,omitempty"`
	ExtendedToken string                   `json:"extended_token,omitempty"`
	IssuedAt      *time.Time               `json:"issued_at,omitempty"`
	ExpiresAt     *time.Time               `json:"expires_at,omitempty"`
}
