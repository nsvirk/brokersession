package zerodha

import (
	"time"

	"github.com/nsvirk/brokersession"
)

// Session is the result of a successful Zerodha GenerateSession call.
//
// Field shape mirrors the Kite session/token-exchange response JSON
// (the "data" object from `{"status":"success","data":{...}}`), with
// snake_case JSON tags suitable for storage.
//
// The OMS-only flow (Credentials.APIKey == "") populates the subset it
// has access to (UserID/UserName/Email/Enctoken/PublicToken/LoginTime,
// etc.); API-leg fields (APIKey, AccessToken, RefreshToken, Silo, Meta)
// remain zero in OMS-only mode.
//
// IssuedAt is derived (IST): the parsed login_time for the API leg, or
// time.Now() for OMS-only. Kite's session API does not return an expiry,
// so there is no ExpiresAt field on this type.
type Session struct {
	Broker        brokersession.BrokerName `json:"broker"`
	UserID        string                   `json:"user_id"`
	UserName      string                   `json:"user_name,omitempty"`
	UserShortname string                   `json:"user_shortname,omitempty"`
	UserType      string                   `json:"user_type,omitempty"`
	Email         string                   `json:"email,omitempty"`
	AvatarURL     string                   `json:"avatar_url,omitempty"`
	APIKey        string                   `json:"api_key,omitempty"`
	AccessToken   string                   `json:"access_token,omitempty"`
	PublicToken   string                   `json:"public_token,omitempty"`
	RefreshToken  string                   `json:"refresh_token,omitempty"`
	Enctoken      string                   `json:"enctoken,omitempty"`
	Silo          string                   `json:"silo,omitempty"`
	Exchanges     []string                 `json:"exchanges,omitempty"`
	Products      []string                 `json:"products,omitempty"`
	OrderTypes    []string                 `json:"order_types,omitempty"`
	LoginTime     string                   `json:"login_time,omitempty"`
	Meta          Meta                     `json:"meta,omitempty"`
	IssuedAt      *time.Time               `json:"issued_at,omitempty"`
}

// Meta carries the broker's "meta" sub-object from the session/token
// response.
type Meta struct {
	DematConsent string `json:"demat_consent,omitempty"`
}
