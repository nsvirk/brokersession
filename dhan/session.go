package dhan

import (
	"time"

	"github.com/nsvirk/brokersession"
)

// Session is the result of a successful Dhan GenerateSession call.
//
// Field shape mirrors the Dhan
// `POST /app/generateAccessToken` response JSON, with snake_case JSON
// tags suitable for storage.
//
// ExpiryTime carries the broker's expiry timestamp normalized to the
// "2006-01-02 15:04:05" format (IST). IssuedAt is derived as
// time.Now().In(IST) because Dhan's API does not return one. ExpiresAt
// is the IST time.Time parsed from the broker's raw expiryTime field
// ("2006-01-02T15:04:05.000" wire format).
type Session struct {
	Broker               brokersession.BrokerName `json:"broker"`
	ClientID             string                   `json:"client_id"`
	ClientName           string                   `json:"client_name,omitempty"`
	ClientUcc            string                   `json:"client_ucc,omitempty"`
	GivenPowerOfAttorney bool                     `json:"given_power_of_attorney"`
	AccessToken          string                   `json:"access_token,omitempty"`
	ExpiryTime           string                   `json:"expiry_time,omitempty"`
	IssuedAt             *time.Time               `json:"issued_at,omitempty"`
	ExpiresAt            *time.Time               `json:"expires_at,omitempty"`
}
