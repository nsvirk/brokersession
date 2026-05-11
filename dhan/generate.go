package dhan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// urlGenerateToken is Dhan's access-token generation endpoint. var (not
// const) so tests can swap it via withEndpoints.
var urlGenerateToken = "https://auth.dhan.co/app/generateAccessToken"

const (
	// dhanAPITimeFormat is Dhan's expiry-time wire format (no timezone,
	// millisecond precision).
	dhanAPITimeFormat = "2006-01-02T15:04:05.000"
	// dhanWireTimeFormat is the brokersession-normalized output format
	// stored on Session.ExpiryTime (matches Zerodha's LoginTime format).
	dhanWireTimeFormat = "2006-01-02 15:04:05"
)

// GenerateSession runs Dhan's one-step headless flow:
//
//  1. POST https://auth.dhan.co/app/generateAccessToken with
//     dhanClientId + pin + totp as query parameters.
//
// The response carries a JWT access token plus client identity and an
// IST expiry timestamp.
func (c *Client) GenerateSession(ctx context.Context, creds Credentials) (*Session, error) {
	if err := creds.Validate(); err != nil {
		return nil, err
	}

	otp := creds.TOTPValue
	if otp == "" {
		v, err := internal.GenerateTOTP(creds.TOTPSecret, time.Now())
		if err != nil {
			return nil, &brokersession.Error{
				Broker:  brokersession.BrokerDhan,
				Step:    StepGenerateToken,
				Message: fmt.Sprintf("totp: %v", err),
				Err:     err,
			}
		}
		otp = v
	}

	u := fmt.Sprintf("%s?dhanClientId=%s&pin=%s&totp=%s",
		urlGenerateToken,
		url.QueryEscape(creds.ClientID),
		url.QueryEscape(creds.PIN),
		url.QueryEscape(otp),
	)
	req, _ := http.NewRequest(http.MethodPost, u, nil)
	req.Header.Set("User-Agent", c.uaOrDefault())
	req.Header.Set("Accept", "application/json")

	hc := internal.NewHTTPClient(c.transport)
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, &brokersession.Error{
			Broker:  brokersession.BrokerDhan,
			Step:    StepGenerateToken,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	body, err := internal.ReadBody(resp)
	if err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerDhan,
			Step:       StepGenerateToken,
			StatusCode: resp.StatusCode,
			Message:    "read body: " + err.Error(),
			Err:        err,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, dhanHTTPError(StepGenerateToken, resp.StatusCode, body)
	}

	var dr struct {
		DhanClientID         string `json:"dhanClientId"`
		DhanClientName       string `json:"dhanClientName"`
		DhanClientUcc        string `json:"dhanClientUcc"`
		GivenPowerOfAttorney bool   `json:"givenPowerOfAttorney"`
		AccessToken          string `json:"accessToken"`
		ExpiryTime           string `json:"expiryTime"`
	}
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerDhan,
			Step:       StepGenerateToken,
			StatusCode: resp.StatusCode,
			Message:    "decode response: " + err.Error(),
		}
	}
	if dr.AccessToken == "" {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerDhan,
			Step:       StepGenerateToken,
			StatusCode: resp.StatusCode,
			Message:    "empty access_token in response",
		}
	}

	expiresAt, err := time.ParseInLocation(dhanAPITimeFormat, dr.ExpiryTime, internal.IST)
	if err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerDhan,
			Step:       StepGenerateToken,
			StatusCode: resp.StatusCode,
			Message:    "parse expiry_time: " + err.Error(),
		}
	}
	issuedAt := time.Now().In(internal.IST)

	return &Session{
		Broker:               brokersession.BrokerDhan,
		ClientID:             dr.DhanClientID,
		ClientName:           dr.DhanClientName,
		ClientUcc:            dr.DhanClientUcc,
		GivenPowerOfAttorney: dr.GivenPowerOfAttorney,
		AccessToken:          dr.AccessToken,
		ExpiryTime:           expiresAt.Format(dhanWireTimeFormat),
		IssuedAt:             &issuedAt,
		ExpiresAt:            &expiresAt,
	}, nil
}

// dhanHTTPError builds a *brokersession.Error from an upstream non-2xx
// response. Tries to parse Dhan's `{"errorMessage":"...","errorCode":"..."}`
// envelope; falls back to a generic message if the body isn't decodable JSON.
func dhanHTTPError(step brokersession.Step, statusCode int, body []byte) *brokersession.Error {
	bsErr := &brokersession.Error{
		Broker:     brokersession.BrokerDhan,
		Step:       step,
		StatusCode: statusCode,
	}
	var raw map[string]any
	if json.Unmarshal(body, &raw) == nil && raw != nil {
		bsErr.Raw = raw
		// Dhan's documented error key. Try a few common variations.
		for _, key := range []string{"errorMessage", "message", "error"} {
			if msg, ok := raw[key].(string); ok && msg != "" {
				bsErr.Message = msg
				return bsErr
			}
		}
	}
	bsErr.Message = fmt.Sprintf("%s (unparseable body, %d bytes)",
		http.StatusText(statusCode), len(body))
	return bsErr
}
