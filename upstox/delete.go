package upstox

import (
	"context"
	"net/http"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

var urlLogout = "https://api.upstox.com/v2/logout"

// DeleteSession invalidates an Upstox session by calling DELETE
// https://api.upstox.com/v2/logout with Authorization: Bearer <AccessToken>.
//
// Idempotent: 401 / 404 responses are treated as "already deleted" and
// return nil. Other 4xx/5xx return a populated *brokersession.Error.
//
// Calling DeleteSession with a nil session returns a *brokersession.Error
// with Step = StepValidate and Message = "session: required" without
// making any HTTP call.
func (c *Client) DeleteSession(ctx context.Context, session *brokersession.Session) error {
	if session == nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    brokersession.StepValidate,
			Message: "session: required",
		}
	}

	req, _ := http.NewRequest(http.MethodDelete, urlLogout, nil)
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.uaOrDefault())

	hc := internal.NewHTTPClient(c.transport)
	err := internal.Do(ctx, hc, req, nil)
	if err == nil {
		return nil
	}
	if he := internal.AsHTTPError(err); he != nil {
		if he.StatusCode == http.StatusUnauthorized || he.StatusCode == http.StatusNotFound {
			return nil
		}
		return c.httpErr(brokersession.StepDelete, he.StatusCode, he.Body)
	}
	return c.wrap(brokersession.StepDelete, 0, nil, err)
}
