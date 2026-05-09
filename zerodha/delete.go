package zerodha

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// DeleteSession invalidates a Zerodha session.
//
//   - For sessions with APIKey set (API mode), issues
//     `DELETE /session/token?api_key=…&access_token=…`.
//   - For OMS-only sessions (APIKey == ""), is a no-op (Kite does not
//     expose enctoken revocation).
//
// Idempotent: a 401 or 404 response from the broker is treated as
// "already deleted" and returns nil. Other 4xx/5xx return a populated
// *brokersession.Error.
//
// Calling DeleteSession with a nil session returns a *brokersession.Error
// with Step = StepValidate and Message = "session: required" without
// making any HTTP call.
func (c *Client) DeleteSession(ctx context.Context, session *Session) error {
	if session == nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    brokersession.StepValidate,
			Message: "session: required",
		}
	}
	if session.APIKey == "" {
		// OMS-only — no-op.
		return nil
	}

	u := fmt.Sprintf("%s?api_key=%s&access_token=%s",
		urlSessionToken,
		url.QueryEscape(session.APIKey),
		url.QueryEscape(session.AccessToken),
	)
	req, _ := http.NewRequest(http.MethodDelete, u, nil)
	applyHeaders(req, c.defaultHeaders())

	hc := internal.NewHTTPClient(c.transport)
	err := internal.Do(ctx, hc, req, nil)
	if err == nil {
		return nil
	}
	if he := internal.AsHTTPError(err); he != nil {
		// Idempotency: 401/404 ⇒ already deleted.
		if he.StatusCode == http.StatusUnauthorized || he.StatusCode == http.StatusNotFound {
			return nil
		}
		return kiteHTTPError(brokersession.StepDelete, he.StatusCode, he.Body)
	}
	return &brokersession.Error{
		Broker:  brokersession.BrokerZerodha,
		Step:    brokersession.StepDelete,
		Message: err.Error(),
		Err:     err,
	}
}
