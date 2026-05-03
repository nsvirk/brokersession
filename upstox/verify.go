package upstox

import (
	"context"
	"net/http"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

var urlProfile = "https://api.upstox.com/v2/user/profile"

// VerifySession returns true if the broker accepts the session's
// access_token, false otherwise.
//
// Wire details: GET https://api.upstox.com/v2/user/profile with
// `Authorization: Bearer <session.AccessToken>`. 200 ⇒ true, any other
// status ⇒ false.
//
// Calling VerifySession with a nil session returns
// (false, *brokersession.Error{Step: StepValidate, Message: "session: required"})
// without making any HTTP call. Transport-level failures (DNS, TCP reset,
// context cancellation) return (false, *brokersession.Error{Step: StepVerify, Err: cause}).
func (c *Client) VerifySession(ctx context.Context, session *brokersession.Session) (bool, error) {
	if session == nil {
		return false, &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    brokersession.StepValidate,
			Message: "session: required",
		}
	}

	req, _ := http.NewRequest(http.MethodGet, urlProfile, nil)
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.uaOrDefault())

	hc := internal.NewHTTPClient(c.transport)
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return false, &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    brokersession.StepVerify,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
