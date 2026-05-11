package dhan

import (
	"context"
	"net/http"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// urlProfile is the Dhan profile endpoint used by VerifySession to
// confirm that the session's access token is still accepted. var (not
// const) so tests can swap it via withEndpoints.
var urlProfile = "https://api.dhan.co/v2/profile"

// VerifySession returns true if the broker accepts the session's
// access_token, false otherwise.
//
// Wire details: GET https://api.dhan.co/v2/profile with
// `access-token: <session.AccessToken>` (Dhan uses a literal `access-token`
// header, not Authorization Bearer). 200 ⇒ true, any other status ⇒ false.
//
// Calling VerifySession with a nil session returns
// (false, *brokersession.Error{Step: StepValidate, Message: "session: required"})
// without making any HTTP call. Transport-level failures return
// (false, *brokersession.Error{Step: StepVerify, Err: cause}).
func (c *Client) VerifySession(ctx context.Context, session *Session) (bool, error) {
	if session == nil {
		return false, &brokersession.Error{
			Broker:  brokersession.BrokerDhan,
			Step:    brokersession.StepValidate,
			Message: "session: required",
		}
	}

	req, _ := http.NewRequest(http.MethodGet, urlProfile, nil)
	req.Header.Set("access-token", session.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.uaOrDefault())

	hc := internal.NewHTTPClient(c.transport)
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return false, &brokersession.Error{
			Broker:  brokersession.BrokerDhan,
			Step:    brokersession.StepVerify,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// uaOrDefault returns the configured user-agent or the shared library default.
func (c *Client) uaOrDefault() string {
	if c.userAgent != "" {
		return c.userAgent
	}
	return internal.DefaultUserAgent
}
