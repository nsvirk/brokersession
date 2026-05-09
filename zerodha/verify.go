package zerodha

import (
	"context"
	"net/http"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// VerifySession returns true if the broker accepts the session's credentials,
// false otherwise.
//
// Behaviour by flow:
//
//   - API mode (session.APIKey set): GET https://api.kite.trade/user/profile
//     with `Authorization: token <APIKey>:<AccessToken>`. 200 ⇒ true,
//     any other status ⇒ false.
//   - OMS-only mode (session.APIKey == ""): GET
//     https://kite.zerodha.com/oms/user/profile with
//     `Authorization: enctoken <Enctoken>`. 200 ⇒ true, any other status ⇒ false.
//
// Calling VerifySession with a nil session returns
// (false, *brokersession.Error{Step: StepValidate, Message: "session: required"})
// without making any HTTP call. Transport-level failures (DNS, TCP reset,
// context cancellation) return (false, *brokersession.Error{Step: StepVerify, Err: cause}).
func (c *Client) VerifySession(ctx context.Context, session *Session) (bool, error) {
	if session == nil {
		return false, &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    brokersession.StepValidate,
			Message: "session: required",
		}
	}

	var (
		url     string
		authHdr string
	)
	if session.APIKey != "" {
		url = urlAPIProfile
		authHdr = "token " + session.APIKey + ":" + session.AccessToken
	} else {
		url = urlProfile
		authHdr = "enctoken " + session.Enctoken
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	applyHeaders(req, c.defaultHeaders())
	req.Header.Set("Authorization", authHdr)

	hc := internal.NewHTTPClient(c.transport)
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return false, &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    brokersession.StepVerify,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
