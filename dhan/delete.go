package dhan

import (
	"context"

	"github.com/nsvirk/brokersession"
)

// DeleteSession invalidates a Dhan session — except Dhan does not expose
// a logout / token-revoke endpoint, so for any non-nil session this is a
// no-op that returns nil. The token expires at the broker 24 hours after
// generation.
//
// Calling DeleteSession with a nil session returns a *brokersession.Error
// with Step = StepValidate and Message = "session: required" without
// making any HTTP call.
//
// The signature matches the other broker subpackages so callers can use
// `defer client.DeleteSession(ctx, session)` uniformly across brokers.
func (c *Client) DeleteSession(ctx context.Context, session *Session) error {
	if session == nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerDhan,
			Step:    brokersession.StepValidate,
			Message: "session: required",
		}
	}
	return nil
}
