package zerodha

import (
	"net/http"

	"github.com/nsvirk/brokersession"
)

// Zerodha-specific Step constants. Underlying string values are part of the
// public API and are asserted in credentials_test.go.
const (
	StepLogin           brokersession.Step = "login"
	StepTwoFA           brokersession.Step = "twofa"
	StepProfile         brokersession.Step = "profile"
	StepGetSessID       brokersession.Step = "get_sess_id"
	StepGetRequestToken brokersession.Step = "get_request_token"
	StepSessionToken    brokersession.Step = "session_token"
)

// Client is a Zerodha session generator. Safe for concurrent
// GenerateSession / DeleteSession calls — each call constructs a fresh
// *http.Client with its own cookie jar.
type Client struct {
	transport http.RoundTripper
	userAgent string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient configures only the transport (TLS, proxy, dialer) of the
// supplied client. The supplied client's Jar and Timeout are ignored — the
// library always provides a fresh cookiejar.New(nil) and Timeout: 0.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.transport = c.Transport
		}
	}
}

// WithUserAgent overrides the default Mozilla-style User-Agent string.
func WithUserAgent(ua string) Option {
	return func(cl *Client) { cl.userAgent = ua }
}

// New returns a Client configured with the given options.
func New(opts ...Option) *Client {
	c := &Client{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
