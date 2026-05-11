package dhan

import (
	"net/http"

	"github.com/nsvirk/brokersession"
)

// Dhan-specific Step constants. Underlying string values are part of the
// public API and are asserted in credentials_test.go.
const (
	StepGenerateToken brokersession.Step = "generate_token"
)

// Client is a Dhan session generator. Safe for concurrent
// GenerateSession / DeleteSession calls — each call constructs a fresh
// *http.Client.
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
