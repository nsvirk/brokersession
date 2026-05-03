// Package internal holds plumbing shared by the brokersession broker
// subpackages. It is not part of the public API.
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// MaxBodyBytes caps response-body reads across all broker flows. 1 MiB is
// far larger than any legitimate broker JSON response and bounds memory if
// a CDN, proxy, or misbehaving broker streams unbounded data.
const MaxBodyBytes = 1 << 20

// IST is the Asia/Kolkata location used to render Session.IssuedAt /
// ExpiresAt. Falls back to a fixed +05:30 zone if the tzdata lookup fails
// (e.g. minimal scratch container without zoneinfo).
var IST = mustLoadIST()

func mustLoadIST() *time.Location {
	if loc, err := time.LoadLocation("Asia/Kolkata"); err == nil {
		return loc
	}
	return time.FixedZone("IST", 5*3600+30*60)
}

// ReadBody reads up to MaxBodyBytes from resp.Body. Use this everywhere a
// response body is consumed so size limits stay consistent.
func ReadBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
}

// DefaultUserAgent is the User-Agent string used by NewHTTPClient. It
// matches the value used by the existing nsvirk/gokitesession and
// nsvirk/goupstoxsession reference libraries to stay under broker
// anti-bot heuristics.
const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// NewHTTPClient returns an *http.Client configured for the brokersession
// flows: a fresh cookie jar, manual redirect handling
// (CheckRedirect: ErrUseLastResponse), and Timeout: 0 so cancellation is
// driven entirely by the request context.
//
// transport may be nil (uses http.DefaultTransport); pass a custom one for
// TLS pinning, proxies, or custom dialers.
//
// Each GenerateSession / DeleteSession call should construct a fresh
// client via this helper so cookies are isolated per session.
func NewHTTPClient(transport http.RoundTripper) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 0,
	}
}

// HTTPError is returned by Do for non-2xx responses. It carries the status
// code and the raw response body so callers can build a
// *brokersession.Error with broker-specific Message extraction and Raw
// population.
type HTTPError struct {
	StatusCode int
	Body       []byte
}

// Error implements the error interface.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("internal: http %d (%d body bytes)", e.StatusCode, len(e.Body))
}

// Do sends req using client. It applies req.WithContext(ctx) and reads the
// full response body before returning.
//
//   - 2xx: if out is non-nil, decodes the JSON body into out. Returns nil on
//     success; returns a JSON-decode error on malformed JSON.
//   - non-2xx: returns *HTTPError{StatusCode, Body}.
//   - transport failure: returns the underlying error wrapped with %w.
//
// The caller is responsible for building req with the correct method, URL,
// body, and Content-Type. One helper covers both JSON and form payloads.
func Do(ctx context.Context, client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("internal: http do: %w", err)
	}
	defer resp.Body.Close()

	body, err := ReadBody(resp)
	if err != nil {
		return fmt.Errorf("internal: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode, Body: body}
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(out); err != nil {
		return fmt.Errorf("internal: decode json: %w", err)
	}
	return nil
}

// AsHTTPError extracts an *HTTPError from err if present. Returns nil if
// err is a transport-level failure or any other error type.
func AsHTTPError(err error) *HTTPError {
	var he *HTTPError
	if errors.As(err, &he) {
		return he
	}
	return nil
}
