package upstox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// Endpoint URLs — Upstox login flow. var (not const) so tests can swap them
// to a httptest.Server URL via withEndpoints; the public Client API is
// unaffected.
var (
	urlDialog        = "https://api.upstox.com/v2/login/authorization/dialog"
	urlOTPGenerate   = "https://service.upstox.com/login/open/v6/auth/1fa/otp/generate"
	urlOTPVerify     = "https://service.upstox.com/login/open/v4/auth/1fa/otp-totp/verify"
	urlPINSubmit     = "https://service.upstox.com/login/open/v3/auth/2fa"
	urlOAuthApprove  = "https://service.upstox.com/login/v2/oauth/authorize"
	urlTokenExchange = "https://api.upstox.com/v2/login/authorization/token"

	// Internal redirect URI used by the PIN-submit and OAuth-approve
	// endpoints. NOT the user-supplied Credentials.RedirectURL.
	internalRedirectURI = "https://api-v2.upstox.com/login/authorization/redirect"
)

const (
	// Service-call HTTP origin and referer required by service.upstox.com.
	loginOrigin  = "https://login.upstox.com"
	loginReferer = "https://login.upstox.com/"

	deviceDetails = "platform=WEB|osName=Mac OS/10.15.7|osVersion=Chrome/146.0.0.0|" +
		"appVersion=4.0.0|modelName=Chrome|manufacturer=Apple|" +
		"uuid=00000000-0000-0000-0000-000000000000|userAgent=Upstox 3.0"
)

// flowState carries values produced by earlier steps and consumed by later ones.
type flowState struct {
	hc               *http.Client
	creds            Credentials
	internalClientID string // captured in step 1 (Dialog)
	leadUserID       string // captured in step 1 (Dialog)
	validateToken    string // captured in step 2 (OTP Generate)
	authCode         string // captured in step 5 (OAuth Approve)
}

// GenerateSession runs the six-step headless OAuth flow and returns a
// populated *Session.
func (c *Client) GenerateSession(ctx context.Context, creds Credentials) (*Session, error) {
	if err := creds.Validate(); err != nil {
		return nil, err
	}

	s := &flowState{
		hc:    internal.NewHTTPClient(c.transport),
		creds: creds,
	}

	if err := c.doDialog(ctx, s); err != nil {
		return nil, err
	}
	if err := c.doOTPGenerate(ctx, s); err != nil {
		return nil, err
	}
	if err := c.doOTPVerify(ctx, s); err != nil {
		return nil, err
	}
	if err := c.doPINSubmit(ctx, s); err != nil {
		return nil, err
	}
	if err := c.doOAuthApprove(ctx, s); err != nil {
		return nil, err
	}
	return c.doTokenExchange(ctx, s)
}

// --- Step 1: Dialog ---

func (c *Client) doDialog(ctx context.Context, s *flowState) error {
	u := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s",
		urlDialog,
		url.QueryEscape(s.creds.APIKey),
		url.QueryEscape(s.creds.RedirectURL),
	)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", c.uaOrDefault())

	resp, err := s.hc.Do(req.WithContext(ctx))
	if err != nil {
		return c.wrap(StepDialog, 0, nil, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := internal.ReadBody(resp)
		return c.httpErr(StepDialog, resp.StatusCode, body)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		return &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepDialog,
			StatusCode: resp.StatusCode,
			Message:    "empty Location header on redirect",
		}
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		return &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepDialog,
			StatusCode: resp.StatusCode,
			Message:    "parse Location: " + err.Error(),
		}
	}
	s.internalClientID = parsed.Query().Get("client_id")
	s.leadUserID = parsed.Query().Get("user_id")
	if s.internalClientID == "" {
		return &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepDialog,
			StatusCode: resp.StatusCode,
			Message:    "client_id missing from redirect Location",
		}
	}
	if s.leadUserID == "" {
		return &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepDialog,
			StatusCode: resp.StatusCode,
			Message:    "user_id missing from redirect Location",
		}
	}
	return nil
}

// --- Step 2: OTP Generate ---

func (c *Client) doOTPGenerate(ctx context.Context, s *flowState) error {
	type body struct {
		MobileNumber string `json:"mobileNumber"`
		UserID       string `json:"userId"`
	}
	data, err := c.postService(ctx, s, urlOTPGenerate, body{
		MobileNumber: s.creds.Mobile,
		UserID:       s.leadUserID,
	}, StepOTPGenerate)
	if err != nil {
		return err
	}
	var resp struct {
		ValidateOTPToken string `json:"validateOTPToken"`
		IsTotpEnabled    bool   `json:"isTotpEnabled"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOTPGenerate,
			Message: "decode response: " + err.Error(),
		}
	}
	if !resp.IsTotpEnabled {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOTPGenerate,
			Message: "authenticator-app 2FA not enabled on Upstox account; enable it in Profile → Security → Two-factor authentication",
		}
	}
	if resp.ValidateOTPToken == "" {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOTPGenerate,
			Message: "empty validateOTPToken in response",
		}
	}
	s.validateToken = resp.ValidateOTPToken
	return nil
}

// --- Step 3: OTP Verify ---

func (c *Client) doOTPVerify(ctx context.Context, s *flowState) error {
	otp := s.creds.TOTPValue
	if otp == "" {
		v, err := internal.GenerateTOTP(s.creds.TOTPSecret, time.Now())
		if err != nil {
			return &brokersession.Error{
				Broker:  brokersession.BrokerUpstox,
				Step:    StepOTPVerify,
				Message: fmt.Sprintf("totp: %v", err),
				Err:     err,
			}
		}
		otp = v
	}
	type body struct {
		OTP              string `json:"otp"`
		ValidateOtpToken string `json:"validateOtpToken"`
		ClientID         string `json:"clientId"`
	}
	if _, err := c.postService(ctx, s, urlOTPVerify, body{
		OTP:              otp,
		ValidateOtpToken: s.validateToken,
		ClientID:         s.internalClientID,
	}, StepOTPVerify); err != nil {
		return err
	}
	return nil
}

// --- Step 4: PIN Submit ---

func (c *Client) doPINSubmit(ctx context.Context, s *flowState) error {
	pinB64 := base64.StdEncoding.EncodeToString([]byte(s.creds.PIN))
	u := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s",
		urlPINSubmit,
		url.QueryEscape(s.internalClientID),
		url.QueryEscape(internalRedirectURI),
	)
	type body struct {
		TwoFAMethod string `json:"twoFAMethod"`
		InputText   string `json:"inputText"`
	}
	if _, err := c.postService(ctx, s, u, body{
		TwoFAMethod: "SECRET_PIN",
		InputText:   pinB64,
	}, StepPINSubmit); err != nil {
		return err
	}
	return nil
}

// --- Step 5: OAuth Approve ---

func (c *Client) doOAuthApprove(ctx context.Context, s *flowState) error {
	reqID, err := generateOAuthRequestID()
	if err != nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOAuthApprove,
			Message: err.Error(),
			Err:     err,
		}
	}
	u := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&requestId=%s&response_type=code",
		urlOAuthApprove,
		url.QueryEscape(s.internalClientID),
		url.QueryEscape(internalRedirectURI),
		url.QueryEscape(reqID),
	)
	type body struct {
		UserOAuthApproval bool `json:"userOAuthApproval"`
	}
	data, err := c.postService(ctx, s, u, body{UserOAuthApproval: true}, StepOAuthApprove)
	if err != nil {
		return err
	}
	var resp struct {
		RedirectURI string `json:"redirectUri"`
		IsApproved  bool   `json:"isApproved"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOAuthApprove,
			Message: "decode response: " + err.Error(),
		}
	}
	parsed, err := url.Parse(resp.RedirectURI)
	if err != nil {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOAuthApprove,
			Message: "parse redirectUri: " + err.Error(),
		}
	}
	s.authCode = parsed.Query().Get("code")
	if s.authCode == "" {
		return &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    StepOAuthApprove,
			Message: "auth code missing from redirectUri",
		}
	}
	return nil
}

// --- Step 6: Token Exchange ---

func (c *Client) doTokenExchange(ctx context.Context, s *flowState) (*Session, error) {
	form := url.Values{
		"code":          {s.authCode},
		"client_id":     {s.creds.APIKey},
		"client_secret": {s.creds.APISecret},
		"redirect_uri":  {s.creds.RedirectURL},
		"grant_type":    {"authorization_code"},
	}
	req, _ := http.NewRequest(http.MethodPost, urlTokenExchange, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.uaOrDefault())
	req.Header.Set("Accept", "application/json")

	resp, err := s.hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, c.wrap(StepTokenExchange, 0, nil, err)
	}
	defer resp.Body.Close()

	body, err := internal.ReadBody(resp)
	if err != nil {
		return nil, c.wrap(StepTokenExchange, resp.StatusCode, nil,
			fmt.Errorf("read body: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.httpErr(StepTokenExchange, resp.StatusCode, body)
	}

	var tok struct {
		AccessToken   string   `json:"access_token"`
		ExtendedToken string   `json:"extended_token"`
		UserID        string   `json:"user_id"`
		UserName      string   `json:"user_name"`
		UserType      string   `json:"user_type"`
		Email         string   `json:"email"`
		Exchanges     []string `json:"exchanges"`
		Products      []string `json:"products"`
		OrderTypes    []string `json:"order_types"`
		POA           bool     `json:"poa"`
		IsActive      bool     `json:"is_active"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepTokenExchange,
			StatusCode: resp.StatusCode,
			Message:    "decode token response: " + err.Error(),
		}
	}
	if tok.AccessToken == "" {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepTokenExchange,
			StatusCode: resp.StatusCode,
			Message:    "empty access_token in response",
		}
	}

	jwt, err := decodeJWTPayload(tok.AccessToken)
	if err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       StepTokenExchange,
			StatusCode: resp.StatusCode,
			Message:    err.Error(),
		}
	}

	issuedAt := time.Unix(jwt.Iat, 0).In(internal.IST)
	expiresAt := time.Unix(jwt.Exp, 0).In(internal.IST)
	return &Session{
		Broker:        brokersession.BrokerUpstox,
		UserID:        tok.UserID,
		UserName:      tok.UserName,
		UserType:      tok.UserType,
		Email:         tok.Email,
		Exchanges:     tok.Exchanges,
		Products:      tok.Products,
		OrderTypes:    tok.OrderTypes,
		POA:           tok.POA,
		IsActive:      tok.IsActive,
		APIKey:        s.creds.APIKey,
		AccessToken:   tok.AccessToken,
		ExtendedToken: tok.ExtendedToken,
		IssuedAt:      &issuedAt,
		ExpiresAt:     &expiresAt,
	}, nil
}

// --- helpers ---

func (c *Client) uaOrDefault() string {
	if c.userAgent != "" {
		return c.userAgent
	}
	return internal.DefaultUserAgent
}

// postService POSTs a JSON body wrapped in {"data": ...} to a service.upstox.com
// endpoint with the standard service headers. Returns the "data" field of
// the success envelope; converts non-success / non-2xx responses into a
// *brokersession.Error.
func (c *Client) postService(ctx context.Context, s *flowState, u string, payload any, step brokersession.Step) (json.RawMessage, error) {
	reqID, err := generateRequestID()
	if err != nil {
		return nil, &brokersession.Error{
			Broker:  brokersession.BrokerUpstox,
			Step:    step,
			Message: err.Error(),
			Err:     err,
		}
	}
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(wrapDataEnvelope(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", loginOrigin)
	req.Header.Set("Referer", loginReferer)
	req.Header.Set("User-Agent", c.uaOrDefault())
	req.Header.Set("X-Device-Details", deviceDetails)
	req.Header.Set("X-Request-Id", reqID)

	resp, err := s.hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, c.wrap(step, 0, nil, err)
	}
	defer resp.Body.Close()

	body, err := internal.ReadBody(resp)
	if err != nil {
		return nil, c.wrap(step, resp.StatusCode, nil, fmt.Errorf("read body: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.httpErr(step, resp.StatusCode, body)
	}

	// service.upstox.com wraps successful responses in
	// {"success":true,"data":{...}}. Parse and return the data field.
	var env struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerUpstox,
			Step:       step,
			StatusCode: resp.StatusCode,
			Message:    "decode envelope: " + err.Error(),
		}
	}
	if !env.Success {
		return nil, c.httpErr(step, resp.StatusCode, body)
	}
	return env.Data, nil
}

// wrap converts an arbitrary error (typically transport-level) into a
// *brokersession.Error with the given step and optional status.
func (c *Client) wrap(step brokersession.Step, statusCode int, raw map[string]any, err error) error {
	return &brokersession.Error{
		Broker:     brokersession.BrokerUpstox,
		Step:       step,
		StatusCode: statusCode,
		Message:    err.Error(),
		Err:        err,
		Raw:        raw,
	}
}

// httpErr builds a *brokersession.Error from a non-2xx response body using
// the shared parseErrorBody helper. Falls back to a generic message when
// the body isn't decodable as JSON or doesn't match either envelope.
func (c *Client) httpErr(step brokersession.Step, statusCode int, body []byte) error {
	bsErr := &brokersession.Error{
		Broker:     brokersession.BrokerUpstox,
		Step:       step,
		StatusCode: statusCode,
	}
	msg, raw, ok := parseErrorBody(body)
	if ok {
		bsErr.Raw = raw
	}
	if msg != "" {
		bsErr.Message = msg
	} else {
		bsErr.Message = fmt.Sprintf("%s (unparseable body, %d bytes)",
			http.StatusText(statusCode), len(body))
	}
	return bsErr
}

// generateRequestID produces a WPRO-<10 hex chars> nonce per the
// X-Request-Id header convention used by service.upstox.com. Returns an
// error if the system RNG fails so callers don't silently emit a constant
// ID across concurrent flows.
func generateRequestID() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("upstox: generate request id: %w", err)
	}
	return "WPRO-" + hex.EncodeToString(b), nil
}

// generateOAuthRequestID produces a PW<11 hex chars> nonce for step 5's
// requestId query parameter. Returns an error if the system RNG fails.
func generateOAuthRequestID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("upstox: generate oauth request id: %w", err)
	}
	return "PW" + hex.EncodeToString(b)[:11], nil
}
