package zerodha

import (
	"context"
	"crypto/sha256"
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

// Endpoint URLs — Zerodha (Kite) authentication flow. var (not const) so
// tests can swap them to a httptest.Server URL via withEndpoints; the
// public Client API is unaffected.
var (
	urlLogin         = "https://kite.zerodha.com/api/login"
	urlTwoFA         = "https://kite.zerodha.com/api/twofa"
	urlConnectLogin  = "https://kite.zerodha.com/connect/login"
	urlConnectFinish = "https://kite.zerodha.com/connect/finish"
	urlSessionToken  = "https://api.kite.trade/session/token"
	urlProfile       = "https://kite.zerodha.com/oms/user/profile"
	urlAPIProfile    = "https://api.kite.trade/user/profile"
)

// loginTimeFormat is Kite's login_time string format (IST).
const loginTimeFormat = "2006-01-02 15:04:05"

// GenerateSession performs the headless Kite session-generation flow.
//
// OMS leg (always runs):
//  1. POST /api/login → request_id, kf_session cookie
//  2. POST /api/twofa with TOTP → enctoken, public_token cookies
//  3. GET /oms/user/profile with enctoken → user profile
//
// API leg (runs only when APIKey and APISecret are both set):
//  4. GET /connect/login → 302; parse sess_id from Location
//  5. GET /connect/finish?sess_id=… → 302; parse request_token from Location
//  6. POST /session/token (SHA256 checksum) → access_token, refresh_token
func (c *Client) GenerateSession(ctx context.Context, creds Credentials) (*Session, error) {
	if err := creds.Validate(); err != nil {
		return nil, err
	}

	httpClient := internal.NewHTTPClient(c.transport)
	headers := c.defaultHeaders()

	// --- OMS leg ---
	loginResp, _, err := c.doLogin(ctx, httpClient, headers, creds)
	if err != nil {
		return nil, err
	}
	twofaCookies, err := c.doTwoFA(ctx, httpClient, headers, creds, loginResp.Data.RequestID)
	if err != nil {
		return nil, err
	}
	enctoken := cookieValue(twofaCookies, "enctoken")
	if enctoken == "" {
		return nil, &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepTwoFA,
			Message: "enctoken cookie missing from twofa response",
		}
	}
	publicToken := cookieValue(twofaCookies, "public_token")

	profile, err := c.doProfile(ctx, httpClient, headers, enctoken)
	if err != nil {
		return nil, err
	}

	loginTime := time.Now().In(internal.IST)

	session := &Session{
		Broker:        brokersession.BrokerZerodha,
		UserID:        creds.UserID,
		UserName:      profile.Data.UserName,
		UserShortname: profile.Data.UserShortname,
		UserType:      profile.Data.UserType,
		Email:         profile.Data.Email,
		AvatarURL:     profile.Data.AvatarURL,
		Enctoken:      enctoken,
		PublicToken:   publicToken,
		Exchanges:     profile.Data.Exchanges,
		Products:      profile.Data.Products,
		OrderTypes:    profile.Data.OrderTypes,
		LoginTime:     loginTime.Format(loginTimeFormat),
		IssuedAt:      &loginTime,
	}

	if creds.APIKey == "" {
		// OMS-only flow: no token-exchange call. The session is fully
		// populated from profile + cookies + login time.
		return session, nil
	}

	// --- API leg ---
	sessID, err := c.doGetSessID(ctx, httpClient, headers, creds)
	if err != nil {
		return nil, err
	}
	requestToken, err := c.doGetRequestToken(ctx, httpClient, headers, creds, sessID)
	if err != nil {
		return nil, err
	}
	tokenResp, err := c.doSessionToken(ctx, httpClient, headers, creds, requestToken)
	if err != nil {
		return nil, err
	}

	// Override OMS-derived session fields with API-derived ones where they
	// differ. Enctoken stays as OMS value (the API response also returns it
	// but the cookie value is canonical).
	session.AccessToken = tokenResp.Data.AccessToken
	session.APIKey = creds.APIKey
	session.RefreshToken = tokenResp.Data.RefreshToken
	session.Silo = tokenResp.Data.Silo
	session.Meta = Meta{DematConsent: tokenResp.Data.Meta.DematConsent}
	if tokenResp.Data.LoginTime != "" {
		session.LoginTime = tokenResp.Data.LoginTime
	}
	if t, err := time.ParseInLocation(loginTimeFormat, tokenResp.Data.LoginTime, internal.IST); err == nil {
		session.IssuedAt = &t
	}
	if tokenResp.Data.UserName != "" {
		session.UserName = tokenResp.Data.UserName
	}
	if tokenResp.Data.UserShortname != "" {
		session.UserShortname = tokenResp.Data.UserShortname
	}
	if tokenResp.Data.UserType != "" {
		session.UserType = tokenResp.Data.UserType
	}
	if tokenResp.Data.Email != "" {
		session.Email = tokenResp.Data.Email
	}
	if tokenResp.Data.AvatarURL != "" {
		session.AvatarURL = tokenResp.Data.AvatarURL
	}
	if len(tokenResp.Data.Exchanges) > 0 {
		session.Exchanges = tokenResp.Data.Exchanges
	}
	if len(tokenResp.Data.Products) > 0 {
		session.Products = tokenResp.Data.Products
	}
	if len(tokenResp.Data.OrderTypes) > 0 {
		session.OrderTypes = tokenResp.Data.OrderTypes
	}
	return session, nil
}

func (c *Client) defaultHeaders() http.Header {
	h := http.Header{}
	ua := c.userAgent
	if ua == "" {
		ua = internal.DefaultUserAgent
	}
	h.Set("User-Agent", ua)
	h.Set("X-Kite-Version", "3.0.0")
	return h
}

// --- OMS leg ---

type loginResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserID    string `json:"user_id"`
		RequestID string `json:"request_id"`
	} `json:"data"`
}

func (c *Client) doLogin(ctx context.Context, hc *http.Client, headers http.Header, creds Credentials) (*loginResponse, []*http.Cookie, error) {
	form := url.Values{}
	form.Set("user_id", creds.UserID)
	form.Set("password", creds.Password)
	form.Set("type", "user_id")

	req, _ := http.NewRequest(http.MethodPost, urlLogin, strings.NewReader(form.Encode()))
	applyHeaders(req, headers)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var out loginResponse
	cookies, err := doAndCookies(ctx, hc, req, &out, StepLogin)
	if err != nil {
		return nil, nil, err
	}
	return &out, cookies, nil
}

type twoFAResponse struct {
	Status string `json:"status"`
}

func (c *Client) doTwoFA(ctx context.Context, hc *http.Client, headers http.Header, creds Credentials, requestID string) ([]*http.Cookie, error) {
	otp := creds.TOTPValue
	if otp == "" {
		v, err := internal.GenerateTOTP(creds.TOTPSecret, time.Now())
		if err != nil {
			return nil, &brokersession.Error{
				Broker:  brokersession.BrokerZerodha,
				Step:    StepTwoFA,
				Message: fmt.Sprintf("totp: %v", err),
				Err:     err,
			}
		}
		otp = v
	}

	form := url.Values{}
	form.Set("user_id", creds.UserID)
	form.Set("request_id", requestID)
	form.Set("twofa_value", otp)
	form.Set("twofa_type", "totp")
	form.Set("skip_session", "true")

	req, _ := http.NewRequest(http.MethodPost, urlTwoFA, strings.NewReader(form.Encode()))
	applyHeaders(req, headers)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var out twoFAResponse
	cookies, err := doAndCookies(ctx, hc, req, &out, StepTwoFA)
	if err != nil {
		return nil, err
	}
	return cookies, nil
}

type profileResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserID        string   `json:"user_id"`
		UserName      string   `json:"user_name"`
		UserShortname string   `json:"user_shortname"`
		UserType      string   `json:"user_type"`
		Email         string   `json:"email"`
		AvatarURL     string   `json:"avatar_url"`
		Broker        string   `json:"broker"`
		Exchanges     []string `json:"exchanges"`
		Products      []string `json:"products"`
		OrderTypes    []string `json:"order_types"`
	} `json:"data"`
}

func (c *Client) doProfile(ctx context.Context, hc *http.Client, headers http.Header, enctoken string) (*profileResponse, error) {
	req, _ := http.NewRequest(http.MethodGet, urlProfile, nil)
	applyHeaders(req, headers)
	req.Header.Set("Authorization", "enctoken "+enctoken)

	var out profileResponse
	if err := internal.Do(ctx, hc, req, &out); err != nil {
		return nil, c.wrapErr(StepProfile, err)
	}
	return &out, nil
}

// --- API leg ---

func (c *Client) doGetSessID(ctx context.Context, hc *http.Client, headers http.Header, creds Credentials) (string, error) {
	u := fmt.Sprintf("%s?v=3&api_key=%s", urlConnectLogin, url.QueryEscape(creds.APIKey))
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	applyHeaders(req, headers)

	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return "", &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepGetSessID,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return "", &brokersession.Error{
			Broker:     brokersession.BrokerZerodha,
			Step:       StepGetSessID,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("expected 302, got %d", resp.StatusCode),
		}
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepGetSessID,
			Message: "parse location: " + err.Error(),
			Err:     err,
		}
	}
	sessID := loc.Query().Get("sess_id")
	if sessID == "" {
		return "", &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepGetSessID,
			Message: "sess_id missing from Location",
		}
	}
	return sessID, nil
}

func (c *Client) doGetRequestToken(ctx context.Context, hc *http.Client, headers http.Header, creds Credentials, sessID string) (string, error) {
	u := fmt.Sprintf("%s?v=3&api_key=%s&sess_id=%s",
		urlConnectFinish, url.QueryEscape(creds.APIKey), url.QueryEscape(sessID))
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	applyHeaders(req, headers)

	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return "", &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepGetRequestToken,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return "", &brokersession.Error{
			Broker:     brokersession.BrokerZerodha,
			Step:       StepGetRequestToken,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("expected 302, got %d", resp.StatusCode),
		}
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepGetRequestToken,
			Message: "parse location: " + err.Error(),
			Err:     err,
		}
	}
	rt := loc.Query().Get("request_token")
	if rt == "" {
		return "", &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepGetRequestToken,
			Message: "request_token missing from Location",
		}
	}
	return rt, nil
}

type sessionTokenResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserID        string   `json:"user_id"`
		UserName      string   `json:"user_name"`
		UserShortname string   `json:"user_shortname"`
		UserType      string   `json:"user_type"`
		Email         string   `json:"email"`
		AvatarURL     string   `json:"avatar_url"`
		Broker        string   `json:"broker"`
		Exchanges     []string `json:"exchanges"`
		Products      []string `json:"products"`
		OrderTypes    []string `json:"order_types"`
		APIKey        string   `json:"api_key"`
		AccessToken   string   `json:"access_token"`
		PublicToken   string   `json:"public_token"`
		RefreshToken  string   `json:"refresh_token"`
		Enctoken      string   `json:"enctoken"`
		Silo          string   `json:"silo"`
		LoginTime     string   `json:"login_time"`
		Meta          struct {
			DematConsent string `json:"demat_consent"`
		} `json:"meta"`
	} `json:"data"`
}

func (c *Client) doSessionToken(ctx context.Context, hc *http.Client, headers http.Header, creds Credentials, requestToken string) (*sessionTokenResponse, error) {
	checksum := sha256Hex(creds.APIKey + requestToken + creds.APISecret)

	form := url.Values{}
	form.Set("api_key", creds.APIKey)
	form.Set("request_token", requestToken)
	form.Set("checksum", checksum)

	req, _ := http.NewRequest(http.MethodPost, urlSessionToken, strings.NewReader(form.Encode()))
	applyHeaders(req, headers)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	body, err := doAndBody(ctx, hc, req, StepSessionToken)
	if err != nil {
		return nil, err
	}
	var out sessionTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    StepSessionToken,
			Message: "decode response: " + err.Error(),
		}
	}
	return &out, nil
}

// --- helpers ---

func applyHeaders(req *http.Request, h http.Header) {
	for k, v := range h {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// doAndBody sends the request and returns the raw response body. For
// non-2xx, returns a populated *brokersession.Error.
func doAndBody(ctx context.Context, hc *http.Client, req *http.Request, step brokersession.Step) ([]byte, error) {
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    step,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	body, err := internal.ReadBody(resp)
	if err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerZerodha,
			Step:       step,
			StatusCode: resp.StatusCode,
			Message:    "read body: " + err.Error(),
			Err:        err,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, kiteHTTPError(step, resp.StatusCode, body)
	}
	return body, nil
}

// doAndCookies sends the request, decodes JSON into out, and returns the
// response cookies. For non-2xx, returns a populated *brokersession.Error.
func doAndCookies(ctx context.Context, hc *http.Client, req *http.Request, out any, step brokersession.Step) ([]*http.Cookie, error) {
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, &brokersession.Error{
			Broker:  brokersession.BrokerZerodha,
			Step:    step,
			Message: err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	body, err := internal.ReadBody(resp)
	if err != nil {
		return nil, &brokersession.Error{
			Broker:     brokersession.BrokerZerodha,
			Step:       step,
			StatusCode: resp.StatusCode,
			Message:    "read body: " + err.Error(),
			Err:        err,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, kiteHTTPError(step, resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return nil, &brokersession.Error{
				Broker:     brokersession.BrokerZerodha,
				Step:       step,
				StatusCode: resp.StatusCode,
				Message:    "decode response: " + err.Error(),
			}
		}
	}
	return resp.Cookies(), nil
}

// wrapErr converts an error returned by internal.Do into a
// *brokersession.Error. Handles HTTPError (via kiteHTTPError) and
// transport-level errors.
func (c *Client) wrapErr(step brokersession.Step, err error) error {
	if he := internal.AsHTTPError(err); he != nil {
		return kiteHTTPError(step, he.StatusCode, he.Body)
	}
	return &brokersession.Error{
		Broker:  brokersession.BrokerZerodha,
		Step:    step,
		Message: err.Error(),
		Err:     err,
	}
}

// kiteHTTPError builds a *brokersession.Error from an upstream non-2xx
// response. Tries to parse Kite's standard error envelope
// (`{"status":"error","message":"...","error_type":"..."}`); falls back to
// a generic message if the body isn't decodable JSON.
func kiteHTTPError(step brokersession.Step, statusCode int, body []byte) *brokersession.Error {
	bsErr := &brokersession.Error{
		Broker:     brokersession.BrokerZerodha,
		Step:       step,
		StatusCode: statusCode,
	}
	var raw map[string]any
	if json.Unmarshal(body, &raw) == nil && raw != nil {
		bsErr.Raw = raw
		if msg, ok := raw["message"].(string); ok && msg != "" {
			bsErr.Message = msg
			return bsErr
		}
	}
	bsErr.Message = fmt.Sprintf("%s (unparseable body, %d bytes)", http.StatusText(statusCode), len(body))
	return bsErr
}
