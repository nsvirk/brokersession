package upstox

import (
	"net/url"
	"regexp"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// Credentials holds the inputs required for an Upstox session generation.
//
// Exactly one of TOTPSecret or TOTPValue must be set. TOTPSecret lets the
// library derive the 6-digit code itself; TOTPValue lets the caller supply
// a pre-computed code (useful when the 2FA seed is held by a hardware
// token or a separate secrets service that won't release the seed).
type Credentials struct {
	APIKey      string // UUID issued by account.upstox.com/developer/apps
	APISecret   string // OAuth client secret
	Mobile      string // 10 digits, no country code
	PIN         string // 6 digits
	TOTPSecret  string // base32, from Authenticator-app 2FA setup; alternative to TOTPValue
	TOTPValue   string // 6-digit code; alternative to TOTPSecret
	RedirectURL string // absolute URL registered with the developer-portal app
}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	mobileRE = regexp.MustCompile(`^[0-9]{10}$`)
	pinRE    = regexp.MustCompile(`^[0-9]{6}$`)
)

// Validate runs format checks before any network I/O. Failures return a
// *brokersession.Error with Step = StepValidate and Broker = BrokerUpstox.
// Validation runs in order; the first failure short-circuits.
func (c Credentials) Validate() error {
	if c.APIKey == "" {
		return c.validationErr("APIKey: required")
	}
	if !uuidRE.MatchString(c.APIKey) {
		return c.validationErr("APIKey: invalid UUID")
	}
	if c.APISecret == "" {
		return c.validationErr("APISecret: required")
	}
	if c.Mobile == "" {
		return c.validationErr("Mobile: required")
	}
	if !mobileRE.MatchString(c.Mobile) {
		return c.validationErr("Mobile: must be 10 digits")
	}
	if c.PIN == "" {
		return c.validationErr("PIN: required")
	}
	if !pinRE.MatchString(c.PIN) {
		return c.validationErr("PIN: must be 6 digits")
	}
	switch {
	case c.TOTPSecret == "" && c.TOTPValue == "":
		return c.validationErr("TOTP: set exactly one of TOTPSecret / TOTPValue")
	case c.TOTPSecret != "" && c.TOTPValue != "":
		return c.validationErr("TOTP: set exactly one of TOTPSecret / TOTPValue")
	case c.TOTPSecret != "":
		if err := internal.ValidateBase32Secret(c.TOTPSecret); err != nil {
			return c.validationErr("TOTPSecret: invalid base32")
		}
	case c.TOTPValue != "":
		if err := internal.ValidateTOTPValue(c.TOTPValue); err != nil {
			return c.validationErr("TOTPValue: must be 6 digits")
		}
	}
	if c.RedirectURL == "" {
		return c.validationErr("RedirectURL: required")
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || !u.IsAbs() {
		return c.validationErr("RedirectURL: must be a valid absolute URL")
	}
	return nil
}

func (c Credentials) validationErr(msg string) *brokersession.Error {
	return &brokersession.Error{
		Broker:  brokersession.BrokerUpstox,
		Step:    brokersession.StepValidate,
		Message: msg,
	}
}
