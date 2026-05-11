package dhan

import (
	"regexp"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// Credentials holds the inputs required for a Dhan session generation.
//
// Exactly one of TOTPSecret or TOTPValue must be set. TOTPSecret lets the
// library derive the 6-digit code itself; TOTPValue lets the caller supply
// a pre-computed code (useful when the 2FA seed is held by a hardware
// token or a separate secrets service that won't release the seed).
type Credentials struct {
	ClientID   string `json:"client_id"`             // numeric Dhan client ID
	PIN        string `json:"pin"`                   // 6 digits
	TOTPSecret string `json:"totp_secret,omitempty"` // base32; alternative to TOTPValue
	TOTPValue  string `json:"totp_value,omitempty"`  // 6-digit code; alternative to TOTPSecret
}

var (
	dhanClientIDRE = regexp.MustCompile(`^[0-9]+$`)
	dhanPINRE      = regexp.MustCompile(`^[0-9]{6}$`)
)

// Validate runs format checks before any network I/O. Failures return a
// *brokersession.Error with Step = StepValidate and Broker = BrokerDhan.
// Validation runs in order; the first failure short-circuits.
func (c Credentials) Validate() error {
	if c.ClientID == "" {
		return c.validationErr("ClientID: required")
	}
	if !dhanClientIDRE.MatchString(c.ClientID) {
		return c.validationErr("ClientID: must be numeric")
	}
	if c.PIN == "" {
		return c.validationErr("PIN: required")
	}
	if !dhanPINRE.MatchString(c.PIN) {
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
	return nil
}

func (c Credentials) validationErr(msg string) *brokersession.Error {
	return &brokersession.Error{
		Broker:  brokersession.BrokerDhan,
		Step:    brokersession.StepValidate,
		Message: msg,
	}
}
