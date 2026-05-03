package zerodha

import (
	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/internal"
)

// Credentials holds the inputs required for a Zerodha session generation.
//
// APIKey and APISecret are optional — when both empty, the OMS-only flow
// runs. When both set, the OAuth API flow runs after the OMS leg. Setting
// only one is a validation error.
//
// Exactly one of TOTPSecret or TOTPValue must be set. TOTPSecret lets the
// library derive the 6-digit code itself; TOTPValue lets the caller supply
// a pre-computed code (useful when the 2FA seed is held by a hardware
// token or a separate secrets service that won't release the seed).
type Credentials struct {
	UserID     string
	Password   string
	TOTPSecret string // base32; alternative to TOTPValue
	TOTPValue  string // 6-digit code; alternative to TOTPSecret
	APIKey     string // optional → empty triggers OMS-only flow
	APISecret  string // optional
}

// Validate runs format checks before any network I/O. Failures return a
// *brokersession.Error with Step = StepValidate and Broker = BrokerZerodha.
// Validation runs in order; the first failure short-circuits.
func (c Credentials) Validate() error {
	if c.UserID == "" {
		return c.validationErr("UserID: required")
	}
	if c.Password == "" {
		return c.validationErr("Password: required")
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
	// Cross-field: APIKey and APISecret must be both set or both empty.
	if (c.APIKey == "") != (c.APISecret == "") {
		return c.validationErr("APIKey: must be set when APISecret is set (and vice versa)")
	}
	return nil
}

func (c Credentials) validationErr(msg string) *brokersession.Error {
	return &brokersession.Error{
		Broker:  brokersession.BrokerZerodha,
		Step:    brokersession.StepValidate,
		Message: msg,
	}
}
