package brokersession

import (
	"time"

	"github.com/nsvirk/brokersession/internal"
)

// GenerateTOTPValue derives the 6-digit RFC-6238 TOTP code for a base32
// secret at time t (SHA1, 30-second period — the defaults both Zerodha and
// Upstox 2FA expect). The returned value is suitable for the TOTPValue
// field on either broker's Credentials, so callers using that input path
// can compute codes from a stored secret without depending on a separate
// OTP library.
func GenerateTOTPValue(secret string, t time.Time) (string, error) {
	return internal.GenerateTOTP(secret, t)
}
