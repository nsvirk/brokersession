package internal

import (
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTP returns the 6-digit RFC 6238 TOTP code for the given base32
// secret at time t. SHA1, 30-second period — the defaults that both
// Zerodha and Upstox 2FA expect.
func GenerateTOTP(secret string, t time.Time) (string, error) {
	code, err := totp.GenerateCode(secret, t)
	if err != nil {
		return "", fmt.Errorf("internal: generate totp: %w", err)
	}
	return code, nil
}

// ValidateTOTPValue returns nil if value is exactly 6 ASCII digits, the
// shape both Zerodha and Upstox 2FA endpoints expect. Returns an error for
// any other length or any non-digit character.
func ValidateTOTPValue(value string) error {
	if len(value) != 6 {
		return fmt.Errorf("must be 6 digits")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return fmt.Errorf("must be 6 digits")
		}
	}
	return nil
}

// ValidateBase32Secret returns nil if secret is a non-empty,
// case-insensitive base32-encoded string (with optional padding). Returns
// an error otherwise. The TOTP libraries accept base32 with relaxed
// padding, so we mirror that.
func ValidateBase32Secret(secret string) error {
	if secret == "" {
		return fmt.Errorf("empty")
	}
	// Upper-case, trim whitespace, strip any existing padding, then re-pad
	// to the next multiple of 8. Mirrors what pquerna/otp accepts.
	s := strings.TrimRight(strings.ToUpper(strings.TrimSpace(secret)), "=")
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	if _, err := base32.StdEncoding.DecodeString(s); err != nil {
		return fmt.Errorf("invalid base32: %w", err)
	}
	return nil
}
