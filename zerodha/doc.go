// Package zerodha provides headless session generation for Zerodha (Kite).
//
// Two flows: OMS-only (no APIKey/APISecret) produces enctoken-based sessions
// for OMS endpoints; the API flow adds the OAuth handshake to produce
// KiteConnect /v3 access tokens alongside the OMS enctoken.
//
// Set up External 2FA TOTP in the Kite Web account-security screen and
// supply the base32 secret as Credentials.TOTPSecret.
package zerodha
