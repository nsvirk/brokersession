// Package dhan provides headless session generation for Dhan.
//
// Single-step flow: POST https://auth.dhan.co/app/generateAccessToken with
// dhanClientId + pin + totp as query parameters. The response carries a
// JWT access token valid for 24 hours.
//
// Set up TOTP-based 2FA in the Dhan account first; supply the base32
// secret as Credentials.TOTPSecret (or pass a pre-computed 6-digit value
// as Credentials.TOTPValue).
//
// Dhan does not expose a token-revoke endpoint, so DeleteSession is a
// no-op for non-nil sessions. The token expires at the broker 24h after
// generation.
package dhan
