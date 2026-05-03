// Package upstox provides headless session generation for Upstox.
//
// Implements the six-step OAuth-without-browser handshake. Set up
// Authenticator 2FA in the Upstox account first; supply the base32 secret
// as Credentials.TOTPSecret. The registered developer-portal app's redirect
// URI must match Credentials.RedirectURL (required, no default).
package upstox
