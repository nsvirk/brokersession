// Package brokersession provides a session-handling surface for Indian
// stock brokers. Zerodha and Upstox each live in their own subpackage and
// own their own Session and Credentials types; this top-level package
// holds only the cross-broker BrokerName / Step / Error types and the
// GenerateTOTPValue helper.
//
// Each broker's Session struct mirrors that broker's session/token-API
// JSON faithfully, with snake_case JSON tags suitable for storage. All
// time.Time values are IST (Asia/Kolkata).
//
// Quick start:
//
//	client := zerodha.New()
//	session, err := client.GenerateSession(ctx, zerodha.Credentials{...})
//	// session is *zerodha.Session
//
// See the per-broker subpackages for credential shapes, session shapes,
// and flows:
//
//	github.com/nsvirk/brokersession/zerodha
//	github.com/nsvirk/brokersession/upstox
//	github.com/nsvirk/brokersession/dhan
package brokersession
