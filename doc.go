// Package brokersession provides a session-handling surface for Indian
// stock brokers. v1 supports Zerodha and Upstox via per-broker subpackages;
// sessions are returned as a unified *Session type with JSON-serializable,
// lowercase-snake-case keys for storage.
//
// All time.Time values are IST (Asia/Kolkata).
//
// Quick start:
//
//	client := zerodha.New()
//	session, err := client.GenerateSession(ctx, zerodha.Credentials{...})
//
// See the per-broker subpackages for credential shapes and flows:
//
//	github.com/nsvirk/brokersession/zerodha
//	github.com/nsvirk/brokersession/upstox
package brokersession
