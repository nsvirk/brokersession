# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0] - 2026-05-02

### Added

- Initial release.
- Unified `*brokersession.Session` type with snake_case JSON keys and
  IST `time.Time` values.
- `zerodha` subpackage: OMS-only and OMS+API headless session flows.
- `upstox` subpackage: six-step headless OAuth flow.
- Typed `*brokersession.Error` with broker / step / status / message / raw fields
  and `errors.Is` / `errors.As` support via `Unwrap`.
- `GenerateSession`, `VerifySession`, `DeleteSession` on each broker `Client`.
- `WithHTTPClient` and `WithUserAgent` options on each `Client`.
- Test coverage across both broker subpackages and shared internals: HTTP
  client, TOTP, error envelopes, credential validation, JWT parsing, and
  end-to-end generate / verify / delete flows for Zerodha (OMS and OMS+API)
  and Upstox (six-step OAuth).
