# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1.0] - 2026-05-09

Breaking change: `Session` is now per-broker, mirroring how `Credentials`
already worked. The unified top-level `*brokersession.Session` type is
removed; each broker subpackage owns its own `Session` struct shaped to
that broker's session-API JSON.

### Changed (BREAKING)

- Removed the top-level `brokersession.Session` type. Each broker
  subpackage now owns its own `Session`:
  - `zerodha.Session` — mirrors the Kite session/token-exchange response.
  - `upstox.Session` — mirrors the Upstox `/v2/login/authorization/token`
    response.
- `Client.GenerateSession` returns `*Session` from the owning subpackage
  (`*zerodha.Session` or `*upstox.Session`). `VerifySession` and
  `DeleteSession` accept the same per-broker `*Session`.

### Removed

- `Session.Raw map[string]any` is gone — all API fields are first-class
  typed fields on each broker's `Session`. Synthetic envelope construction
  in the OMS-only Zerodha flow is removed (the previously-stuffed
  `kf_session` cookie value, which was never part of the official Kite
  API JSON, is no longer exposed).

### Added

- Zerodha session fields: `UserShortname`, `AvatarURL`, `PublicToken`,
  `RefreshToken`, `Silo`, `LoginTime` (raw API string), `Meta.DematConsent`.
- Upstox session fields: `POA`, `IsActive`.
- snake_case `json` tags on `zerodha.Credentials` and `upstox.Credentials`
  so credentials can be loaded from / saved to JSON files with the same
  shape as the session output. Field names and Go-level usage are
  unchanged; only `encoding/json` behavior is affected.
- File-driven `examples/zerodha` and `examples/upstox` programs that
  read credentials from `$BROKERSESSION_PATH/<broker>/users/<user>.json`
  and write the session to `$BROKERSESSION_PATH/<broker>/sessions/<user>.json`
  (`$BROKERSESSION_PATH` defaults to `~/.brokersession`).

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
