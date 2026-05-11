# brokersession

> 🔐 A Go library providing fully-automated, headless session-handling
> for Indian stock brokers, with per-broker `Session` and `Credentials`
> types shaped to each broker's session-API JSON.

Sessions are generated headlessly — no browser, no user interaction during
the flow — using the credentials each broker requires (TOTP secret, PIN,
etc.).

## 🏦 Brokers supported

| Broker  | Package                                   | Flow(s)                   |
| ------- | ----------------------------------------- | ------------------------- |
| Zerodha | `github.com/nsvirk/brokersession/zerodha` | OMS-only, OMS + API       |
| Upstox  | `github.com/nsvirk/brokersession/upstox`  | Six-step OAuth (headless) |
| Dhan    | `github.com/nsvirk/brokersession/dhan`    | TOTP + PIN (single POST)  |

## ✨ Features

- 🤖 Fully headless login — no browser, no manual interaction.
- 🧩 Per-broker `Session` and `Credentials` types — each shaped to its
  broker's session-API JSON, with snake_case tags for storage.
- 🎯 Strictly-typed `Credentials` per broker, validated up front.
- 🛑 Typed `*brokersession.Error` with broker / step / status / message / raw.
- 🪶 Tiny surface: `GenerateSession`, `VerifySession`, `DeleteSession`.

## 📦 Install

```sh
go get github.com/nsvirk/brokersession
```

Requires Go 1.22+.

## 🚀 Usage

Import the broker subpackage you need (`zerodha` or `upstox`). Each
exposes the same shape: a strictly-typed `Credentials` struct and a
`Client` with three lifecycle methods. The top-level `brokersession`
package adds a broker-agnostic TOTP helper.

| Symbol                      | Package                | Purpose                                                                                                                                                                                |
| --------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GenerateTOTPValue`         | `brokersession` (root) | Derive a 6-digit RFC-6238 TOTP code from a base32 secret, suitable for `Credentials.TOTPValue`. Saves pulling in a separate OTP library. Signature: `(secret, t) (string, error)`.     |
| `New`                       | `zerodha` / `upstox`   | Construct a broker client. Options: `WithHTTPClient(*http.Client)`, `WithUserAgent(string)`. Zero-value usage (`zerodha.New()` / `upstox.New()`) is supported.                         |
| `(Credentials).Validate`    | `zerodha` / `upstox`   | Format-check credentials before any network call. Run automatically by `GenerateSession`; exposed so callers can pre-flight a form without paying a round-trip.                        |
| `(*Client).GenerateSession` | `zerodha` / `upstox`   | Run the headless login flow end-to-end. Returns `(*Session, error)` from the owning subpackage (`*zerodha.Session` or `*upstox.Session`).                                              |
| `(*Client).VerifySession`   | `zerodha` / `upstox`   | Hit the broker profile endpoint with the session's auth header. `true` on 200, `false` otherwise. Errors only for `nil` session or transport-level failures.                           |
| `(*Client).DeleteSession`   | `zerodha` / `upstox`   | Invalidate the session at the broker. Idempotent (401/404 = success). Zerodha OMS-only sessions are a no-op — Kite does not expose `enctoken` revocation.                              |

All `*Client` methods take `ctx context.Context` as the first argument.

### 📥 Credentials shape

Both `Credentials` types carry snake_case `json` tags, so credentials can
be loaded from / saved to JSON files with the same shape as the session
output. Exactly one of `totp_secret` / `totp_value` must be set on each
broker. Unknown keys are ignored by the standard `encoding/json` decoder.

**Zerodha** (`api_key`/`api_secret` empty → OMS-only flow; both set → OMS + API):

```jsonc
{
  "user_id":     "AB1234",                          // required
  "password":    "********",                        // required
  "totp_secret": "JBSWY3DPEHPK3PXP",                // base32; alternative to totp_value
  "totp_value":  "",                                // 6-digit code; alternative to totp_secret
  "api_key":     "",                                // optional; empty → OMS-only flow
  "api_secret":  ""                                 // optional; required when api_key is set
}
```

**Upstox** (all fields required, plus exactly one TOTP field):

```jsonc
{
  "api_key":      "00000000-0000-0000-0000-000000000000", // UUID from developer portal
  "api_secret":   "********",                             // OAuth client secret
  "mobile":       "9876543210",                           // 10 digits, no country code
  "pin":          "123456",                               // 6 digits
  "totp_secret":  "JBSWY3DPEHPK3PXP",                     // base32; alternative to totp_value
  "totp_value":   "",                                     // 6-digit code; alternative to totp_secret
  "redirect_url": "https://example.com/callback"          // absolute URL registered with the app
}
```

**Dhan** (all fields required, plus exactly one TOTP field):

```jsonc
{
  "client_id":   "1000000001",                      // numeric Dhan client ID
  "pin":         "123456",                          // 6 digits
  "totp_secret": "JBSWY3DPEHPK3PXP",                // base32; alternative to totp_value
  "totp_value":  ""                                 // 6-digit code; alternative to totp_secret
}
```

### 📤 Session shape

The result of `GenerateSession` is a per-broker `*Session` whose fields
mirror that broker's session-API JSON. Both shapes use lowercase-snake-case
JSON keys; `issued_at` (and Upstox's `expires_at`) are IST `time.Time`
values. Zerodha's session API does not return an expiry, so `*zerodha.Session`
has no `expires_at` field. **The wire format below is part of the public
contract.**

**Zerodha** (`*zerodha.Session`) — OMS-only flow leaves `api_key`,
`access_token`, `refresh_token`, `silo`, `meta` zero-valued; OMS+API flow
populates the full shape.

```jsonc
{
  "broker":         "zerodha",
  "user_id":        "AB1234",
  "user_name":      "Alice Bose",
  "user_shortname": "Alice",
  "user_type":      "individual",
  "email":          "alice@example.com",
  "avatar_url":     "https://kite.zerodha.com/...",
  "api_key":        "abcd1234",                                    // OMS+API flow only
  "access_token":   "...",                                         // OMS+API flow only
  "public_token":   "...",
  "refresh_token":  "",                                            // present when broker returns it
  "enctoken":       "...",                                         // OMS-leg cookie value
  "silo":           "",                                            // OMS+API flow only
  "exchanges":      ["NSE", "BSE", "NFO", "MCX"],
  "products":       ["CNC", "MIS", "NRML"],
  "order_types":    ["MARKET", "LIMIT", "SL", "SL-M"],
  "login_time":     "2026-05-03 09:30:00",                         // raw API string
  "meta":           { "demat_consent": "physical" },               // OMS+API flow only
  "issued_at":      "2026-05-03T09:30:00+05:30"                    // derived (IST)
}
```

**Upstox** (`*upstox.Session`):

```jsonc
{
  "broker":         "upstox",
  "user_id":        "AB1234",
  "user_name":      "Alice Bose",
  "user_type":      "individual",
  "email":          "alice@example.com",
  "exchanges":      ["NSE", "NFO", "BSE", "CDS", "BFO", "BCD"],
  "products":       ["D", "CO", "I"],
  "order_types":    ["MARKET", "LIMIT", "SL", "SL-M"],
  "poa":            false,
  "is_active":      true,
  "api_key":        "00000000-0000-0000-0000-000000000000",
  "access_token":   "eyJhbGciOi...",
  "extended_token": "...",
  "issued_at":      "2026-05-03T09:30:00+05:30",                   // decoded from JWT iat
  "expires_at":     "2026-05-04T06:00:00+05:30"                    // decoded from JWT exp
}
```

**Dhan** (`*dhan.Session`):

```jsonc
{
  "broker":                  "dhan",
  "client_id":               "1000000001",
  "client_name":             "JOHN DOE",
  "client_ucc":              "ABCD12345E",
  "given_power_of_attorney": false,
  "access_token":            "eyJhbGciOi...",
  "expiry_time":             "2026-05-12 21:46:16",                 // normalized from API "2026-05-12T21:46:16.999"
  "issued_at":               "2026-05-11T19:51:00+05:30",           // time.Now() in IST (Dhan API does not return one)
  "expires_at":              "2026-05-12T21:46:16+05:30"            // expiry_time parsed in IST
}
```

All optional fields are dropped via `omitempty` when the broker doesn't
populate them.

### 🔐 TOTP — secret or pre-computed value

Both broker `Credentials` structs accept the 2FA TOTP in one of two
mutually-exclusive ways. Set **exactly one** of:

- `TOTPSecret` — the base32 seed from the broker's authenticator setup; the
  library derives the 6-digit code at flow time. Easiest and matches what
  most Authenticator-app users store.
- `TOTPValue` — a pre-computed 6-digit code. Use this when the seed lives
  in a hardware token, password manager, or external secrets service that
  produces codes but won't release the seed, or when a UI front-end has
  already prompted the user for the live code.

Setting both, or neither, fails `Validate()` before any network call.
Callers that want to derive a code themselves can use the public
`brokersession.GenerateTOTPValue(secret, time.Now())` helper rather than pulling
in a separate OTP library.

### 📈 Zerodha

```go
package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/nsvirk/brokersession"
    "github.com/nsvirk/brokersession/zerodha"
)

func main() {
    // Derive the 6-digit code from the stored TOTP secret using the
    // public helper, then feed it as TOTPValue. Reading the secret from
    // env keeps the example self-contained; in production the secret
    // typically lives in a hardware token or secrets service.
    totpValue, err := brokersession.GenerateTOTPValue(os.Getenv("ZERODHA_TOTP_SECRET"), time.Now())
    if err != nil {
        log.Fatalf("generate totp value failed: %v", err)
    }

    creds := zerodha.Credentials{
        UserID:    os.Getenv("ZERODHA_USER_ID"),
        Password:  os.Getenv("ZERODHA_PASSWORD"),
        TOTPValue: totpValue,
        // For OMS+API flow, also supply:
        APIKey:    os.Getenv("ZERODHA_API_KEY"),
        APISecret: os.Getenv("ZERODHA_API_SECRET"),
    }

    client := zerodha.New()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    session, err := client.GenerateSession(ctx, creds)
    if err != nil {
        var bsErr *brokersession.Error
        if errors.As(err, &bsErr) {
            log.Fatalf("generate failed: broker=%s step=%s status=%d msg=%s",
                bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
        }
        log.Fatalf("generate failed: %v", err)
    }

    b, _ := json.MarshalIndent(session, "", "  ")
    fmt.Printf("session:\n%s\n", b)

    ok, err := client.VerifySession(ctx, session)
    if err != nil {
        log.Fatalf("verify failed: %v", err)
    }
    fmt.Printf("session_valid: %v\n", ok)

    // Optional: revoke the session at the broker.
    // For OMS-only sessions this is a no-op (Kite does not expose
    // enctoken revocation). For API sessions it calls
    // DELETE /session/token.
    // if err := client.DeleteSession(ctx, session); err != nil {
    //     log.Fatalf("delete failed: %v", err)
    // }
}
```

A runnable, file-driven version lives at
[examples/zerodha/main.go](./examples/zerodha/main.go). It reads
credentials from `$BROKERSESSION_PATH/zerodha/users/<user>.json` and
writes the resulting session to
`$BROKERSESSION_PATH/zerodha/sessions/<user>.json`
(`$BROKERSESSION_PATH` defaults to `~/.brokersession`):

```sh
go run ./examples/zerodha alice [--flow api|oms]
```

### 📊 Upstox

```go
package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/nsvirk/brokersession"
    "github.com/nsvirk/brokersession/upstox"
)

func main() {
    // Derive the 6-digit code from the stored TOTP secret using the
    // public helper, then feed it as TOTPValue. Reading the secret from
    // env keeps the example self-contained; in production the secret
    // typically lives in a hardware token or secrets service.
    totpValue, err := brokersession.GenerateTOTPValue(os.Getenv("UPSTOX_TOTP_SECRET"), time.Now())
    if err != nil {
        log.Fatalf("generate totp value failed: %v", err)
    }

    creds := upstox.Credentials{
        APIKey:      os.Getenv("UPSTOX_API_KEY"),
        APISecret:   os.Getenv("UPSTOX_API_SECRET"),
        Mobile:      os.Getenv("UPSTOX_MOBILE"),
        PIN:         os.Getenv("UPSTOX_PIN"),
        TOTPValue:   totpValue,
        RedirectURL: os.Getenv("UPSTOX_REDIRECT_URL"),
    }

    client := upstox.New()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    session, err := client.GenerateSession(ctx, creds)
    if err != nil {
        var bsErr *brokersession.Error
        if errors.As(err, &bsErr) {
            log.Fatalf("generate failed: broker=%s step=%s status=%d msg=%s",
                bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
        }
        log.Fatalf("generate failed: %v", err)
    }

    b, _ := json.MarshalIndent(session, "", "  ")
    fmt.Printf("session:\n%s\n", b)

    ok, err := client.VerifySession(ctx, session)
    if err != nil {
        log.Fatalf("verify failed: %v", err)
    }
    fmt.Printf("session_valid: %v\n", ok)

    // Optional: revoke the session at the broker.
    // Calls DELETE https://api.upstox.com/v2/logout. Idempotent.
    // if err := client.DeleteSession(ctx, session); err != nil {
    //     log.Fatalf("delete failed: %v", err)
    // }
}
```

A runnable, file-driven version lives at
[examples/upstox/main.go](./examples/upstox/main.go). It reads
credentials from `$BROKERSESSION_PATH/upstox/users/<user>.json` and
writes the resulting session to
`$BROKERSESSION_PATH/upstox/sessions/<user>.json`
(`$BROKERSESSION_PATH` defaults to `~/.brokersession`):

```sh
go run ./examples/upstox alice
```

### 💼 Dhan

```go
package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/nsvirk/brokersession"
    "github.com/nsvirk/brokersession/dhan"
)

func main() {
    // Derive the 6-digit code from the stored TOTP secret using the
    // public helper, then feed it as TOTPValue.
    totpValue, err := brokersession.GenerateTOTPValue(os.Getenv("DHAN_TOTP_SECRET"), time.Now())
    if err != nil {
        log.Fatalf("generate totp value failed: %v", err)
    }

    creds := dhan.Credentials{
        ClientID:  os.Getenv("DHAN_CLIENT_ID"),
        PIN:       os.Getenv("DHAN_PIN"),
        TOTPValue: totpValue,
    }

    client := dhan.New()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    session, err := client.GenerateSession(ctx, creds)
    if err != nil {
        var bsErr *brokersession.Error
        if errors.As(err, &bsErr) {
            log.Fatalf("generate failed: broker=%s step=%s status=%d msg=%s",
                bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
        }
        log.Fatalf("generate failed: %v", err)
    }

    b, _ := json.MarshalIndent(session, "", "  ")
    fmt.Printf("session:\n%s\n", b)

    ok, err := client.VerifySession(ctx, session)
    if err != nil {
        log.Fatalf("verify failed: %v", err)
    }
    fmt.Printf("session_valid: %v\n", ok)

    // DeleteSession is a no-op for Dhan (no logout endpoint).
}
```

A runnable, file-driven version lives at
[examples/dhan/main.go](./examples/dhan/main.go). It reads credentials
from `$BROKERSESSION_PATH/dhan/users/<user>.json` and writes the
resulting session to `$BROKERSESSION_PATH/dhan/sessions/<user>.json`
(`$BROKERSESSION_PATH` defaults to `~/.brokersession`):

```sh
go run ./examples/dhan alice
```

## 🧪 Tests

Run the local test suite (Tier 0 + Tier 1 — pure unit + HTTP plumbing,
no network):

```sh
go test ./...
```

End-to-end verification is by running the two `examples/` programs
against real broker credentials. Each program reads its credentials
from `$BROKERSESSION_PATH/<broker>/users/<user>.json` and writes the
generated session to `$BROKERSESSION_PATH/<broker>/sessions/<user>.json`
(`$BROKERSESSION_PATH` defaults to `~/.brokersession`). On a re-run the
program first verifies any cached session and skips regeneration if the
broker still accepts it.

## ⚙️ Operational notes

A few sharp edges to be aware of when running this in production:

- **`*Error.Raw` may contain credentials.** When a broker returns a non-2xx
  response, the verbatim JSON body is preserved on `*brokersession.Error.Raw`
  so callers can extract broker-specific fields (e.g. Upstox `errorCode`,
  Zerodha `error_type`). On rare token-exchange edge cases this body can echo
  back tokens or cookies. The default `Error()` stringer does **not** print
  `Raw`, so `log.Printf("%v", err)` is safe — but JSON-marshalling the error
  for structured logging will include it. Strip or redact `Raw` before
  shipping errors to logs.

- **Zerodha `DeleteSession` puts `access_token` in the URL.** The Kite
  `DELETE /session/token?api_key=…&access_token=…` endpoint requires the
  token as a query parameter. URL query strings are more likely than headers
  to surface in proxy logs, CDN access logs, and crash reports. Take care if
  you instrument this transport.

- **No automatic retry / backoff.** A transient 5xx, TCP reset, or rate-limit
  response surfaces as an error on the first attempt. The library performs
  no internal retries — wrapping `GenerateSession` / `VerifySession` /
  `DeleteSession` in your own retry policy (with jitter, and respecting any
  `Retry-After` header the broker sends) is the caller's responsibility.

## 🏷️ Status

v1.1 — public API stable. v1.1.0 introduced a breaking change: the
unified top-level `*brokersession.Session` was replaced by per-broker
`*zerodha.Session` and `*upstox.Session` types. See [CHANGELOG.md](./CHANGELOG.md).

## ⚠️ Disclaimer

> This library is provided strictly for **educational and research
> purposes**. They are **not** endorsed,
> recommended, or supported for production use, and their use is **in
> no way promoted** where it would conflict with the terms of service,
> developer agreement, or any other policy of the respective broker
> (Zerodha, Upstox, or any other). You are solely responsible for
> ensuring that your use complies with each broker's terms and
> applicable law.

## 📄 License

MIT — see [LICENSE](./LICENSE).
