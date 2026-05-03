// Example program: generate a Zerodha session from credentials supplied
// via env vars, print the result, and (optionally) delete it.
//
// Usage: go run ./examples/zerodha [--flow api|oms]
//
// --flow api (default) runs the full OMS + API flow and requires
// ZERODHA_API_KEY and ZERODHA_API_SECRET. --flow oms runs only the OMS
// leg and ignores the API_KEY / API_SECRET env vars.
//
// Required env: ZERODHA_USER_ID, ZERODHA_PASSWORD, ZERODHA_TOTP_SECRET
// (the secret is fed through brokersession.GenerateTOTPValue and the
// resulting 6-digit code is passed as Credentials.TOTPValue).
// Required for --flow api: ZERODHA_API_KEY, ZERODHA_API_SECRET.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/zerodha"
)

func main() {
	flow := flag.String("flow", "api", `flow mode: "api" (OMS + API leg) or "oms" (OMS only)`)
	flag.Parse()
	if *flow != "api" && *flow != "oms" {
		log.Fatalf("invalid --flow %q: want \"api\" or \"oms\"", *flow)
	}

	// Derive the 6-digit code from the stored TOTP secret using the public
	// helper. Using TOTPValue (instead of TOTPSecret) is the right path when
	// the seed lives in a hardware token, password manager, or external
	// secrets service that produces codes but won't release the seed. Here
	// we read the secret from env purely to keep the example self-contained.
	totpValue, err := brokersession.GenerateTOTPValue(os.Getenv("ZERODHA_TOTP_SECRET"), time.Now())
	if err != nil {
		log.Fatalf("generate totp value failed: %v", err)
	}

	creds := zerodha.Credentials{
		UserID:    os.Getenv("ZERODHA_USER_ID"),
		Password:  os.Getenv("ZERODHA_PASSWORD"),
		TOTPValue: totpValue,
	}
	if *flow == "api" {
		creds.APIKey = os.Getenv("ZERODHA_API_KEY")
		creds.APISecret = os.Getenv("ZERODHA_API_SECRET")
		if creds.APIKey == "" || creds.APISecret == "" {
			log.Fatal("--flow api requires ZERODHA_API_KEY and ZERODHA_API_SECRET")
		}
	}

	client := zerodha.New()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err := client.GenerateSession(ctx, creds)
	if err != nil {
		var bsErr *brokersession.Error
		if errors.As(err, &bsErr) {
			log.Fatalf("generate session failed: broker=%s step=%s status=%d msg=%s",
				bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
		}
		log.Fatalf("generate session failed: %v", err)
	}

	printJSON("session", session)

	// Verify the session by hitting the broker's profile endpoint.
	// API mode: GET https://api.kite.trade/user/profile with
	//   `Authorization: token <api_key>:<access_token>`.
	// OMS-only mode: GET https://kite.zerodha.com/oms/user/profile with
	//   `Authorization: enctoken <enctoken>`.
	// 200 ⇒ true, any other status ⇒ false.
	ok, err := client.VerifySession(ctx, session)
	if err != nil {
		var bsErr *brokersession.Error
		if errors.As(err, &bsErr) {
			log.Fatalf("verify session failed: broker=%s step=%s status=%d msg=%s",
				bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
		}
		log.Fatalf("verify session failed: %v", err)
	}
	fmt.Printf("session_valid: %v\n", ok)

	// Delete the session when done.
	// For OMS-only sessions (no APIKey/APISecret) DeleteSession is a no-op
	// because Kite does not expose enctoken revocation. For API sessions it
	// calls DELETE /session/token.
	//
	// if err := client.DeleteSession(ctx, session); err != nil {
	// 	log.Fatalf("delete session failed: %v", err)
	// }
	// fmt.Println("session deleted")
}

// printJSON marshals v as indented JSON and writes it to stdout.
func printJSON(label string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("marshal %s: %v", label, err)
	}
	fmt.Printf("%s:\n%s\n", label, b)
}
