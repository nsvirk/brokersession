// Example program: generate an Upstox session from credentials supplied
// via env vars, print the result, and (optionally) delete it.
//
// Required env: UPSTOX_API_KEY, UPSTOX_API_SECRET, UPSTOX_MOBILE,
// UPSTOX_PIN, UPSTOX_TOTP_SECRET, UPSTOX_REDIRECT_URL. The TOTP secret
// is fed through brokersession.GenerateTOTPValue and the resulting
// 6-digit code is passed as Credentials.TOTPValue.
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
	// Derive the 6-digit code from the stored TOTP secret using the public
	// helper. Using TOTPValue (instead of TOTPSecret) is the right path when
	// the seed lives in a hardware token, password manager, or external
	// secrets service that produces codes but won't release the seed. Here
	// we read the secret from env purely to keep the example self-contained.
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
			log.Fatalf("generate session failed: broker=%s step=%s status=%d msg=%s",
				bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
		}
		log.Fatalf("generate session failed: %v", err)
	}

	printJSON("session", session)

	// Verify the session by hitting the broker's profile endpoint.
	// GET https://api.upstox.com/v2/user/profile with
	//   `Authorization: Bearer <access_token>`.
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
	// Calls DELETE https://api.upstox.com/v2/logout. Idempotent.
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
