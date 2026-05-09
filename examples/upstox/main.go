// Example program: generate an Upstox session from a credentials file,
// write the session JSON to a sibling sessions/ directory, and verify.
//
// Behavior:
//
//  1. If a cached session file already exists, the program verifies it
//     against the broker first. If the broker accepts it, the program
//     prints `cache_session_valid: true` and exits without regenerating.
//  2. Otherwise it prints `cache_session_valid: false`, runs the full
//     headless flow, writes the new session, verifies it, and prints
//     `generated_session_valid: <true|false>`.
//
// Usage:
//
//	go run ./examples/upstox <user>
//
// <user> is the bare user name (no `.json` suffix). File layout, rooted
// at $BROKERSESSION_PATH (default ~/.brokersession):
//
//	<root>/upstox/users/<user>.json     // input credentials (snake_case)
//	<root>/upstox/sessions/<user>.json  // output session (created if missing)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/nsvirk/brokersession"
	"github.com/nsvirk/brokersession/upstox"
)

const broker = "upstox"

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		log.Fatalf("usage: go run ./examples/upstox <user>")
	}
	user := args[0]

	root := brokersessionPath()
	credsPath := filepath.Join(root, broker, "users", user+".json")
	sessionPath := filepath.Join(root, broker, "sessions", user+".json")

	printSeparator()
	defer printSeparator()
	printRow("broker", broker)
	printRow("user", user)
	printRow("session_file", sessionPath)

	client := upstox.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Try the cached session first.
	if cached, ok := tryLoadSession(sessionPath); ok {
		valid, _ := client.VerifySession(ctx, cached)
		printRow("cache_session_valid", valid)
		if valid {
			return
		}
	} else {
		printRow("cache_session_valid", false)
	}

	// 2. Cache miss / invalid: regenerate.
	var creds upstox.Credentials
	if err := readJSON(credsPath, &creds); err != nil {
		log.Fatalf("read creds %s: %v", credsPath, err)
	}

	session, err := client.GenerateSession(ctx, creds)
	if err != nil {
		var bsErr *brokersession.Error
		if errors.As(err, &bsErr) {
			log.Fatalf("generate session failed: broker=%s step=%s status=%d msg=%s",
				bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
		}
		log.Fatalf("generate session failed: %v", err)
	}

	if err := writeJSON(sessionPath, session); err != nil {
		log.Fatalf("write session %s: %v", sessionPath, err)
	}

	// Verify the freshly-generated session via GET /v2/user/profile with
	// `Authorization: Bearer <access_token>`. 200 ⇒ true, anything else ⇒ false.
	valid, err := client.VerifySession(ctx, session)
	if err != nil {
		var bsErr *brokersession.Error
		if errors.As(err, &bsErr) {
			log.Fatalf("verify session failed: broker=%s step=%s status=%d msg=%s",
				bsErr.Broker, bsErr.Step, bsErr.StatusCode, bsErr.Message)
		}
		log.Fatalf("verify session failed: %v", err)
	}
	printRow("generated_session_valid", valid)
}

// printRow prints a label/value pair with the value left-aligned in a
// fixed column so successive rows line up. Width is sized for the
// longest label this program emits ("generated_session_valid:").
func printRow(label string, value any) {
	fmt.Printf("%-25s%v\n", label+":", value)
}

// printSeparator prints a 50-dash horizontal rule used to bracket the
// program's output.
func printSeparator() {
	fmt.Println("--------------------------------------------------")
}

// tryLoadSession returns the cached session and true if path exists and
// decodes as an *upstox.Session. Missing or unparseable files return
// (nil, false) — the caller treats that as a cache miss.
func tryLoadSession(path string) (*upstox.Session, bool) {
	var s upstox.Session
	if err := readJSON(path, &s); err != nil {
		return nil, false
	}
	return &s, true
}

// brokersessionPath returns $BROKERSESSION_PATH if set, else ~/.brokersession.
func brokersessionPath() string {
	if v := os.Getenv("BROKERSESSION_PATH"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("resolve home dir: %v", err)
	}
	return filepath.Join(home, ".brokersession")
}

// readJSON loads a JSON file into v. Unknown keys are ignored (default
// encoding/json behavior); missing required fields surface later via
// Credentials.Validate inside GenerateSession.
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSON marshals v as indented JSON and writes it to path with 0600
// permissions, creating parent directories as needed.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
