package brokersession

import (
	"testing"
	"time"
)

// TestGenerateTOTPValue_Reexport asserts that the public GenerateTOTPValue
// wrapper returns the same code as the underlying internal helper for an
// RFC 6238 vector. Rationale: the wrapper is a thin re-export, so a single
// well-known vector is sufficient — exhaustive cases live in
// internal/totp_test.go.
func TestGenerateTOTPValue_Reexport(t *testing.T) {
	t.Parallel()
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	got, err := GenerateTOTPValue(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("GenerateTOTPValue error: %v", err)
	}
	if got != "287082" {
		t.Errorf("GenerateTOTPValue = %q, want 287082", got)
	}
}
