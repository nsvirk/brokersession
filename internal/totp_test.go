package internal

import (
	"testing"
	"time"
)

// TestGenerateTOTP_RFC6238 uses the published RFC 6238 SHA-1 test vectors.
// The RFC table maps Unix-second timestamps to 8-digit codes for a known
// 20-byte ASCII secret "12345678901234567890". pquerna/otp's GenerateCode
// returns the rightmost 6 digits (default Digits = 6), so we compare
// against the trailing 6 digits of each RFC value.
func TestGenerateTOTP_RFC6238(t *testing.T) {
	t.Parallel()
	// "12345678901234567890" base32-encoded.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	tests := []struct {
		unixSec int64
		want    string // last 6 digits of the RFC's 8-digit value
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tt := range tests {
		got, err := GenerateTOTP(secret, time.Unix(tt.unixSec, 0))
		if err != nil {
			t.Errorf("unix=%d: GenerateTOTP error: %v", tt.unixSec, err)
			continue
		}
		if got != tt.want {
			t.Errorf("unix=%d: GenerateTOTP = %q, want %q", tt.unixSec, got, tt.want)
		}
	}
}

func TestGenerateTOTP_InvalidSecret(t *testing.T) {
	t.Parallel()
	if _, err := GenerateTOTP("not!base32", time.Now()); err == nil {
		t.Errorf("GenerateTOTP with invalid secret returned no error")
	}
}

func TestValidateTOTPValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "123456", false},
		{"valid all zeros", "000000", false},
		{"empty", "", true},
		{"5 digits", "12345", true},
		{"7 digits", "1234567", true},
		{"contains letter", "12345a", true},
		{"contains space (leading)", " 12345", true},
		{"contains space (trailing)", "12345 ", true},
		{"contains punctuation", "12-456", true},
	}
	for _, tt := range tests {
		err := ValidateTOTPValue(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("%s: ValidateTOTPValue(%q) = nil, want error", tt.name, tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("%s: ValidateTOTPValue(%q) = %v, want nil", tt.name, tt.input, err)
		}
	}
}

func TestValidateBase32Secret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"valid uppercase no padding", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", false},
		{"valid lowercase", "gezdgnbvgy3tqojq", false},
		{"valid with padding", "MFRGGZDF====", false},
		{"valid odd length (auto-padded)", "JBSWY3DPEHPK3PXP", false},
		{"contains invalid char (1)", "GEZDGNBVGY3TQOJ1", true},
		{"contains invalid char (0)", "GEZDGNBVGY3TQOJ0", true},
		{"contains punctuation", "GEZDGNBV!Y3TQOJQ", true},
	}
	for _, tt := range tests {
		err := ValidateBase32Secret(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("%s: ValidateBase32Secret(%q) = nil, want error", tt.name, tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("%s: ValidateBase32Secret(%q) = %v, want nil", tt.name, tt.input, err)
		}
		if tt.wantErr && err != nil && err.Error() == "" {
			t.Errorf("%s: ValidateBase32Secret(%q) returned empty error message", tt.name, tt.input)
		}
	}
}
