package upstox

import (
	"context"
	"errors"
	"testing"

	"github.com/nsvirk/brokersession"
)

func validCreds() Credentials {
	return Credentials{
		APIKey:      "abcdef01-2345-6789-abcd-ef0123456789",
		APISecret:   "secretvalue",
		Mobile:      "9560777000",
		PIN:         "123456",
		TOTPSecret:  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		RedirectURL: "https://example.com/callback",
	}
}

func TestValidate_OK(t *testing.T) {
	t.Parallel()
	if err := validCreds().Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestValidate_OK_TOTPValue(t *testing.T) {
	t.Parallel()
	c := validCreds()
	c.TOTPSecret = ""
	c.TOTPValue = "123456"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() with TOTPValue = %v, want nil", err)
	}
}

func TestValidate_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Credentials)
		wantMsg string
	}{
		{"missing APIKey", func(c *Credentials) { c.APIKey = "" }, "APIKey: required"},
		{"non-UUID APIKey", func(c *Credentials) { c.APIKey = "not-a-uuid" }, "APIKey: invalid UUID"},
		{"missing APISecret", func(c *Credentials) { c.APISecret = "" }, "APISecret: required"},
		{"missing Mobile", func(c *Credentials) { c.Mobile = "" }, "Mobile: required"},
		{"Mobile not 10 digits", func(c *Credentials) { c.Mobile = "956077" }, "Mobile: must be 10 digits"},
		{"Mobile contains non-digit", func(c *Credentials) { c.Mobile = "956077A000" }, "Mobile: must be 10 digits"},
		{"missing PIN", func(c *Credentials) { c.PIN = "" }, "PIN: required"},
		{"PIN not 6 digits", func(c *Credentials) { c.PIN = "1234" }, "PIN: must be 6 digits"},
		{"PIN contains non-digit", func(c *Credentials) { c.PIN = "12A456" }, "PIN: must be 6 digits"},
		{"neither TOTPSecret nor TOTPValue", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "" }, "TOTP: set exactly one of TOTPSecret / TOTPValue"},
		{"both TOTPSecret and TOTPValue", func(c *Credentials) { c.TOTPValue = "123456" }, "TOTP: set exactly one of TOTPSecret / TOTPValue"},
		{"invalid base32 TOTPSecret", func(c *Credentials) { c.TOTPSecret = "not!base32!" }, "TOTPSecret: invalid base32"},
		{"invalid TOTPValue (5 digits)", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "12345" }, "TOTPValue: must be 6 digits"},
		{"invalid TOTPValue (non-digit)", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "12345a" }, "TOTPValue: must be 6 digits"},
		{"missing RedirectURL", func(c *Credentials) { c.RedirectURL = "" }, "RedirectURL: required"},
		{"invalid RedirectURL", func(c *Credentials) { c.RedirectURL = "not-a-url" }, "RedirectURL: must be a valid absolute URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validCreds()
			tt.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error %q", tt.wantMsg)
			}
			var bsErr *brokersession.Error
			if !errors.As(err, &bsErr) {
				t.Fatalf("err is not *brokersession.Error: %v", err)
			}
			if bsErr.Broker != brokersession.BrokerUpstox {
				t.Errorf("Broker = %q, want %q", bsErr.Broker, brokersession.BrokerUpstox)
			}
			if bsErr.Step != brokersession.StepValidate {
				t.Errorf("Step = %q, want %q", bsErr.Step, brokersession.StepValidate)
			}
			if bsErr.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", bsErr.Message, tt.wantMsg)
			}
		})
	}
}

func TestStepConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		got, want string
	}{
		{string(StepDialog), "dialog"},
		{string(StepOTPGenerate), "otp_generate"},
		{string(StepOTPVerify), "otp_verify"},
		{string(StepPINSubmit), "pin_submit"},
		{string(StepOAuthApprove), "oauth_approve"},
		{string(StepTokenExchange), "token_exchange"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("Step constant = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestDeleteSession_NilSessionReturnsValidationError(t *testing.T) {
	t.Parallel()
	c := New()
	err := c.DeleteSession(context.Background(), nil)
	var bsErr *brokersession.Error
	if !errors.As(err, &bsErr) {
		t.Fatalf("err is not *brokersession.Error: %v", err)
	}
	if bsErr.Broker != brokersession.BrokerUpstox {
		t.Errorf("Broker = %q, want %q", bsErr.Broker, brokersession.BrokerUpstox)
	}
	if bsErr.Step != brokersession.StepValidate {
		t.Errorf("Step = %q, want %q", bsErr.Step, brokersession.StepValidate)
	}
	if bsErr.Message != "session: required" {
		t.Errorf("Message = %q, want %q", bsErr.Message, "session: required")
	}
}
