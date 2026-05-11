package dhan

import (
	"context"
	"errors"
	"testing"

	"github.com/nsvirk/brokersession"
)

func validCreds() Credentials {
	return Credentials{
		ClientID:   "1000000001",
		PIN:        "123456",
		TOTPSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
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
		{"missing ClientID", func(c *Credentials) { c.ClientID = "" }, "ClientID: required"},
		{"non-numeric ClientID", func(c *Credentials) { c.ClientID = "100A000" }, "ClientID: must be numeric"},
		{"missing PIN", func(c *Credentials) { c.PIN = "" }, "PIN: required"},
		{"PIN not 6 digits", func(c *Credentials) { c.PIN = "1234" }, "PIN: must be 6 digits"},
		{"PIN contains non-digit", func(c *Credentials) { c.PIN = "12A456" }, "PIN: must be 6 digits"},
		{"neither TOTPSecret nor TOTPValue", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "" }, "TOTP: set exactly one of TOTPSecret / TOTPValue"},
		{"both TOTPSecret and TOTPValue", func(c *Credentials) { c.TOTPValue = "123456" }, "TOTP: set exactly one of TOTPSecret / TOTPValue"},
		{"invalid base32 TOTPSecret", func(c *Credentials) { c.TOTPSecret = "not!base32!" }, "TOTPSecret: invalid base32"},
		{"invalid TOTPValue (5 digits)", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "12345" }, "TOTPValue: must be 6 digits"},
		{"invalid TOTPValue (non-digit)", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "12345a" }, "TOTPValue: must be 6 digits"},
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
			if bsErr.Broker != brokersession.BrokerDhan {
				t.Errorf("Broker = %q, want %q", bsErr.Broker, brokersession.BrokerDhan)
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
	if got, want := string(StepGenerateToken), "generate_token"; got != want {
		t.Errorf("StepGenerateToken = %q, want %q", got, want)
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
	if bsErr.Broker != brokersession.BrokerDhan {
		t.Errorf("Broker = %q, want %q", bsErr.Broker, brokersession.BrokerDhan)
	}
	if bsErr.Step != brokersession.StepValidate {
		t.Errorf("Step = %q, want %q", bsErr.Step, brokersession.StepValidate)
	}
	if bsErr.Message != "session: required" {
		t.Errorf("Message = %q, want %q", bsErr.Message, "session: required")
	}
}
