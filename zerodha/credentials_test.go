package zerodha

import (
	"context"
	"errors"
	"testing"

	"github.com/nsvirk/brokersession"
)

func validCreds() Credentials {
	return Credentials{
		UserID:     "AB1234",
		Password:   "secret",
		TOTPSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	}
}

func TestValidate_OK_OMSOnly(t *testing.T) {
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

func TestValidate_OK_APIMode(t *testing.T) {
	t.Parallel()
	c := validCreds()
	c.APIKey = "abc123"
	c.APISecret = "secretkey"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() with API creds = %v, want nil", err)
	}
}

func TestValidate_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Credentials)
		wantMsg string
	}{
		{"missing UserID", func(c *Credentials) { c.UserID = "" }, "UserID: required"},
		{"missing Password", func(c *Credentials) { c.Password = "" }, "Password: required"},
		{"neither TOTPSecret nor TOTPValue", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "" }, "TOTP: set exactly one of TOTPSecret / TOTPValue"},
		{"both TOTPSecret and TOTPValue", func(c *Credentials) { c.TOTPValue = "123456" }, "TOTP: set exactly one of TOTPSecret / TOTPValue"},
		{"invalid base32 TOTPSecret", func(c *Credentials) { c.TOTPSecret = "not!base32!" }, "TOTPSecret: invalid base32"},
		{"invalid TOTPValue (5 digits)", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "12345" }, "TOTPValue: must be 6 digits"},
		{"invalid TOTPValue (non-digit)", func(c *Credentials) { c.TOTPSecret = ""; c.TOTPValue = "12345a" }, "TOTPValue: must be 6 digits"},
		{"only APIKey set", func(c *Credentials) { c.APIKey = "abc" }, "APIKey: must be set when APISecret is set (and vice versa)"},
		{"only APISecret set", func(c *Credentials) { c.APISecret = "abc" }, "APIKey: must be set when APISecret is set (and vice versa)"},
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
			if bsErr.Broker != brokersession.BrokerZerodha {
				t.Errorf("Broker = %q, want %q", bsErr.Broker, brokersession.BrokerZerodha)
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
		{string(StepLogin), "login"},
		{string(StepTwoFA), "twofa"},
		{string(StepProfile), "profile"},
		{string(StepGetSessID), "get_sess_id"},
		{string(StepGetRequestToken), "get_request_token"},
		{string(StepSessionToken), "session_token"},
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
	if bsErr.Broker != brokersession.BrokerZerodha {
		t.Errorf("Broker = %q, want %q", bsErr.Broker, brokersession.BrokerZerodha)
	}
	if bsErr.Step != brokersession.StepValidate {
		t.Errorf("Step = %q, want %q", bsErr.Step, brokersession.StepValidate)
	}
	if bsErr.Message != "session: required" {
		t.Errorf("Message = %q, want %q", bsErr.Message, "session: required")
	}
}
