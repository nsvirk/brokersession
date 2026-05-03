package brokersession

import (
	"errors"
	"testing"
)

func TestBrokerNameConstants(t *testing.T) {
	t.Parallel()
	if got, want := string(BrokerZerodha), "zerodha"; got != want {
		t.Errorf("BrokerZerodha = %q, want %q", got, want)
	}
	if got, want := string(BrokerUpstox), "upstox"; got != want {
		t.Errorf("BrokerUpstox = %q, want %q", got, want)
	}
}

func TestSharedStepConstants(t *testing.T) {
	t.Parallel()
	if got, want := string(StepValidate), "validate"; got != want {
		t.Errorf("StepValidate = %q, want %q", got, want)
	}
	if got, want := string(StepVerify), "verify"; got != want {
		t.Errorf("StepVerify = %q, want %q", got, want)
	}
	if got, want := string(StepDelete), "delete"; got != want {
		t.Errorf("StepDelete = %q, want %q", got, want)
	}
}

func TestErrorString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{
			name: "validation error",
			err: &Error{
				Broker:  BrokerZerodha,
				Step:    StepValidate,
				Message: "UserID: required",
			},
			want: `brokersession: broker=zerodha step=validate msg="UserID: required"`,
		},
		{
			name: "HTTP error with status",
			err: &Error{
				Broker:     BrokerUpstox,
				Step:       Step("token_exchange"),
				StatusCode: 401,
				Message:    "Invalid token used to access API",
			},
			want: `brokersession: broker=upstox step=token_exchange status=401 msg="Invalid token used to access API"`,
		},
		{
			name: "transport error",
			err: &Error{
				Broker: BrokerUpstox,
				Step:   Step("otp_generate"),
				Err:    errors.New(`Get "...": context deadline exceeded`),
			},
			want: `brokersession: broker=upstox step=otp_generate transport_error="Get \"...\": context deadline exceeded"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("network down")
	err := &Error{
		Broker: BrokerZerodha,
		Step:   Step("login"),
		Err:    cause,
	}
	if got := errors.Unwrap(err); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true")
	}
}

func TestErrorAs(t *testing.T) {
	t.Parallel()
	original := &Error{Broker: BrokerZerodha, Step: StepValidate, Message: "test"}
	var got *Error
	if !errors.As(error(original), &got) {
		t.Fatalf("errors.As did not extract *Error")
	}
	if got != original {
		t.Errorf("errors.As extracted %v, want %v", got, original)
	}
}
