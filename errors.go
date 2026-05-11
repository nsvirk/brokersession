package brokersession

import "fmt"

// BrokerName identifies which broker generated a session or error.
type BrokerName string

// Canonical broker identifiers. Wire format is the underlying string value.
const (
	BrokerZerodha BrokerName = "zerodha"
	BrokerUpstox  BrokerName = "upstox"
	BrokerDhan    BrokerName = "dhan"
)

// Step identifies a stage of the GenerateSession / DeleteSession flow.
// Shared step constants are declared here; broker-specific step constants
// are declared in their owning subpackage.
type Step string

// Shared step constants used by both brokers.
const (
	StepValidate Step = "validate"
	StepVerify   Step = "verify"
	StepDelete   Step = "delete"
)

// Error is the typed error returned from GenerateSession and DeleteSession.
//
// Invariants:
//
//   - Err is set only for transport-level causes (DNS, TCP reset,
//     context.DeadlineExceeded, etc.); it is what errors.Unwrap returns so
//     errors.Is reaches through to that cause. Decode / parse failures on a
//     completed round-trip do not populate Err.
//   - StatusCode > 0 indicates that an HTTP round-trip completed.
//
// Raw carries the verbatim broker response body when JSON-decodable, so
// callers needing broker-specific fields (Upstox errorCode, Zerodha
// error_type, etc.) read them from Raw rather than relying on a single
// normalized Code field.
type Error struct {
	Broker     BrokerName     `json:"broker"`
	Step       Step           `json:"step"`
	StatusCode int            `json:"status_code,omitempty"`
	Message    string         `json:"message"`
	Err        error          `json:"-"`
	Raw        map[string]any `json:"raw,omitempty"`
}

// Error implements the error interface. Format depends on which fields are
// populated — transport errors include the wrapped cause; HTTP errors
// include the status code; validation errors omit both.
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("brokersession: broker=%s step=%s transport_error=%q",
			e.Broker, e.Step, e.Err.Error())
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("brokersession: broker=%s step=%s status=%d msg=%q",
			e.Broker, e.Step, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("brokersession: broker=%s step=%s msg=%q",
		e.Broker, e.Step, e.Message)
}

// Unwrap returns the wrapped transport error so errors.As / errors.Is
// reach through to the underlying cause (DNS, TCP reset,
// context.DeadlineExceeded, etc.).
func (e *Error) Unwrap() error { return e.Err }
