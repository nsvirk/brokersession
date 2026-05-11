package dhan

import (
	"errors"
	"strings"
	"testing"

	"github.com/nsvirk/brokersession"
)

// withEndpoints temporarily overrides package-level URL vars and registers
// a t.Cleanup to restore them. Pass a map of *target → newValue.
func withEndpoints(t *testing.T, m map[*string]string) {
	t.Helper()
	saved := make(map[*string]string, len(m))
	for p := range m {
		saved[p] = *p
	}
	t.Cleanup(func() {
		for p, v := range saved {
			*p = v
		}
	})
	for p, v := range m {
		*p = v
	}
}

// assertBSError walks err, asserts it is a *brokersession.Error with the
// expected broker, step and status, and that Message contains wantMsgSubstr.
// Pass wantStatus = -1 to skip the status check.
func assertBSError(t *testing.T, err error, wantBroker brokersession.BrokerName, wantStep brokersession.Step, wantStatus int, wantMsgSubstr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *brokersession.Error, got nil")
	}
	var bsErr *brokersession.Error
	if !errors.As(err, &bsErr) {
		t.Fatalf("err is not *brokersession.Error: %T (%v)", err, err)
	}
	if bsErr.Broker != wantBroker {
		t.Errorf("Broker = %q, want %q", bsErr.Broker, wantBroker)
	}
	if bsErr.Step != wantStep {
		t.Errorf("Step = %q, want %q", bsErr.Step, wantStep)
	}
	if wantStatus >= 0 && bsErr.StatusCode != wantStatus {
		t.Errorf("StatusCode = %d, want %d", bsErr.StatusCode, wantStatus)
	}
	if wantMsgSubstr != "" && !strings.Contains(bsErr.Message, wantMsgSubstr) {
		t.Errorf("Message = %q, want substring %q", bsErr.Message, wantMsgSubstr)
	}
}
