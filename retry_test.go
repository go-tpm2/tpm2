package tpm2

import (
	"errors"
	"testing"
	"time"

	"github.com/go-tpm2/common"
)

// busyTransport answers a list of canned responses in order and then REPEATS
// the last one, which is what a TPM that stays busy looks like. seal_test.go's
// scriptedTransport runs off the end of its slice instead, so it cannot
// express "and it never clears".
type busyTransport struct {
	replies [][]byte
	sent    int
}

func (s *busyTransport) Send(cmd []byte) ([]byte, error) {
	s.sent++
	i := s.sent - 1
	if i >= len(s.replies) {
		i = len(s.replies) - 1
	}
	return s.replies[i], nil
}

func retryResp() []byte {
	return resp(uint16(common.TagNoSessions), rcRetry, nil)
}

// TestARetryIsResentRatherThanReported. TPM_RC_RETRY is the TPM saying it
// could not start the command — a warning, not a failure. openweft/weft's
// swtpm attestation test failed the first time it ever ran with exactly this,
// on TPM2_Quote against a software TPM that had not finished starting.
func TestARetryIsResentRatherThanReported(t *testing.T) {
	st := &busyTransport{replies: [][]byte{
		retryResp(),
		retryResp(),
		okResp([]byte{0xAB}),
	}}
	out, err := New(st).execute(common.TagNoSessions, common.CCQuote, nil)
	if err != nil {
		t.Fatalf("a TPM that asked to be asked again was reported as broken: %v", err)
	}
	if len(out) != 1 || out[0] != 0xAB {
		t.Errorf("params = % x, want ab", out)
	}
	if st.sent != 3 {
		t.Errorf("sent %d commands, want 3 — two refusals and the one that worked", st.sent)
	}
}

// TestARetryThatNeverClearsStillEnds. A TPM that is genuinely stuck must give
// an error, not a hang: turning "busy" into "the program stopped" is worse
// than the error it replaces.
func TestARetryThatNeverClearsStillEnds(t *testing.T) {
	st := &busyTransport{replies: [][]byte{retryResp()}}
	start := time.Now()
	_, err := New(st).execute(common.TagNoSessions, common.CCQuote, nil)
	if err == nil {
		t.Fatal("a TPM that never stopped being busy returned success")
	}
	var te *TPMError
	if !errors.As(err, &te) || te.RC != rcRetry {
		t.Errorf("err = %v, want a TPMError carrying rc 0x922", err)
	}
	if st.sent != retryLimit+1 {
		t.Errorf("sent %d commands, want %d — the first plus %d retries", st.sent, retryLimit+1, retryLimit)
	}
	// The whole doubling series is about a quarter of a second; a minute would
	// mean the bound is not doing its job.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("gave up after %v, which is not a bound anybody would wait for", d)
	}
}

// TestAnythingElseIsStillAnError — the other direction. A retry loop that
// swallowed other response codes would turn every real failure into a pause
// and then the same failure, which is the quiet way to make this worse.
func TestAnythingElseIsStillAnError(t *testing.T) {
	const rcValue = 0x1D5 // TPM_RC_SIZE on parameter 1: the rc a real swtpm
	// caught in import.go, and one nothing should retry.
	st := &busyTransport{replies: [][]byte{
		resp(uint16(common.TagNoSessions), rcValue, nil),
		okResp(nil),
	}}
	_, err := New(st).execute(common.TagNoSessions, common.CCQuote, nil)
	if err == nil {
		t.Fatal("a real failure was retried into a success")
	}
	var te *TPMError
	if !errors.As(err, &te) || te.RC != rcValue {
		t.Errorf("err = %v, want rc 0x1D5", err)
	}
	if st.sent != 1 {
		t.Errorf("sent %d commands, want 1 — a non-retry code is not resent", st.sent)
	}
}

// TestSuccessIsNotDelayed. The common path must not pay for the retry: one
// command, no sleep.
func TestSuccessIsNotDelayed(t *testing.T) {
	st := &busyTransport{replies: [][]byte{okResp(nil)}}
	start := time.Now()
	if _, err := New(st).execute(common.TagNoSessions, common.CCQuote, nil); err != nil {
		t.Fatal(err)
	}
	if st.sent != 1 {
		t.Errorf("sent %d commands for a success, want 1", st.sent)
	}
	if d := time.Since(start); d > retryBackoff {
		t.Errorf("a successful command waited %v", d)
	}
}
