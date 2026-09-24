package securitylog

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCategorySeparation(t *testing.T) {
	for _, tc := range []struct {
		name, kind, outcome, reason, l402Reason, want string
		internal                                      bool
	}{
		{"accepted", "l402.authorization", "accepted", "accepted", "", "accepted", false},
		{"invalid", "l402.authorization", "denied", "invalid_signature", "", "denied", false},
		{"store", "l402.authorization", "denied", "secret_store_error", "", "indeterminate", true},
		{"lookup", "l402.authorization", "denied", "invoice_check_error", "", "indeterminate", true},
		{"missing invoice", "l402.authorization", "denied", "invoice_not_found", "", "indeterminate", true},
		{"stopped", "l402.authorization", "denied", "checker_stopped", "", "indeterminate", true},
		{"fallback", "l402.authorization", "denied", "processing_error", "", "indeterminate", true},
		{"mixed", "l402.authorization", "not_applicable", "accepted_other_scheme", "secret_store_error", "not_applicable", true},
		{"settlement", "l402.settlement", "error", "invoice_check_error", "", "error", true},
		{"mismatch", "l402.settlement", "mismatch", "invoice_state_mismatch", "", "mismatch", false},
		{"mint", "l402.challenge", "error", "challenge_creation_failed", "", "error", true},
		{"delivery", "l402.challenge", "error", "challenge_delivery_failed", "", "error", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &memorySink{}
			e, err := New(bytes.Repeat([]byte{1}, 32), "generation-1", sink)
			require.NoError(t, err)
			observed := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
			tr := e.Begin("svc", "GET", "192.0.2.1:1234")
			tr.Record(Detail{Kind: tc.kind, Outcome: tc.outcome, Reason: tc.reason,
				L402Reason: tc.l402Reason, Internal: tc.internal, Verified: true,
				Identifier: append([]byte{0, 0}, bytes.Repeat([]byte{7}, 64)...), ObservedAt: observed})
			e.Close()
			lines := bytes.Split(bytes.TrimSpace(sink.Bytes()), []byte{'\n'})
			count := 1
			if tc.internal {
				count = 2
			}
			require.Len(t, lines, count)
			var security Event
			require.NoError(t, json.Unmarshal(lines[0], &security))
			require.Equal(t, "security", security.Category)
			require.Equal(t, "INFO", security.Level)
			require.Equal(t, tc.want, security.Outcome)
			require.Equal(t, observed, security.Timestamp)
			require.NotEmpty(t, security.CredentialRef)
			require.True(t, security.CredentialVerified)
			if tc.internal {
				var op Event
				require.NoError(t, json.Unmarshal(lines[1], &op))
				require.Equal(t, "operational", op.Category)
				require.Equal(t, "ERROR", op.Level)
				require.Equal(t, "error", op.Outcome)
				reason := tc.reason
				if tc.l402Reason != "" {
					reason = tc.l402Reason
				}
				require.Equal(t, reason, op.Reason)
				require.Equal(t, security.RequestID, op.RequestID)
				require.Equal(t, security.Timestamp, op.Timestamp)
				require.Equal(t, security.Event, op.Event)
				require.Equal(t, security.Service, op.Service)
				require.Empty(t, op.CredentialRef)
				require.Empty(t, op.PaymentRef)
				require.Empty(t, op.KeyID)
				require.False(t, op.CredentialVerified)
			}
			require.Equal(t, uint64(count), e.Stats().Emitted)
		})
	}
}

func TestOperationalOutputFailureIsBounded(t *testing.T) {
	e, err := New(bytes.Repeat([]byte{1}, 32), "", &memorySink{fail: ErrWouldBlock})
	require.NoError(t, err)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		e.Begin("svc", "GET", "").Record(Detail{Kind: "l402.authorization",
			Outcome: "denied", Reason: "secret_store_error", Internal: true})
	}
	require.Less(t, time.Since(start), time.Second)
	require.LessOrEqual(t, e.Stats().Queued, QueueSize)
	e.Close()
	require.Equal(t, uint64(2000), e.Stats().Dropped)
	require.Zero(t, e.Stats().Emitted)
}
