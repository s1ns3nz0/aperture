package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/lightninglabs/aperture/auth"
	"github.com/lightninglabs/aperture/l402"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon.v2"
)

// gatherVerifyReason reads the current value of
// aperture_l402_verify_total{reason=<reason>} straight from the process's
// default Prometheus registry. mint.l402VerifyTotal is unexported, so this
// package can't hold a reference to it directly; going through the
// registry is the same path a real Prometheus scrape takes.
func gatherVerifyReason(t *testing.T, reason string) float64 {
	t.Helper()

	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "aperture_l402_verify_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func verifyReasonDelta(t *testing.T, reason string, fn func()) float64 {
	t.Helper()
	before := gatherVerifyReason(t, reason)
	fn()
	return gatherVerifyReason(t, reason) - before
}

// validL402Header builds a syntactically valid L402 Authorization header.
// Its content doesn't matter for these tests: mockMint.VerifyL402 accepts
// any macaroon unconditionally, so this only needs to satisfy
// l402.FromHeader's parsing, not any real cryptographic check.
func validL402Header(t *testing.T) http.Header {
	t.Helper()

	mac, err := macaroon.New(
		make([]byte, 32), []byte("test-id"), "lsat",
		macaroon.LatestVersion,
	)
	require.NoError(t, err)

	header := http.Header{}
	require.NoError(t, l402.SetHeader(&header, mac, lntypes.Preimage{}))
	return header
}

func TestAcceptRecordsMalformedHeader(t *testing.T) {
	t.Parallel()

	authenticator := auth.NewL402Authenticator(&mockMint{}, &mockChecker{})

	empty := http.Header{}
	d := verifyReasonDelta(t, "malformed_header", func() {
		ok := authenticator.Accept(&empty, "svc")
		require.False(t, ok)
	})
	require.Equal(t, float64(1), d)
}

func TestAcceptRecordsInvoiceUnsettled(t *testing.T) {
	t.Parallel()

	checker := &mockChecker{err: errors.New("invoice not settled")}
	authenticator := auth.NewL402Authenticator(&mockMint{}, checker)

	header := validL402Header(t)
	d := verifyReasonDelta(t, "invoice_unsettled", func() {
		ok := authenticator.Accept(&header, "svc")
		require.False(t, ok)
	})
	require.Equal(t, float64(1), d)
}

func TestAcceptRecordsAccepted(t *testing.T) {
	t.Parallel()

	authenticator := auth.NewL402Authenticator(&mockMint{}, &mockChecker{})

	header := validL402Header(t)
	d := verifyReasonDelta(t, "accepted", func() {
		ok := authenticator.Accept(&header, "svc")
		require.True(t, ok)
	})
	require.Equal(t, float64(1), d)
}
