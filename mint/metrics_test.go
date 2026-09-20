package mint

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/lightninglabs/aperture/l402"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon.v2"
)

// mintDelta runs fn and returns how much the mint counter for result changed.
// Reading a before/after delta rather than an absolute value keeps these
// tests independent of execution order and of every other test in the
// package that touches the same process-global counters.
func mintDelta(t *testing.T, result MintResult, fn func()) float64 {
	t.Helper()
	c := l402MintTotal.WithLabelValues(string(result))
	before := testutil.ToFloat64(c)
	fn()
	return testutil.ToFloat64(c) - before
}

// verifyDelta is mintDelta's counterpart for the verify counter.
func verifyDelta(t *testing.T, reason VerifyReason, fn func()) float64 {
	t.Helper()
	c := l402VerifyTotal.WithLabelValues(string(reason))
	before := testutil.ToFloat64(c)
	fn()
	return testutil.ToFloat64(c) - before
}

func newTestMint(secrets SecretStore, challenger Challenger) *Mint {
	if secrets == nil {
		secrets = newMockSecretStore()
	}
	if challenger == nil {
		challenger = newMockChallenger()
	}
	return New(&Config{
		Secrets:        secrets,
		Challenger:     challenger,
		ServiceLimiter: newMockServiceLimiter(),
		Now:            time.Now,
	})
}

// --- MintL402 ---

// TestMetricsMintOK deliberately does not call t.Parallel(): MintOK is
// incremented as a side effect by every other successful mint anywhere in
// this package's test suite (including the pre-existing TestBasicL402 /
// TestAdminL402), so measuring its delta is only race-free while those
// parallel tests are still paused, i.e. before this test returns.
func TestMetricsMintOK(t *testing.T) {
	m := newTestMint(nil, nil)
	d := mintDelta(t, MintOK, func() {
		_, _, err := m.MintL402(context.Background(), testService)
		require.NoError(t, err)
	})
	require.Equal(t, float64(1), d)
}

type failingChallenger struct{}

func (failingChallenger) Start() error { return nil }
func (failingChallenger) Stop()        {}
func (failingChallenger) NewChallenge(int64) (string, lntypes.Hash, error) {
	return "", lntypes.Hash{}, errors.New("challenger unavailable")
}

func TestMetricsMintChallengeFailed(t *testing.T) {
	t.Parallel()

	m := newTestMint(nil, failingChallenger{})
	d := mintDelta(t, MintChallengeFailed, func() {
		_, _, err := m.MintL402(context.Background(), testService)
		require.Error(t, err)
	})
	require.Equal(t, float64(1), d)
}

// --- VerifyL402 ---

// TestMetricsVerifyMacaroonValid deliberately does not call t.Parallel():
// see TestMetricsMintOK — the same reasoning applies to VerifyMacaroonValid,
// which every successful VerifyL402 call in this package's test suite also
// increments.
func TestMetricsVerifyMacaroonValid(t *testing.T) {
	m := newTestMint(nil, nil)
	mac, _, err := m.MintL402(context.Background(), testService)
	require.NoError(t, err)

	d := verifyDelta(t, VerifyMacaroonValid, func() {
		err := m.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      testPreimage,
			TargetService: testService.Name,
		})
		require.NoError(t, err)
	})
	require.Equal(t, float64(1), d)
}

func TestMetricsVerifyBadPreimage(t *testing.T) {
	t.Parallel()

	m := newTestMint(nil, nil)
	mac, _, err := m.MintL402(context.Background(), testService)
	require.NoError(t, err)

	wrongPreimage := testPreimage
	wrongPreimage[0] ^= 0xFF

	d := verifyDelta(t, VerifyBadPreimage, func() {
		err := m.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      wrongPreimage,
			TargetService: testService.Name,
		})
		require.True(t, errors.Is(err, ErrInvalidPreimage))
	})
	require.Equal(t, float64(1), d)
}

// TestMetricsVerifyCaveatUnsatisfied deliberately does not call
// t.Parallel(): TestBasicL402's unauthorized-service check and the
// pre-existing TestDemotedServicesL402 / TestExpiredServicesL402 all hit
// VerifyCaveatUnsatisfied too, and are themselves parallel — see
// TestMetricsMintOK for why non-parallel is what dodges that.
func TestMetricsVerifyCaveatUnsatisfied(t *testing.T) {
	m := newTestMint(nil, nil)
	mac, _, err := m.MintL402(context.Background(), testService)
	require.NoError(t, err)

	d := verifyDelta(t, VerifyCaveatUnsatisfied, func() {
		err := m.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      testPreimage,
			TargetService: "some-other-service",
		})
		require.Error(t, err)
	})
	require.Equal(t, float64(1), d)
}

func TestMetricsVerifyMalformedMacaroon(t *testing.T) {
	t.Parallel()

	m := newTestMint(nil, nil)

	// A macaroon whose ID isn't an L402 identifier at all: DecodeIdentifier
	// must fail before the preimage is even inspected.
	mac, err := macaroon.New(
		[]byte("some-32-byte-secret-value-here!"), []byte("not-an-id"),
		"lsat", macaroon.LatestVersion,
	)
	require.NoError(t, err)

	d := verifyDelta(t, VerifyMalformedMacaroon, func() {
		err := m.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      testPreimage,
			TargetService: testService.Name,
		})
		require.Error(t, err)
	})
	require.Equal(t, float64(1), d)
}

// TestMetricsVerifySecretNotFound deliberately does not call t.Parallel():
// the pre-existing TestRevokedL402 also hits VerifySecretNotFound and is
// itself parallel — see TestMetricsMintOK for why non-parallel dodges that.
func TestMetricsVerifySecretNotFound(t *testing.T) {
	// Mint with one mint instance, then verify against a second one whose
	// secret store never saw that macaroon minted: GetSecret returns
	// ErrSecretNotFound, which must map to VerifySecretNotFound, not
	// VerifySecretLookupError.
	minting := newTestMint(nil, nil)
	mac, _, err := minting.MintL402(context.Background(), testService)
	require.NoError(t, err)

	verifying := newTestMint(newMockSecretStore(), nil)
	d := verifyDelta(t, VerifySecretNotFound, func() {
		err := verifying.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      testPreimage,
			TargetService: testService.Name,
		})
		require.True(t, errors.Is(err, ErrSecretNotFound))
	})
	require.Equal(t, float64(1), d)
}

// flakySecretStore always fails GetSecret with a non-ErrSecretNotFound
// error, simulating a backend/storage fault rather than an absent secret.
type flakySecretStore struct {
	SecretStore
}

func (flakySecretStore) GetSecret(context.Context,
	[sha256.Size]byte) ([l402.SecretSize]byte, error) {

	var secret [l402.SecretSize]byte
	return secret, errors.New("db: connection reset")
}

func TestMetricsVerifySecretLookupError(t *testing.T) {
	t.Parallel()

	m := newTestMint(nil, nil)
	mac, _, err := m.MintL402(context.Background(), testService)
	require.NoError(t, err)

	m.cfg.Secrets = flakySecretStore{}

	d := verifyDelta(t, VerifySecretLookupError, func() {
		err := m.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      testPreimage,
			TargetService: testService.Name,
		})
		require.Error(t, err)
		require.False(t, errors.Is(err, ErrSecretNotFound))
	})
	require.Equal(t, float64(1), d)
}

// fixedSecretStore always hands back the same secret, regardless of the
// macaroon it was minted for, so a macaroon signed with a different secret
// fails VerifySignature deterministically.
type fixedSecretStore struct {
	secret [l402.SecretSize]byte
}

func (s fixedSecretStore) NewSecret(context.Context,
	[sha256.Size]byte) ([l402.SecretSize]byte, error) {
	return s.secret, nil
}
func (s fixedSecretStore) GetSecret(context.Context,
	[sha256.Size]byte) ([l402.SecretSize]byte, error) {
	return s.secret, nil
}
func (fixedSecretStore) RevokeSecret(context.Context,
	[sha256.Size]byte) error {
	return nil
}

// TestMetricsVerifyBadSignature deliberately does not call t.Parallel():
// the pre-existing TestTamperedL402 also hits VerifyBadSignature and is
// itself parallel — see TestMetricsMintOK for why non-parallel dodges that.
func TestMetricsVerifyBadSignature(t *testing.T) {
	var mintSecret, verifySecret [l402.SecretSize]byte
	mintSecret[0] = 0x01
	verifySecret[0] = 0x02

	m := newTestMint(fixedSecretStore{secret: mintSecret}, nil)
	mac, _, err := m.MintL402(context.Background(), testService)
	require.NoError(t, err)

	// Same mint, but the secret store now hands back a different secret
	// than the one the macaroon was actually signed with.
	m.cfg.Secrets = fixedSecretStore{secret: verifySecret}

	d := verifyDelta(t, VerifyBadSignature, func() {
		err := m.VerifyL402(context.Background(), &VerificationParams{
			Macaroon:      mac,
			Preimage:      testPreimage,
			TargetService: testService.Name,
		})
		require.True(t, errors.Is(err, ErrInvalidSignature))
	})
	require.Equal(t, float64(1), d)
}

// --- RecordVerifyResult (the seam auth.Accept reports into) ---

func TestMetricsRecordVerifyResult(t *testing.T) {
	t.Parallel()

	for _, reason := range []VerifyReason{
		VerifyMalformedHeader, VerifyInvoiceUnsettled, VerifyAccepted,
	} {
		reason := reason
		t.Run(string(reason), func(t *testing.T) {
			t.Parallel()

			d := verifyDelta(t, reason, func() {
				RecordVerifyResult(reason)
			})
			require.Equal(t, float64(1), d)
		})
	}
}
