package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/aperture/auth"
	"github.com/lightninglabs/aperture/challenger"
	"github.com/lightninglabs/aperture/l402"
	"github.com/lightninglabs/aperture/mint"
	"github.com/lightninglabs/aperture/securitylog"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon.v2"
)

type eventStore struct {
	secret [32]byte
	err    error
}

func (s *eventStore) NewSecret(context.Context, [32]byte) ([32]byte, error) { return s.secret, nil }
func (s *eventStore) GetSecret(context.Context, [32]byte) ([32]byte, error) { return s.secret, s.err }
func (s *eventStore) RevokeSecret(context.Context, [32]byte) error          { return nil }

type eventChecker struct {
	preimage     lntypes.Preimage
	enabled      bool
	err, mintErr error
}

func (*eventChecker) Stop() {}

func (c *eventChecker) NewChallenge(int64) (string, lntypes.Hash, error) {
	return "invoice-canary", c.preimage.Hash(), c.mintErr
}
func (c *eventChecker) VerifyInvoiceStatus(lntypes.Hash, lnrpc.Invoice_InvoiceState, time.Duration) error {
	return c.err
}
func (c *eventChecker) InvoiceCheckEnabled() bool { return c.enabled }

type eventLimiter struct{}

func (eventLimiter) ServiceCapabilities(context.Context, ...l402.Service) ([]l402.Caveat, error) {
	return nil, nil
}
func (eventLimiter) ServiceConstraints(context.Context, ...l402.Service) ([]l402.Caveat, error) {
	return nil, nil
}
func (eventLimiter) ServiceTimeouts(context.Context, ...l402.Service) ([]l402.Caveat, error) {
	return nil, nil
}

type eventSink struct {
	mu   sync.Mutex
	data bytes.Buffer
	fail error
}

func (s *eventSink) TryWrite(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	_, err := s.data.Write(b)
	return err
}
func (*eventSink) Close() error { return nil }
func (s *eventSink) events(t *testing.T) []securitylog.Event {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var events []securitylog.Event
	for _, line := range bytes.Split(bytes.TrimSpace(s.data.Bytes()), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e securitylog.Event
		require.NoError(t, json.Unmarshal(line, &e))
		events = append(events, e)
	}
	return events
}

type eventFixture struct {
	p       *Proxy
	minter  *mint.Mint
	store   *eventStore
	checker *eventChecker
	emitter *securitylog.Emitter
	sink    *eventSink
	backend *httptest.Server
}

func newEventFixture(t *testing.T, enabled bool, fail error) *eventFixture {
	t.Helper()
	f := &eventFixture{store: &eventStore{}, checker: &eventChecker{enabled: true}, sink: &eventSink{fail: fail}}
	copy(f.store.secret[:], []byte("signing-secret-canary-01234567890"))
	copy(f.checker.preimage[:], []byte("payment-preimage-canary-012345678"))
	f.minter = mint.New(&mint.Config{Secrets: f.store, Challenger: f.checker, ServiceLimiter: eventLimiter{}, Now: time.Now})
	f.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(f.backend.Close)
	var err error
	f.p, err = New(auth.NewL402Authenticator(f.minter, f.checker), []*Service{{Name: "configured-service", Address: strings.TrimPrefix(f.backend.URL, "http://"), Protocol: "http", HostRegexp: ".*", PathRegexp: ".*", Auth: "on", Price: 1}}, nil, nil)
	require.NoError(t, err)
	if enabled {
		f.emitter, err = securitylog.New(bytes.Repeat([]byte{0xad}, 32), "rotation-v1", f.sink)
		require.NoError(t, err)
		f.p.SetSecurityLog(f.emitter)
		t.Cleanup(f.emitter.Close)
	}
	return f
}
func (f *eventFixture) request(header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://seller/path-canary?query-canary=value", nil)
	r.RemoteAddr = "192.0.2.44:5000"
	r.Header = header.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("Referer", "https://referer-canary")
	r.Header.Set("X-Forwarded-For", "198.51.100.99")
	r.Header.Set("X-Request-ID", "client-id-canary")
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, r)
	return w
}
func (f *eventFixture) token(t *testing.T) *macaroon.Macaroon {
	t.Helper()
	m, _, err := f.minter.MintL402(context.Background(), l402.Service{Name: "configured-service", Tier: l402.BaseTier, Price: 1})
	require.NoError(t, err)
	return m
}
func eventHeader(t *testing.T, m *macaroon.Macaroon, p lntypes.Preimage) http.Header {
	t.Helper()
	h := make(http.Header)
	require.NoError(t, l402.SetHeader(&h, m, p))
	return h
}
func authorizations(events []securitylog.Event) []securitylog.Event {
	var out []securitylog.Event
	for _, e := range events {
		if e.Event == "l402.authorization" {
			out = append(out, e)
		}
	}
	return out
}

func TestSecurityEventsPaymentFlowAndReuse(t *testing.T) {
	f := newEventFixture(t, true, nil)
	w := f.request(nil)
	require.Equal(t, http.StatusPaymentRequired, w.Code)
	var token *macaroon.Macaroon
	for _, v := range w.Header().Values("WWW-Authenticate") {
		if !strings.HasPrefix(v, "L402 ") {
			continue
		}
		parts := challengeMacaroonRegex.FindStringSubmatch(v)
		require.Len(t, parts, 2)
		b, err := base64.StdEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		token = &macaroon.Macaroon{}
		require.NoError(t, token.UnmarshalBinary(b))
	}
	require.NotNil(t, token)
	h := eventHeader(t, token, f.checker.preimage)
	for i := 0; i < 2; i++ {
		require.Equal(t, http.StatusNoContent, f.request(h).Code)
	}
	f.checker.enabled = false
	require.Equal(t, http.StatusNoContent, f.request(h).Code)
	f.emitter.Close()
	events := f.sink.events(t)
	require.Len(t, events, 8)
	final := authorizations(events)
	require.Len(t, final, 4)
	require.Equal(t, "missing_credentials", final[0].Reason)
	var issued securitylog.Event
	var skipped, settled int
	for _, e := range events {
		require.Equal(t, "configured-service", e.Service)
		require.Equal(t, "192.0.2.44", e.SourceIP)
		require.Equal(t, "GET", e.Method)
		switch e.Event {
		case "l402.challenge":
			issued = e
		case "l402.settlement":
			if e.Outcome == "skipped" {
				skipped++
			} else if e.Outcome == "settled" {
				settled++
			}
		}
	}
	require.Equal(t, 1, skipped)
	require.Equal(t, 2, settled)
	require.Equal(t, final[0].RequestID, issued.RequestID)
	require.True(t, issued.CredentialVerified)
	for _, e := range final[1:] {
		require.Equal(t, "accepted", e.Outcome)
		require.Equal(t, issued.PaymentRef, e.PaymentRef)
		require.Equal(t, issued.CredentialRef, e.CredentialRef)
		require.NotEqual(t, issued.RequestID, e.RequestID)
	}
	serialized, err := token.MarshalBinary()
	require.NoError(t, err)
	for _, canary := range []string{h.Get("Authorization"), base64.StdEncoding.EncodeToString(serialized), f.checker.preimage.String(), f.checker.preimage.Hash().String(), hex.EncodeToString(f.store.secret[:]), strings.Repeat("ad", 32), "path-canary", "query-canary", "referer-canary", "client-id-canary", "invoice-canary", "198.51.100.99"} {
		require.NotContains(t, f.sink.data.String(), canary)
	}
}

func TestSecurityEventsFailures(t *testing.T) {
	cases := []struct {
		name, reason, level string
		modify              func(*testing.T, *eventFixture, *macaroon.Macaroon) http.Header
	}{
		{"signature", "invalid_signature", "INFO", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			b, err := m.MarshalBinary()
			require.NoError(t, err)
			b[len(b)-1] ^= 1
			var bad macaroon.Macaroon
			require.NoError(t, bad.UnmarshalBinary(b))
			return eventHeader(t, &bad, f.checker.preimage)
		}},
		{"preimage", "payment_proof_mismatch", "INFO", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			p := f.checker.preimage
			p[0] ^= 1
			return eventHeader(t, m, p)
		}},
		{"expired", "restriction_failure", "INFO", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			require.NoError(t, l402.AddFirstPartyCaveats(m, l402.Caveat{Condition: "configured-service_valid_until", Value: "1"}))
			return eventHeader(t, m, f.checker.preimage)
		}},
		{"store", "secret_store_error", "ERROR", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			f.store.err = errors.New("secret-store-error-canary")
			return eventHeader(t, m, f.checker.preimage)
		}},
		{"revoked", "unknown_credential", "INFO", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			f.store.err = mint.ErrSecretNotFound
			return eventHeader(t, m, f.checker.preimage)
		}},
		{"invoice mismatch", "invoice_state_mismatch", "INFO", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			f.checker.err = &challenger.InvoiceStatusError{Reason: "invoice_state_mismatch", Err: errors.New("invoice-error-canary")}
			return eventHeader(t, m, f.checker.preimage)
		}},
		{"invoice lookup", "invoice_check_error", "ERROR", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			f.checker.err = errors.New("invoice-error-canary")
			return eventHeader(t, m, f.checker.preimage)
		}},
		{"malformed", "malformed_credentials", "INFO", func(t *testing.T, f *eventFixture, m *macaroon.Macaroon) http.Header {
			return http.Header{"Authorization": []string{"L402 token-canary:preimage-canary"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newEventFixture(t, true, nil)
			h := tc.modify(t, f, f.token(t))
			require.Equal(t, http.StatusPaymentRequired, f.request(h).Code)
			f.emitter.Close()
			final := authorizations(f.sink.events(t))
			require.Len(t, final, 1)
			e := final[0]
			require.Equal(t, "denied", e.Outcome)
			require.Equal(t, tc.reason, e.Reason)
			require.Equal(t, tc.level, e.Level)
			if tc.name == "signature" || tc.name == "preimage" {
				require.False(t, e.CredentialVerified)
				require.NotEmpty(t, e.PaymentRef)
			}
			if tc.name == "malformed" {
				require.Empty(t, e.PaymentRef)
				require.Empty(t, e.CredentialRef)
			}
			for _, v := range []string{"token-canary", "preimage-canary", "invoice-error-canary", "secret-store-error-canary"} {
				require.NotContains(t, f.sink.data.String(), v)
			}
		})
	}
}

func TestSecurityEventsDisabledAndBlocked(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, failure := range []error{nil, securitylog.ErrWouldBlock, errors.New("output failure")} {
			t.Run(fmt.Sprintf("%v/%v", enabled, failure), func(t *testing.T) {
				f := newEventFixture(t, enabled, failure)
				h := eventHeader(t, f.token(t), f.checker.preimage)
				start := time.Now()
				for i := 0; i < 300; i++ {
					require.Equal(t, http.StatusNoContent, f.request(h).Code)
				}
				require.Less(t, time.Since(start), 5*time.Second)
				if !enabled {
					require.Empty(t, f.sink.events(t))
					return
				}
				f.emitter.Close()
				if failure != nil {
					require.Positive(t, f.emitter.Stats().Dropped)
					require.Positive(t, f.emitter.Stats().OutputErrors)
				}
			})
		}
	}
}

type otherScheme struct{ accepted bool }

func (o otherScheme) Accept(*http.Header, string) bool { return o.accepted }
func (otherScheme) FreshChallengeHeader(string, int64) (http.Header, error) {
	return http.Header{"WWW-Authenticate": []string{"Payment mock"}}, nil
}
func (otherScheme) Scheme() string { return auth.AuthSchemeMPP }

func TestSecurityEventsMixedSchemes(t *testing.T) {
	for _, tc := range []struct {
		name, scheme            string
		firstOther, otherAccept bool
		wantCount               int
		outcome                 string
	}{
		{"fallback", "l402+mpp", false, true, 1, "not_applicable"},
		{"both denied", "l402+mpp", false, false, 1, "denied"},
		{"mpp only", "mpp", false, true, 0, ""},
		{"mpp first", "l402+mpp", true, true, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEventFixture(t, true, nil)
			l := auth.NewL402Authenticator(f.minter, f.checker)
			o := otherScheme{tc.otherAccept}
			if tc.firstOther {
				f.p.authenticator = auth.NewMultiAuthenticator(o, l)
			} else {
				f.p.authenticator = auth.NewMultiAuthenticator(l, o)
			}
			f.p.services[0].AuthScheme = tc.scheme
			w := f.request(http.Header{"Authorization": []string{"Payment mpp-credential-canary"}})
			if tc.otherAccept {
				require.Equal(t, http.StatusNoContent, w.Code)
			} else {
				require.Equal(t, http.StatusPaymentRequired, w.Code)
			}
			f.emitter.Close()
			events := authorizations(f.sink.events(t))
			require.Len(t, events, tc.wantCount)
			if tc.wantCount > 0 {
				require.Equal(t, tc.outcome, events[0].Outcome)
				if tc.otherAccept {
					require.Equal(t, "accepted_other_scheme", events[0].Reason)
				}
			}
		})
	}
}

func TestSecurityEventsOrdinaryLogThreshold(t *testing.T) {
	// Explicitly suppress INFO, then ensure the separate stream emits it.
	logger := btclog.NewSLogger(btclog.NewDefaultHandler(&bytes.Buffer{}))
	logger.SetLevel(btclog.LevelError)
	previous := log
	UseLogger(logger)
	defer UseLogger(previous)
	f := newEventFixture(t, true, nil)
	require.Equal(t, http.StatusNoContent, f.request(eventHeader(t, f.token(t), f.checker.preimage)).Code)
	f.emitter.Close()
	events := authorizations(f.sink.events(t))
	require.Len(t, events, 1)
	require.Equal(t, "INFO", events[0].Level)
}

func TestSecurityEventsConcurrentFinalDecisions(t *testing.T) {
	f := newEventFixture(t, true, nil)
	h := eventHeader(t, f.token(t), f.checker.preimage)
	var wg sync.WaitGroup
	statuses := make(chan int, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- f.request(h).Code }()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		require.Equal(t, http.StatusNoContent, status)
	}
	f.emitter.Close()
	require.Zero(t, f.emitter.Stats().Dropped)
	final := authorizations(f.sink.events(t))
	require.Len(t, final, 100)
	seen := map[string]bool{}
	for _, e := range final {
		require.False(t, seen[e.RequestID])
		seen[e.RequestID] = true
		require.Equal(t, "accepted", e.Outcome)
	}
}

func TestSecurityEventsAttenuationAndChallengeFailure(t *testing.T) {
	f := newEventFixture(t, true, nil)
	m := f.token(t)
	require.Equal(t, http.StatusNoContent, f.request(eventHeader(t, m, f.checker.preimage)).Code)
	require.NoError(t, l402.AddFirstPartyCaveats(m, l402.Caveat{Condition: "configured-service_valid_until", Value: "9999999999"}))
	require.Equal(t, http.StatusNoContent, f.request(eventHeader(t, m, f.checker.preimage)).Code)
	f.checker.mintErr = errors.New("mint-error-secret-canary")
	require.Equal(t, http.StatusInternalServerError, f.request(nil).Code)
	f.emitter.Close()
	events := f.sink.events(t)
	final := authorizations(events)
	require.Len(t, final, 3)
	require.Equal(t, final[0].CredentialRef, final[1].CredentialRef)
	last := events[len(events)-1]
	require.Equal(t, "l402.challenge", last.Event)
	require.Equal(t, "ERROR", last.Level)
	require.Equal(t, "challenge_creation_failed", last.Reason)
	require.NotContains(t, f.sink.data.String(), "mint-error-secret-canary")
}

func TestSecurityEventsBoundPaymentReference(t *testing.T) {
	f := newEventFixture(t, true, nil)
	m := f.token(t)
	require.Equal(t, http.StatusNoContent, f.request(eventHeader(t, m, f.checker.preimage)).Code)
	wrong := f.checker.preimage
	wrong[0] ^= 1
	require.Equal(t, http.StatusPaymentRequired, f.request(eventHeader(t, m, wrong)).Code)
	f.emitter.Close()
	final := authorizations(f.sink.events(t))
	require.Len(t, final, 2)
	require.Equal(t, final[0].PaymentRef, final[1].PaymentRef)
	require.True(t, final[0].CredentialVerified)
	require.False(t, final[1].CredentialVerified)
	require.NotContains(t, f.sink.data.String(), wrong.String())
	require.NotContains(t, f.sink.data.String(), wrong.Hash().String())
}

func TestSecurityEventsDynamicResourceAndLargeInput(t *testing.T) {
	f := newEventFixture(t, true, nil)
	// Keep the fixture's in-memory price provider, but exercise the
	// request-derived resource name used by dynamic pricing.
	f.p.services[0].DynamicPrice.Enabled = true
	header := http.Header{"Authorization": []string{strings.Repeat("header-canary", 10000)}}
	require.Equal(t, http.StatusPaymentRequired, f.request(header).Code)
	f.emitter.Close()
	events := f.sink.events(t)
	require.Len(t, events, 2)
	for _, e := range events {
		require.Equal(t, "configured-service", e.Service)
		b, err := json.Marshal(e)
		require.NoError(t, err)
		require.LessOrEqual(t, len(b)+1, securitylog.MaxEventSize)
	}
	require.NotContains(t, f.sink.data.String(), "path-canary")
	require.NotContains(t, f.sink.data.String(), "header-canary")
}

func TestSecurityEventsMixedInternalFailure(t *testing.T) {
	f := newEventFixture(t, true, nil)
	h := eventHeader(t, f.token(t), f.checker.preimage)
	f.store.err = errors.New("store-error-secret-canary")
	f.p.authenticator = auth.NewMultiAuthenticator(
		auth.NewL402Authenticator(f.minter, f.checker), otherScheme{true},
	)
	f.p.services[0].AuthScheme = auth.AuthSchemeL402MPP
	require.Equal(t, http.StatusNoContent, f.request(h).Code)
	f.emitter.Close()
	final := authorizations(f.sink.events(t))
	require.Len(t, final, 1)
	require.Equal(t, "not_applicable", final[0].Outcome)
	require.Equal(t, "accepted_other_scheme", final[0].Reason)
	require.Equal(t, "secret_store_error", final[0].L402Reason)
	require.Equal(t, "ERROR", final[0].Level)
}
