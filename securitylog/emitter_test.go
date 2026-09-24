package securitylog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

type memorySink struct {
	bytes.Buffer
	fail error
}

func (s *memorySink) TryWrite(b []byte) error {
	if s.fail != nil {
		return s.fail
	}
	_, err := s.Write(b)
	return err
}
func (*memorySink) Close() error { return nil }

func TestConfig(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		e, err := Open(cfg)
		require.NoError(t, err)
		require.Nil(t, e)
	}
	_, err := New(nil)
	require.Error(t, err)
}

func TestReferencesAndBoundedFields(t *testing.T) {
	id := append([]byte{0, 0}, bytes.Repeat([]byte{7}, 64)...)
	newEmitter := func() *Emitter {
		e, err := New(&memorySink{})
		require.NoError(t, err)
		t.Cleanup(e.Close)
		return e
	}
	e := newEmitter()
	c, p := e.references(id)
	c2, p2 := e.references(id)
	require.Equal(t, c, c2)
	require.Equal(t, p, p2)
	require.NotEqual(t, c, p)
	require.Regexp(t, "^sha256:[0-9a-f]{64}$", c)
	require.Regexp(t, "^sha256:[0-9a-f]{64}$", p)
	// Independent fixed vectors lock down domain, NUL delimiter and component.
	require.Equal(t, "sha256:7119e4bb979deb49720c205bbc6227307d56f6ef9d9c61a2077251585a622e7a", c)
	require.Equal(t, "sha256:a1bed5f3c914f06d3046f7ce708ca81ca06db2f522993a5f6dd8c1b72c274457", p)
	changed := bytes.Clone(id)
	changed[34]++
	changedC, changedP := e.references(changed)
	require.NotEqual(t, c, changedC)
	require.Equal(t, p, changedP)
	changed = bytes.Clone(id)
	changed[2]++
	changedC, changedP = e.references(changed)
	require.Equal(t, c, changedC)
	require.NotEqual(t, p, changedP)
	c2, p2 = newEmitter().references(id)
	require.Equal(t, c, c2)
	require.Equal(t, p, p2)
	for _, malformed := range [][]byte{nil, id[:65], append([]byte{1}, id...), append([]byte{0, 1}, id[2:]...)} {
		c, p := e.references(malformed)
		require.Empty(t, c)
		require.Empty(t, p)
	}
	sink := &memorySink{}
	e, err := New(sink)
	require.NoError(t, err)
	tr := e.Begin(strings.Repeat("S", 100000), "METHOD-SECRET", "192.0.2.1:5000")
	tr.Record(Detail{Kind: "l402.authorization", Outcome: "denied", Reason: "invalid_signature", Identifier: id})
	tr.Record(Detail{Kind: "l402.authorization", Outcome: "denied", Reason: "error including secret-canary"})
	e.Close()
	var event Event
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(sink.Bytes()), &event))
	require.NotContains(t, string(sink.Bytes()), `"key_id"`)
	require.Len(t, event.Service, 128)
	require.Equal(t, "OTHER", event.Method)
	require.False(t, event.CredentialVerified)
	require.NotEmpty(t, event.CredentialRef)
	require.Equal(t, "192.0.2.1", event.SourceIP)
	require.Equal(t, uint64(1), e.Stats().Dropped)
	require.LessOrEqual(t, len(sink.Bytes()), MaxEventSize)
}

func TestConcurrentJSONAndUniqueRequests(t *testing.T) {
	sink := &memorySink{}
	e, err := New(sink)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Begin("svc", "GET", "[2001:db8::1]:1234").Record(Detail{Kind: "l402.authorization", Outcome: "accepted", Reason: "accepted"})
		}()
	}
	wg.Wait()
	e.Close()
	require.Zero(t, e.Stats().Dropped)
	seen := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(sink.Bytes()), []byte{'\n'}) {
		var event Event
		require.NoError(t, json.Unmarshal(line, &event))
		require.False(t, seen[event.RequestID])
		seen[event.RequestID] = true
		require.Equal(t, 1, event.SchemaVersion)
		require.Equal(t, "security", event.Category)
	}
	require.Len(t, seen, 100)
}

func TestOutputFailureAndShutdown(t *testing.T) {
	for _, failure := range []error{ErrWouldBlock, errors.New("sink failure secret-canary")} {
		t.Run(failure.Error(), func(t *testing.T) {
			e, err := New(&memorySink{fail: failure})
			require.NoError(t, err)
			start := time.Now()
			for i := 0; i < 1000; i++ {
				e.Begin("svc", "GET", "").Record(Detail{Kind: "l402.authorization", Outcome: "accepted", Reason: "accepted"})
			}
			require.Less(t, time.Since(start), time.Second)
			require.LessOrEqual(t, e.Stats().Queued, QueueSize)
			start = time.Now()
			e.Close()
			e.Close()
			require.Less(t, time.Since(start), FlushTimeout+time.Second)
			s := e.Stats()
			require.Equal(t, uint64(1000), s.Dropped)
			require.Zero(t, s.Emitted)
			require.Positive(t, s.OutputErrors)
			registry := prometheus.NewRegistry()
			require.NoError(t, registry.Register(e))
			families, err := registry.Gather()
			require.NoError(t, err)
			require.Len(t, families, 6)
		})
	}
}

func TestConcurrentClose(t *testing.T) {
	e, err := New(&memorySink{})
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				e.Begin("svc", "GET", "").Record(Detail{Kind: "l402.authorization", Outcome: "accepted", Reason: "accepted"})
			}
			e.Close()
		}()
	}
	wg.Wait()
	s := e.Stats()
	require.Equal(t, uint64(2000), s.Emitted+s.Dropped)
}
