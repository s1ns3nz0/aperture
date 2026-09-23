package securitylog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			for _, content := range []string{"", "secret-canary", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("a", 64) + strings.Repeat(" ", 1000)} {
				p := filepath.Join(t.TempDir(), "key")
				require.NoError(t, os.WriteFile(p, []byte(content), 0600))
				key, err := (&Config{Enabled: enabled, KeyFile: p}).LoadKey()
				if enabled {
					require.Error(t, err)
					require.NotContains(t, err.Error(), "secret-canary")
				} else {
					require.NoError(t, err)
					require.Nil(t, key)
				}
			}
		})
	}
	_, err := (&Config{Enabled: true}).LoadKey()
	require.Error(t, err)
	p := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(p, []byte(strings.Repeat("ab", 32)+"\n"), 0600))
	key, err := (&Config{Enabled: true, KeyFile: p, KeyID: "2026-09"}).LoadKey()
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xab}, 32), key)
	_, err = (&Config{Enabled: true, KeyFile: p, KeyID: strings.Repeat("x", 65)}).LoadKey()
	require.Error(t, err)
	e, err := Open(&Config{})
	require.NoError(t, err)
	require.Nil(t, e)
}

func TestReferencesAndBoundedFields(t *testing.T) {
	id := append([]byte{0, 0}, bytes.Repeat([]byte{7}, 64)...)
	newEmitter := func(key byte) *Emitter {
		e, err := New(bytes.Repeat([]byte{key}, 32), "key-v1", &memorySink{})
		require.NoError(t, err)
		t.Cleanup(e.Close)
		return e
	}
	e := newEmitter(1)
	c, p := e.references(id)
	c2, p2 := e.references(id)
	require.Equal(t, c, c2)
	require.Equal(t, p, p2)
	require.NotEqual(t, c, p)
	c2, p2 = newEmitter(2).references(id)
	require.NotEqual(t, c, c2)
	require.NotEqual(t, p, p2)
	for _, malformed := range [][]byte{nil, id[:65], append([]byte{1}, id...)} {
		c, p := e.references(malformed)
		require.Empty(t, c)
		require.Empty(t, p)
	}
	sink := &memorySink{}
	e, err := New(bytes.Repeat([]byte{1}, 32), "version", sink)
	require.NoError(t, err)
	tr := e.Begin(strings.Repeat("S", 100000), "METHOD-SECRET", "192.0.2.1:5000")
	tr.Record(Detail{Kind: "l402.authorization", Outcome: "denied", Reason: "invalid_signature", Identifier: id})
	tr.Record(Detail{Kind: "l402.authorization", Outcome: "denied", Reason: "error including secret-canary"})
	e.Close()
	var event Event
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(sink.Bytes()), &event))
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
	e, err := New(bytes.Repeat([]byte{3}, 32), "v1", sink)
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
			e, err := New(bytes.Repeat([]byte{1}, 32), "", &memorySink{fail: failure})
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
	e, err := New(bytes.Repeat([]byte{1}, 32), "", &memorySink{})
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
