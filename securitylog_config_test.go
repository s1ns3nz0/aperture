package aperture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/goccy/go-yaml"
	flags "github.com/jessevdk/go-flags"
	"github.com/lightninglabs/aperture/securitylog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestSecurityLogConfiguration(t *testing.T) {
	cfg := NewConfig()
	require.False(t, cfg.SecurityLog.Enabled)
	require.NoError(t, yaml.Unmarshal([]byte("securitylog:\n  enabled: true\n  keyfile: /mounted/key\n  keyid: v2\n"), cfg))
	require.True(t, cfg.SecurityLog.Enabled)
	require.Equal(t, "/mounted/key", cfg.SecurityLog.KeyFile)
	require.Equal(t, "v2", cfg.SecurityLog.KeyID)
	cfg = NewConfig()
	_, err := flags.ParseArgs(cfg, []string{"--securitylog.enabled", "--securitylog.keyfile=/mounted/key", "--securitylog.keyid=v3"})
	require.NoError(t, err)
	require.True(t, cfg.SecurityLog.Enabled)
	require.Equal(t, "v3", cfg.SecurityLog.KeyID)
	// Validation occurs before startup can contact a database or node.
	err = NewAperture(cfg).Start(make(chan error), make(chan struct{}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "securitylog:")
	require.NotContains(t, err.Error(), "/mounted/key")
	p := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(p, []byte("key-material-canary"), 0600))
	cfg.SecurityLog.KeyFile = p
	err = NewAperture(cfg).Start(make(chan error), make(chan struct{}))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "key-material-canary")
	cfg.SecurityLog.Enabled = false
	key, err := cfg.SecurityLog.LoadKey()
	require.NoError(t, err)
	require.Nil(t, key)
}

type blockedConsoleSink struct{}

func (blockedConsoleSink) TryWrite([]byte) error { return securitylog.ErrWouldBlock }
func (blockedConsoleSink) Close() error          { return nil }

func TestSecurityLogBoundedApplicationConsole(t *testing.T) {
	e, err := securitylog.New(bytes.Repeat([]byte{1}, 32), "test", blockedConsoleSink{})
	require.NoError(t, err)
	cfg := NewConfig()
	cfg.Logging.File.Disable = true
	handlers := boundedLogHandlers(cfg.Logging, e)
	require.Len(t, handlers, 1)
	logger := btclog.NewSLogger(handlers[0])
	logger.SetLevel(btclog.LevelDebug)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		logger.Debugf("existing debug statement %d", i)
		e.Begin("svc", "GET", "").Record(securitylog.Detail{Kind: "l402.authorization", Outcome: "accepted", Reason: "accepted"})
	}
	logger.Info(strings.Repeat("oversized", 1000))
	require.Less(t, time.Since(start), time.Second)
	start = time.Now()
	e.Close()
	require.Less(t, time.Since(start), securitylog.FlushTimeout+time.Second)
	r := prometheus.NewRegistry()
	require.NoError(t, r.Register(e))
	metrics, err := r.Gather()
	require.NoError(t, err)
	var dropped float64
	for _, m := range metrics {
		if m.GetName() == "aperture_securitylog_console_dropped_total" {
			dropped = m.Metric[0].Counter.GetValue()
		}
	}
	require.Equal(t, float64(1001), dropped)
	require.Equal(t, uint64(1000), e.Stats().Dropped)
}
