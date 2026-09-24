package aperture

import (
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
	require.NoError(t, yaml.Unmarshal([]byte("securitylog:\n  enabled: true\n"), cfg))
	require.True(t, cfg.SecurityLog.Enabled)
	cfg = NewConfig()
	_, err := flags.ParseArgs(cfg, []string{"--securitylog.enabled"})
	require.NoError(t, err)
	require.True(t, cfg.SecurityLog.Enabled)
	// Old key flags must not silently imply keyed correlation.
	for _, flag := range []string{"--securitylog.keyfile=/mounted/key", "--securitylog.keyid=v1"} {
		_, err := flags.ParseArgs(NewConfig(), []string{flag})
		require.Error(t, err)
	}
}

type blockedConsoleSink struct{}

func (blockedConsoleSink) TryWrite([]byte) error { return securitylog.ErrWouldBlock }
func (blockedConsoleSink) Close() error          { return nil }

func TestSecurityLogBoundedApplicationConsole(t *testing.T) {
	e, err := securitylog.New(blockedConsoleSink{})
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
