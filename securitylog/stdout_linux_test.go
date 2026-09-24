//go:build linux

package securitylog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPipeBlockedAndClosed(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	before, err := unix.FcntlInt(w.Fd(), unix.F_GETFL, 0)
	require.NoError(t, err)
	sink, err := openPipe(w.Fd())
	require.NoError(t, err)
	after, err := unix.FcntlInt(w.Fd(), unix.F_GETFL, 0)
	require.NoError(t, err)
	require.Equal(t, before, after)
	line := bytes.Repeat([]byte{'x'}, MaxEventSize)
	for i := 0; ; i++ {
		err = sink.TryWrite(line)
		if err != nil {
			require.ErrorIs(t, err, ErrWouldBlock)
			break
		}
		require.Less(t, i, 10000)
	}
	e, err := New(sink)
	require.NoError(t, err)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := e.ConsoleWriter().Write([]byte("ordinary console line\n"))
		require.NoError(t, err)
		e.Begin("svc", "GET", "").Record(Detail{Kind: "l402.authorization", Outcome: "accepted", Reason: "accepted"})
	}
	require.Less(t, time.Since(start), time.Second)
	start = time.Now()
	e.Close()
	require.Less(t, time.Since(start), FlushTimeout+time.Second)
	require.Equal(t, uint64(1000), e.Stats().Dropped)
	require.Equal(t, uint64(1000), e.consoleDropped.Load())
	require.Positive(t, e.Stats().OutputErrors)
	// A closed reader yields an error instead of killing the process.
	sink, err = openPipe(w.Fd())
	require.NoError(t, err)
	defer sink.Close()
	require.NoError(t, r.Close())
	require.Error(t, sink.TryWrite([]byte("{}\n")))
}

func TestPipeConcurrentAtomicJSON(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	sink, err := openPipe(w.Fd())
	require.NoError(t, err)
	e, err := New(sink)
	require.NoError(t, err)
	lines := make(chan [][]byte, 1)
	go func() {
		var out [][]byte
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			out = append(out, append([]byte(nil), scan.Bytes()...))
		}
		lines <- out
	}()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Begin("svc", "GET", "").Record(Detail{Kind: "l402.authorization", Outcome: "accepted", Reason: "accepted"})
		}()
	}
	wg.Wait()
	e.Close()
	require.NoError(t, w.Close())
	select {
	case out := <-lines:
		require.Len(t, out, 100)
		for _, line := range out {
			require.True(t, json.Valid(line))
		}
	case <-time.After(time.Second):
		t.Fatal("pipe reader did not exit")
	}
}

func TestUnsupportedStdout(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	defer f.Close()
	_, err = openPipe(f.Fd())
	require.Error(t, err)
}
