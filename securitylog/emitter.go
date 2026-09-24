package securitylog

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	QueueSize    = 256
	MaxEventSize = 4096 // Linux PIPE_BUF, including the newline.
	WriteTimeout = 100 * time.Millisecond
	FlushTimeout = 250 * time.Millisecond
)

// ErrWouldBlock requests a bounded retry, not an unbounded blocking write.
var ErrWouldBlock = errors.New("securitylog: output busy")

// Sink must complete TryWrite and Close without blocking. TryWrite writes a
// whole line atomically or returns an error without writing any bytes.
// Production uses only the checked, nonblocking Linux pipe implementation.
type Sink interface {
	TryWrite([]byte) error
	Close() error
}

type queued struct {
	line    []byte
	at      time.Time
	console bool
}

// Emitter owns one fixed queue and one interruptible writer. Submitters never
// wait for output. Close is idempotent and flushes for at most FlushTimeout.
type Emitter struct {
	sink                           Sink
	queue                          chan queued
	stop, done                     chan struct{}
	mu                             sync.RWMutex
	closed                         bool
	stopAt                         time.Time
	emitted, dropped, outputErrors atomic.Uint64
	consoleDropped                 atomic.Uint64
	delay                          prometheus.Histogram
}

func New(sink Sink) (*Emitter, error) {
	if sink == nil {
		return nil, errors.New("securitylog: invalid emitter configuration")
	}
	e := &Emitter{sink: sink, queue: make(chan queued, QueueSize),
		stop: make(chan struct{}), done: make(chan struct{}),
		delay: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "aperture_securitylog_delay_seconds", Help: "Queue and output delay until delivery or loss.",
			Buckets: []float64{.001, .01, .1, .25, 1, 5, 30},
		}),
	}
	go e.run()
	return e, nil
}

func (e *Emitter) emit(event Event) {
	line, err := json.Marshal(event)
	if err != nil || len(line)+1 > MaxEventSize {
		e.dropped.Add(1)
		return
	}
	line = append(line, '\n')
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		e.dropped.Add(1)
		return
	}
	select {
	case e.queue <- queued{line: line, at: time.Now()}:
	default:
		e.dropped.Add(1)
	}
}

type consoleWriter struct{ emitter *Emitter }

// ConsoleWriter bounds the existing console logger's stdout writes when the
// feature is enabled. Contents and severity remain unchanged. Oversized or
// undeliverable ordinary log lines are dropped, separately counted, not split
// across writes that could interleave with a JSON security event.
func (e *Emitter) ConsoleWriter() io.Writer { return consoleWriter{e} }

func (w consoleWriter) Write(b []byte) (int, error) {
	e := w.emitter
	if len(b) > MaxEventSize {
		e.consoleDropped.Add(1)
		return len(b), nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		e.consoleDropped.Add(1)
		return len(b), nil
	}
	q := queued{line: append([]byte(nil), b...), at: time.Now(), console: true}
	select {
	case e.queue <- q:
	default:
		e.consoleDropped.Add(1)
	}
	return len(b), nil
}

func (e *Emitter) drop(q queued) {
	if q.console {
		e.consoleDropped.Add(1)
	} else {
		e.dropped.Add(1)
	}
}

func (e *Emitter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		e.stopAt = time.Now().Add(FlushTimeout)
		close(e.stop)
	}
	e.mu.Unlock()
	<-e.done
}

func (e *Emitter) expired() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.closed && !time.Now().Before(e.stopAt)
}

func (e *Emitter) run() {
	defer close(e.done)
	defer e.sink.Close()
	for {
		if e.expired() {
			for {
				select {
				case q := <-e.queue:
					e.drop(q)
					e.delay.Observe(time.Since(q.at).Seconds())
				default:
					return
				}
			}
		}
		var q queued
		select {
		case q = <-e.queue:
		case <-e.stop:
			select {
			case q = <-e.queue:
			default:
				return
			}
		}
		deadline := time.Now().Add(WriteTimeout)
		for {
			err := e.sink.TryWrite(q.line)
			if err == nil {
				if !q.console {
					e.emitted.Add(1)
				}
				break
			}
			if !errors.Is(err, ErrWouldBlock) || !time.Now().Before(deadline) || e.expired() {
				e.outputErrors.Add(1)
				e.drop(q)
				break
			}
			// Only this bounded worker waits; requests never do.
			time.Sleep(time.Millisecond)
		}
		e.delay.Observe(time.Since(q.at).Seconds())
	}
}

// Stats remains observable even when stdout is permanently blocked.
type Stats struct {
	Emitted, Dropped, OutputErrors uint64
	Queued                         int
}

func (e *Emitter) Stats() Stats {
	return Stats{e.emitted.Load(), e.dropped.Load(), e.outputErrors.Load(), len(e.queue)}
}

var health = []*prometheus.Desc{
	prometheus.NewDesc("aperture_securitylog_emitted_total", "Events written to stdout; not an acknowledgement from a collector.", nil, nil),
	prometheus.NewDesc("aperture_securitylog_dropped_total", "Events lost due to saturation, invalid fields, output failure or shutdown.", nil, nil),
	prometheus.NewDesc("aperture_securitylog_output_errors_total", "Failed or timed out event writes.", nil, nil),
	prometheus.NewDesc("aperture_securitylog_queue_depth", "Events waiting in the bounded output queue.", nil, nil),
	prometheus.NewDesc("aperture_securitylog_console_dropped_total", "Ordinary console writes dropped by the bounded stdout transport.", nil, nil),
}

func (e *Emitter) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range health {
		ch <- d
	}
	e.delay.Describe(ch)
}

func (e *Emitter) Collect(ch chan<- prometheus.Metric) {
	s := e.Stats()
	values := []float64{float64(s.Emitted), float64(s.Dropped), float64(s.OutputErrors), float64(s.Queued), float64(e.consoleDropped.Load())}
	for i, v := range values {
		kind := prometheus.CounterValue
		if i == 3 {
			kind = prometheus.GaugeValue
		}
		ch <- prometheus.MustNewConstMetric(health[i], kind, v)
	}
	e.delay.Collect(ch)
}
