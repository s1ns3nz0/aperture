package aperture

import (
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/aperture/admin"
	"github.com/lightninglabs/aperture/auth"
	"github.com/lightninglabs/aperture/challenger"
	"github.com/lightninglabs/aperture/l402"
	"github.com/lightninglabs/aperture/mint"
	"github.com/lightninglabs/aperture/mpp"
	"github.com/lightninglabs/aperture/proxy"
	"github.com/lightninglabs/aperture/securitylog"
	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
)

const Subsystem = "APER"

// boundedLogHandlers preserves the application's logging options but shares
// the bounded stdout transport when security logging is enabled. Otherwise a
// blocked console logger could stall authentication despite the event queue.
func boundedLogHandlers(cfg *build.LogConfig, events *securitylog.Emitter) []btclog.Handler {
	var handlers []btclog.Handler
	switch build.LoggingType {
	case build.LogTypeStdOut, build.LogTypeDefault:
		if !cfg.Console.Disable {
			handlers = append(handlers, btclog.NewDefaultHandler(events.ConsoleWriter(), cfg.Console.HandlerOptions()...))
		}
	}
	if build.LoggingType == build.LogTypeDefault && !cfg.File.Disable {
		handlers = append(handlers, btclog.NewDefaultHandler(logWriter, cfg.File.HandlerOptions()...))
	}
	return handlers
}

var (
	logWriter = build.NewRotatingLogWriter()
	log       = build.NewSubLogger(Subsystem, nil)
)

// SetupLoggers initializes all package-global logger variables.
func SetupLoggers(root *build.SubLoggerManager, intercept signal.Interceptor) {
	genLogger := genSubLogger(root, intercept)

	log = build.NewSubLogger(Subsystem, genLogger)

	lnd.SetSubLogger(root, Subsystem, log)
	lnd.AddSubLogger(root, auth.Subsystem, intercept, auth.UseLogger)
	lnd.AddSubLogger(root, l402.Subsystem, intercept, l402.UseLogger)
	lnd.AddSubLogger(root, mint.Subsystem, intercept, mint.UseLogger)
	lnd.AddSubLogger(root, proxy.Subsystem, intercept, proxy.UseLogger)
	lnd.AddSubLogger(root, "LNDC", intercept, lndclient.UseLogger)
	lnd.AddSubLogger(
		root, challenger.Subsystem, intercept, challenger.UseLogger,
	)
	lnd.AddSubLogger(
		root, admin.Subsystem, intercept, admin.UseLogger,
	)
	lnd.AddSubLogger(root, mpp.Subsystem, intercept, mpp.UseLogger)
}

// genSubLogger creates a logger for a subsystem. We provide an instance of
// a signal.Interceptor to be able to shutdown in the case of a critical error.
func genSubLogger(root *build.SubLoggerManager,
	interceptor signal.Interceptor) func(string) btclog.Logger {

	// Create a shutdown function which will request shutdown from our
	// interceptor if it is listening.
	shutdown := func() {
		if !interceptor.Listening() {
			return
		}

		interceptor.RequestShutdown()
	}

	// Return a function which will create a sublogger from our root
	// logger without shutdown fn.
	return func(tag string) btclog.Logger {
		return root.GenSubLogger(tag, shutdown)
	}
}
