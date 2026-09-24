package securitylog

// Config controls the keyless security event stream.
type Config struct {
	Enabled bool `long:"enabled" description:"Emit structured L402 security events to Linux stdout pipe"`
}

// Open opens an independent nonblocking stdout pipe description when enabled.
// It never changes the ordinary logger's file flags.
func Open(c *Config) (*Emitter, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	sink, err := openStdout()
	if err != nil {
		return nil, err
	}
	e, err := New(sink)
	if err != nil {
		_ = sink.Close()
	}
	return e, err
}
