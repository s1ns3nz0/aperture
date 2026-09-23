package securitylog

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
)

// Config contains no key material. KeyFile is an operator-mounted secret.
type Config struct {
	Enabled bool   `long:"enabled" description:"Emit structured L402 security events to Linux stdout pipe"`
	KeyFile string `long:"keyfile" description:"Mounted file containing a dedicated 32-byte HMAC key encoded as 64 hex characters"`
	KeyID   string `long:"keyid" description:"Non-secret key version, at most 64 ASCII letters, digits, dots, underscores or hyphens"`
}

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)

// LoadKey validates without printing secret contents or filesystem errors.
// Disabled mode does not access the key file.
func (c *Config) LoadKey() ([]byte, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	if !keyIDPattern.MatchString(c.KeyID) {
		return nil, errors.New("securitylog: invalid key ID")
	}
	info, err := os.Stat(c.KeyFile)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("securitylog: HMAC key must be a readable regular file")
	}
	f, err := os.Open(c.KeyFile)
	if err != nil {
		return nil, errors.New("securitylog: cannot read HMAC key file")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("securitylog: HMAC key must be a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 67))
	if err != nil {
		return nil, errors.New("securitylog: cannot read HMAC key file")
	}
	if len(b) > 66 {
		return nil, errors.New("securitylog: HMAC key file too large")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) != 64 {
		return nil, errors.New("securitylog: HMAC key must be 64 hex characters")
	}
	key := make([]byte, 32)
	if _, err := hex.Decode(key, b); err != nil {
		return nil, errors.New("securitylog: invalid HMAC key encoding")
	}
	return key, nil
}

// Open validates configuration and opens an independent nonblocking stdout
// pipe description. It never changes the ordinary logger's file flags.
func Open(c *Config) (*Emitter, error) {
	key, err := c.LoadKey()
	if err != nil || key == nil {
		return nil, err
	}
	sink, err := openStdout()
	if err != nil {
		return nil, err
	}
	e, err := New(key, c.KeyID, sink)
	if err != nil {
		_ = sink.Close()
	}
	return e, err
}
