//go:build !linux

package securitylog

import "errors"

func openStdout() (Sink, error) {
	return nil, errors.New("securitylog: enabled output requires Linux")
}
