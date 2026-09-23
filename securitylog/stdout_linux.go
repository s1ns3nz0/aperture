//go:build linux

package securitylog

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type pipeSink struct{ fd int }

func openStdout() (Sink, error) { return openPipe(os.Stdout.Fd()) }

func openPipe(stdout uintptr) (Sink, error) {
	// Reopen, do NOT dup: dup shares the original open-file description
	// and changing its O_NONBLOCK flag would affect ordinary logs too.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", stdout),
		unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("securitylog: cannot open nonblocking stdout pipe")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		_ = unix.Close(fd)
		return nil, errors.New("securitylog: enabled output requires a Linux stdout pipe (no TTY or regular file)")
	}
	return &pipeSink{fd}, nil
}

func (p *pipeSink) TryWrite(b []byte) error {
	if len(b) > MaxEventSize {
		return errors.New("securitylog: oversized event")
	}
	n, err := unix.Write(p.fd, b)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return ErrWouldBlock
	}
	if err != nil {
		return err
	}
	if n != len(b) {
		return errors.New("securitylog: incomplete atomic write")
	}
	return nil
}

func (p *pipeSink) Close() error { return unix.Close(p.fd) }
