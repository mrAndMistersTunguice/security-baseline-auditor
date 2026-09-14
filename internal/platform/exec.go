package platform

import (
	"bytes"
	"time"
)

const (
	// MaxCommandOutput caps the standard output captured from a command.
	MaxCommandOutput = 16 << 20
	maxCommandStderr = 64 << 10
	// DefaultCommandTimeout bounds a single command when the caller's
	// context has no earlier deadline.
	DefaultCommandTimeout = 15 * time.Second
)

// ExecRunner runs programs directly via execve (never through a shell), with
// a fixed minimal environment, a timeout and bounded output. On non-Unix
// platforms it refuses to run anything; no collector needs it there.
type ExecRunner struct{}

// limitedBuffer stores up to limit bytes and records whether more were
// written. It never returns an error so the child process is not killed by
// SIGPIPE; the overflow flag is checked after the command exits.
type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.Len(); remaining < len(p) {
		b.overflow = true
		if remaining > 0 {
			b.Buffer.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}
