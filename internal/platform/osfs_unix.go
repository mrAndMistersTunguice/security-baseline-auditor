//go:build unix

package platform

import (
	"io/fs"
	"os"
	"syscall"
)

// openNoBlock opens name read-only with O_NONBLOCK so that opening a FIFO
// returns immediately instead of waiting for a writer. O_NONBLOCK has no
// effect on reads from regular files.
func openNoBlock(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func ownership(info fs.FileInfo) (uid, gid int64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Uid), int64(st.Gid)
	}
	return -1, -1
}

func isElevated() bool {
	return os.Geteuid() == 0
}
