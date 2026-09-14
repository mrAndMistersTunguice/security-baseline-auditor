//go:build !unix && !windows

package platform

import (
	"io/fs"
	"os"
)

func openNoBlock(name string) (*os.File, error) {
	return os.Open(name)
}

func ownership(fs.FileInfo) (uid, gid int64) {
	return -1, -1
}

func isElevated() bool {
	return false
}
