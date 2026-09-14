//go:build windows

package platform

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func openNoBlock(name string) (*os.File, error) {
	return os.Open(name)
}

// ownership is not expressed as numeric IDs on Windows; ACL inspection is
// not implemented.
func ownership(fs.FileInfo) (uid, gid int64) {
	return -1, -1
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
