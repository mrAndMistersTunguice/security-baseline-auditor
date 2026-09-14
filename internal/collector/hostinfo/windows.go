package hostinfo

import (
	"strconv"
	"strings"
)

// WindowsProductName corrects the registry ProductName, which still reads
// "Windows 10 ..." on Windows 11. Microsoft identifies Windows 11 by build
// number 22000 or later.
func WindowsProductName(productName, currentBuild string) string {
	build, err := strconv.Atoi(currentBuild)
	if err == nil && build >= 22000 && strings.HasPrefix(productName, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(productName, "Windows 10")
	}
	return productName
}
