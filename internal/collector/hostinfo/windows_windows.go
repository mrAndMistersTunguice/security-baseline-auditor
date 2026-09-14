//go:build windows

package hostinfo

import (
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

// CollectWindows fills version details from the registry. Failures leave
// the fields empty; they are informational.
func CollectWindows(host *model.Host) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	product, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	display, _, _ := k.GetStringValue("DisplayVersion")

	host.DistroID = "windows"
	host.PrettyName = strings.TrimSpace(WindowsProductName(product, build) + " " + display)
	host.Version = build
	host.KernelVersion = build
}
