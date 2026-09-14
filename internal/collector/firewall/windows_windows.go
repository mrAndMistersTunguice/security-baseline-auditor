//go:build windows

package firewall

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

const (
	localPolicyKey = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	groupPolicyKey = `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
)

// CollectWindows reads Windows Defender Firewall profile settings from the
// registry (Group Policy values take precedence over local ones) and the
// state of the MpsSvc service. Settings delivered through MDM are not read.
func CollectWindows() model.Section[model.Firewall] {
	profiles := []WindowsProfile{
		readProfile("Domain", "DomainProfile", "DomainProfile"),
		readProfile("Private", "StandardProfile", "PrivateProfile"),
		readProfile("Public", "PublicProfile", "PublicProfile"),
	}
	provider := EvaluateWindows(profiles, queryService("MpsSvc"))
	return model.CollectedSection(model.Firewall{Providers: []model.FirewallProvider{provider}})
}

func readProfile(name, localSubkey, policySubkey string) WindowsProfile {
	return WindowsProfile{
		Name:   name,
		Policy: readDWORD(groupPolicyKey+policySubkey, "EnableFirewall"),
		Local:  readDWORD(localPolicyKey+localSubkey, "EnableFirewall"),
	}
}

func readDWORD(path, value string) *uint64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, typ, err := k.GetIntegerValue(value)
	if err != nil || typ != registry.DWORD {
		return nil
	}
	return &v
}

func queryService(name string) ServiceState {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return ServiceState{Detail: fmt.Sprintf("cannot connect to service manager: %v", err)}
	}
	defer windows.CloseServiceHandle(scm)

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ServiceState{Detail: err.Error()}
	}
	svc, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return ServiceState{Known: true, Running: false, Detail: "service does not exist"}
		}
		return ServiceState{Detail: fmt.Sprintf("cannot open service: %v", err)}
	}
	defer windows.CloseServiceHandle(svc)

	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err = windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	if err != nil {
		return ServiceState{Detail: fmt.Sprintf("cannot query service status: %v", err)}
	}
	running := status.CurrentState == windows.SERVICE_RUNNING
	return ServiceState{Known: true, Running: running, Detail: serviceStateName(status.CurrentState)}
}

func serviceStateName(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "start pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop pending"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_PAUSED:
		return "paused"
	default:
		return fmt.Sprintf("state %d", state)
	}
}
