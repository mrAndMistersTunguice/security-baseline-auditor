package firewall

import (
	"fmt"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

// WindowsProfile holds the EnableFirewall values for one firewall profile.
// A nil pointer means the registry value is absent.
type WindowsProfile struct {
	Name string
	// Policy is the Group Policy value, which takes precedence.
	Policy *uint64
	// Local is the locally configured value.
	Local *uint64
}

// ServiceState describes the Windows Firewall service (MpsSvc).
type ServiceState struct {
	Known   bool
	Running bool
	Detail  string
}

// EvaluateWindows combines profile settings and service state into a
// provider. The result is authoritative only for Windows Defender Firewall;
// third-party firewalls are not detected.
func EvaluateWindows(profiles []WindowsProfile, svc ServiceState) model.FirewallProvider {
	p := model.FirewallProvider{Name: "Windows Defender Firewall", State: model.FirewallUnknown}

	unknown := false
	disabled := false
	for _, prof := range profiles {
		var v *uint64
		source := ""
		switch {
		case prof.Policy != nil:
			v, source = prof.Policy, "Group Policy"
		case prof.Local != nil:
			v, source = prof.Local, "local setting"
		}
		if v == nil {
			unknown = true
			p.Evidence = append(p.Evidence, prof.Name+" profile: EnableFirewall not set in registry")
			continue
		}
		state := "enabled"
		if *v == 0 {
			state = "disabled"
			disabled = true
		}
		p.Evidence = append(p.Evidence, fmt.Sprintf("%s profile: %s (%s, EnableFirewall=%d)", prof.Name, state, source, *v))
	}

	switch {
	case !svc.Known:
		p.Evidence = append(p.Evidence, "firewall service (MpsSvc) state unknown: "+svc.Detail)
	case svc.Running:
		p.Evidence = append(p.Evidence, "firewall service (MpsSvc) is running")
	default:
		p.Evidence = append(p.Evidence, "firewall service (MpsSvc) is not running: "+svc.Detail)
	}

	switch {
	case svc.Known && !svc.Running:
		p.State, p.Authoritative, p.RuntimeVerified = model.FirewallDisabled, true, true
	case disabled && svc.Known:
		p.State, p.Authoritative, p.RuntimeVerified = model.FirewallDisabled, true, true
	case !unknown && svc.Known && svc.Running:
		p.State, p.Authoritative, p.RuntimeVerified = model.FirewallEnabled, true, true
	}
	return p
}
