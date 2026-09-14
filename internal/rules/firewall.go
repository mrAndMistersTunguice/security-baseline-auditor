package rules

import (
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

const (
	refNftables        = "https://wiki.nftables.org/wiki-nftables/index.php/Main_Page"
	refFirewalld       = "https://firewalld.org/documentation/"
	refWindowsFirewall = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
)

func firewallRules() []Rule {
	return []Rule{
		{
			ID:    "FW-001",
			Title: "A host firewall must filter inbound traffic",
			Description: "Checks for evidence that inbound traffic is filtered: on Linux, a drop or reject reachable from an " +
				"nftables input chain or a running firewalld; on Windows, Windows Defender Firewall enabled for all " +
				"profiles with its service running.",
			Category: model.CategoryFirewall,
			Severity: model.SeverityHigh,
			SeverityRationale: "Without host filtering every listening service is reachable from every attached network; " +
				"on flat or cloud networks the host firewall is often the only network-level control.",
			Platforms: []string{"linux", "windows"},
			Remediation: "Linux: enable firewalld ('systemctl enable --now firewalld'), ufw ('ufw enable') or an nftables " +
				"ruleset with a default-deny input policy. Windows: enable the firewall for the Domain, Private and " +
				"Public profiles ('Set-NetFirewallProfile -All -Enabled True').",
			References: []string{refNftables, refFirewalld, refWindowsFirewall},
			Check:      checkFirewall,
		},
	}
}

// checkFirewall passes on runtime-verified enabled evidence, fails only on
// an authoritative "disabled" signal, and otherwise skips: configuration
// intent (for example ufw.conf) is reported but never treated as proof.
func checkFirewall(s *model.Snapshot) Result {
	if res, bad := unavailable("firewall state", s.Firewall); bad {
		return res
	}
	var evidence []string
	enabled, authoritativeDisabled := false, false
	for _, p := range s.Firewall.Data.Providers {
		for _, e := range p.Evidence {
			evidence = append(evidence, p.Name+": "+e)
		}
		switch {
		case p.State == model.FirewallEnabled && p.RuntimeVerified:
			enabled = true
		case p.State == model.FirewallDisabled && p.Authoritative:
			authoritativeDisabled = true
		}
	}
	for _, w := range s.Firewall.Warnings {
		evidence = append(evidence, "note: "+w)
	}
	switch {
	case enabled:
		return Pass("inbound filtering is active", evidence...)
	case authoritativeDisabled:
		return Fail("no active inbound filtering was found", evidence...)
	default:
		msg := "firewall state could not be verified"
		if !s.Host.Elevated {
			msg += " without elevated privileges"
		}
		return Skip(msg, evidence...)
	}
}
