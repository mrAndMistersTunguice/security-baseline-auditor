package firewall

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

const (
	procRoot       = "/proc"
	ufwConfPath    = "/etc/ufw/ufw.conf"
	firewalldConf  = "/etc/firewalld/firewalld.conf"
	maxProcesses   = 200_000
	maxProcFile    = 16 << 10
	legacyV4Tables = "/proc/net/ip_tables_names"
	legacyV6Tables = "/proc/net/ip6_tables_names"
)

// nftCandidates are absolute locations of the nft binary. PATH is never
// consulted, so a manipulated PATH cannot redirect execution.
var nftCandidates = []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"}

// CollectLinux gathers firewall evidence from the kernel ruleset (via nft,
// root only), the firewalld daemon and ufw configuration.
func CollectLinux(ctx context.Context, env platform.Env) model.Section[model.Firewall] {
	var fw model.Firewall
	var warnings []string

	fw.Providers = append(fw.Providers, nftablesProvider(ctx, env))

	if p, ok, warn := firewalldProvider(env); ok {
		fw.Providers = append(fw.Providers, p)
	} else if warn != "" {
		warnings = append(warnings, warn)
	}
	if p, ok := ufwProvider(env.FS); ok {
		fw.Providers = append(fw.Providers, p)
	}

	sec := model.CollectedSection(fw)
	sec.Warnings = warnings
	return sec
}

func nftablesProvider(ctx context.Context, env platform.Env) model.FirewallProvider {
	p := model.FirewallProvider{Name: "nftables kernel ruleset", State: model.FirewallUnknown}
	if !env.Elevated {
		p.Evidence = []string{"inspecting the kernel ruleset requires root (CAP_NET_ADMIN); not attempted"}
		return p
	}

	bin := ""
	for _, c := range nftCandidates {
		if _, err := env.FS.Stat(c); err == nil {
			bin = c
			break
		}
	}
	if bin == "" {
		p.Evidence = []string{"nft binary not found in " + strings.Join(nftCandidates, ", ")}
		return p
	}

	out, err := env.Runner.Run(ctx, bin, "-j", "list", "ruleset")
	if err != nil {
		p.Evidence = []string{fmt.Sprintf("%s -j list ruleset failed: %v", bin, err)}
		return p
	}
	analysis, err := AnalyzeRuleset(out)
	if err != nil {
		p.Evidence = []string{fmt.Sprintf("cannot parse nft JSON output: %v", err)}
		return p
	}
	p.RuntimeVerified = true
	p.Evidence = append(p.Evidence, fmt.Sprintf("%d input base chain(s) inspected with %s", analysis.InputChains, bin))

	if len(analysis.Filtering) > 0 {
		p.State = model.FirewallEnabled
		p.Authoritative = true
		p.Evidence = append(p.Evidence, analysis.Filtering...)
		return p
	}

	// No filtering in nftables. Rules loaded through the legacy iptables
	// interface are invisible to nft, so the result is only conclusive if
	// no legacy tables are loaded.
	legacy, legacyErr := legacyTables(env.FS)
	switch {
	case legacyErr != nil:
		p.Evidence = append(p.Evidence, "no drop/reject reachable from input chains; legacy iptables state could not be checked: "+legacyErr.Error())
	case len(legacy) > 0:
		p.Evidence = append(p.Evidence, "no drop/reject reachable from nftables input chains, but legacy iptables tables are loaded and were not inspected: "+strings.Join(legacy, ", "))
	default:
		p.State = model.FirewallDisabled
		p.Authoritative = true
		p.Evidence = append(p.Evidence, "no drop or reject verdict reachable from any input chain; no legacy iptables tables loaded")
	}
	return p
}

// legacyTables lists loaded legacy x_tables. Missing files mean the legacy
// modules are not loaded.
func legacyTables(fsys platform.FS) ([]string, error) {
	var names []string
	for _, p := range []string{legacyV4Tables, legacyV6Tables} {
		data, err := fsys.ReadFile(p, maxProcFile)
		if err != nil {
			if platform.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, n := range strings.Fields(string(data)) {
			names = append(names, strings.TrimSuffix(p[strings.LastIndex(p, "/")+1:], "_tables_names")+":"+n)
		}
	}
	return names, nil
}

// firewalldProvider looks for a running firewalld owned by root. Only a
// root-owned process counts, because any user can start a process named
// "firewalld".
func firewalldProvider(env platform.Env) (model.FirewallProvider, bool, string) {
	p := model.FirewallProvider{Name: "firewalld"}
	pid, err := findRootProcess(env.FS, "firewalld")
	if err != nil {
		return p, false, "process scan failed: " + err.Error()
	}
	if pid != 0 {
		p.State = model.FirewallEnabled
		p.RuntimeVerified = true
		p.Evidence = []string{fmt.Sprintf("firewalld is running as root (pid %d)", pid)}
		return p, true, ""
	}
	if _, err := env.FS.Stat(firewalldConf); err != nil {
		return p, false, "" // not installed
	}
	p.State = model.FirewallUnknown
	p.Evidence = []string{"firewalld is installed but no running root-owned firewalld process was observed"}
	if env.Elevated {
		// Root sees all processes, even with procfs hidepid.
		p.State = model.FirewallDisabled
		p.RuntimeVerified = true
	}
	return p, true, ""
}

var errTooManyProcesses = errors.New("too many processes")

// findRootProcess returns the pid of a process with the given comm owned by
// real UID 0, or 0 if none is visible.
func findRootProcess(fsys platform.FS, comm string) (int, error) {
	entries, err := fsys.ReadDirNames(procRoot)
	if err != nil {
		return 0, err
	}
	if len(entries) > maxProcesses {
		return 0, errTooManyProcesses
	}
	for _, name := range entries {
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}
		// Processes may exit during the scan; errors are ignored.
		data, err := fsys.ReadFile(procRoot+"/"+name+"/comm", maxProcFile)
		if err != nil || strings.TrimSpace(string(data)) != comm {
			continue
		}
		status, err := fsys.ReadFile(procRoot+"/"+name+"/status", maxProcFile)
		if err != nil {
			continue
		}
		if uid, ok := realUID(status); ok && uid == 0 {
			return pid, nil
		}
	}
	return 0, nil
}

func realUID(status []byte) (int, bool) {
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.Atoi(fields[0])
		return uid, err == nil
	}
	return 0, false
}

func ufwProvider(fsys platform.FS) (model.FirewallProvider, bool) {
	data, err := fsys.ReadFile(ufwConfPath, maxProcFile)
	if err != nil {
		return model.FirewallProvider{}, false
	}
	p := model.FirewallProvider{Name: "ufw", State: model.FirewallUnknown}
	enabled, found := ParseUFWEnabled(data)
	switch {
	case !found:
		p.Evidence = []string{ufwConfPath + " has no ENABLED setting"}
	case enabled:
		p.State = model.FirewallEnabled
		p.Evidence = []string{ufwConfPath + ": ENABLED=yes (configuration only; runtime state not verified)"}
	default:
		p.State = model.FirewallDisabled
		p.Evidence = []string{ufwConfPath + ": ENABLED=no"}
	}
	return p, true
}
