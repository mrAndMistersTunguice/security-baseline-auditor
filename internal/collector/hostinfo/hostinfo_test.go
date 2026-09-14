package hostinfo

import (
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name: "ubuntu",
			input: `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
`,
			want: map[string]string{"PRETTY_NAME": "Ubuntu 24.04.1 LTS", "NAME": "Ubuntu", "VERSION_ID": "24.04", "ID": "ubuntu", "ID_LIKE": "debian"},
		},
		{
			name:  "rhel with multiple id_like",
			input: "ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\n",
			want:  map[string]string{"ID": "rhel", "ID_LIKE": "fedora", "VERSION_ID": "9.4"},
		},
		{
			name:  "comments escapes and junk",
			input: "# comment\nNAME='Single'\nX=\"a \\\"quoted\\\" word\"\nlower=ignored\nnot a pair\n=empty\n",
			want:  map[string]string{"NAME": "Single", "X": `a "quoted" word`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseOSRelease([]byte(tt.input))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestWindowsProductName(t *testing.T) {
	tests := []struct{ product, build, want string }{
		{"Windows 10 Pro", "19045", "Windows 10 Pro"},
		{"Windows 10 Home Single Language", "26200", "Windows 11 Home Single Language"},
		{"Windows Server 2022 Standard", "20348", "Windows Server 2022 Standard"},
		{"Windows 10 Pro", "not-a-number", "Windows 10 Pro"},
	}
	for _, tt := range tests {
		if got := WindowsProductName(tt.product, tt.build); got != tt.want {
			t.Errorf("WindowsProductName(%q, %q) = %q, want %q", tt.product, tt.build, got, tt.want)
		}
	}
}

func TestCollectUnixFallback(t *testing.T) {
	fsys := platformtest.NewFS().
		AddText("/usr/lib/os-release", "ID=fedora\nPRETTY_NAME=\"Fedora Linux 40\"\n").
		AddText("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
	var host model.Host
	CollectUnix(fsys, &host)
	if host.DistroID != "fedora" || host.PrettyName != "Fedora Linux 40" || host.KernelVersion != "6.8.0-45-generic" {
		t.Fatalf("host = %+v", host)
	}
}
