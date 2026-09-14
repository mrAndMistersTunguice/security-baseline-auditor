package sshd

import (
	"errors"
	"strings"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

// FuzzLoad checks that arbitrary configuration content never panics, never
// hangs on self-includes and only fails with the documented error classes.
func FuzzLoad(f *testing.F) {
	for _, seed := range []string{
		"PermitRootLogin yes\n",
		"Include /etc/ssh/sshd_config\n",
		"Match User a\n\tInclude x/*.conf\nMatch all\nPasswordAuthentication=no\n",
		"Banner \"unterminated\n",
		"Ciphers '+aes256-cbc' # comment\n",
		"=\n\"\n\\\n#\n",
		"Include /etc/ssh/[\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		fsys := platformtest.NewFS().
			AddText("/etc/ssh/sshd_config", content).
			AddText("/etc/ssh/x/a.conf", content)
		cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if err != nil {
			if !errors.Is(err, ErrSyntax) && !errors.Is(err, ErrLimit) && !strings.Contains(err.Error(), "Include") {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		for _, d := range cfg.Directives {
			if len(d.Args) == 0 || !knownKeywords[d.Keyword] {
				t.Fatalf("invalid directive stored: %+v", d)
			}
		}
	})
}
