package baseline

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

var known = []string{"SSH-001", "SSH-003", "SSH-008", "USER-001"}

func TestParseValid(t *testing.T) {
	input := `
version: 1
name: "Web servers"
rules:
  - SSH-001
  - SSH-003
  - SSH-008
exclude:
  - rule: SSH-008
    reason: "X11 forwarding is required for the legacy admin tool"
severity_overrides:
  SSH-003: high
`
	b, err := Parse([]byte(input), "web.yaml", known)
	if err != nil {
		t.Fatal(err)
	}
	if b.Name != "Web servers" || b.Source != "web.yaml" || len(b.Rules) != 3 {
		t.Errorf("baseline = %+v", b)
	}
	if !strings.Contains(b.Exclusions["SSH-008"], "legacy admin tool") {
		t.Errorf("exclusions = %v", b.Exclusions)
	}
	if b.SeverityOverrides["SSH-003"] != model.SeverityHigh {
		t.Errorf("overrides = %v", b.SeverityOverrides)
	}
}

func TestParseMinimal(t *testing.T) {
	b, err := Parse([]byte("version: 1\n"), "min.yaml", known)
	if err != nil {
		t.Fatal(err)
	}
	if b.Rules != nil || b.Name != "min.yaml" {
		t.Errorf("baseline = %+v", b)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty document", "", "empty"},
		{"missing version", "name: x\n", "unsupported version 0"},
		{"future version", "version: 2\n", "unsupported version 2"},
		{"unknown field (typo)", "version: 1\nexlude: []\n", "field exlude not found"},
		{"unknown rule", "version: 1\nrules: [SSH-999]\n", `unknown rule ID "SSH-999"`},
		{"duplicate rule", "version: 1\nrules: [SSH-001, SSH-001]\n", "duplicate"},
		{"empty rule list", "version: 1\nrules: []\n", "list is empty"},
		{"exclusion without reason", "version: 1\nexclude:\n  - rule: SSH-001\n", "needs a reason"},
		{"exclusion of unselected rule", "version: 1\nrules: [SSH-001]\nexclude:\n  - rule: SSH-003\n    reason: x\n", "not selected"},
		{"exclusion listed twice", "version: 1\nexclude:\n  - {rule: SSH-001, reason: a}\n  - {rule: SSH-001, reason: b}\n", "listed twice"},
		{"bad severity", "version: 1\nseverity_overrides:\n  SSH-001: urgent\n", "unknown severity"},
		{"override unknown rule", "version: 1\nseverity_overrides:\n  NOPE-001: low\n", "unknown rule ID"},
		{"wrong type", "version: one\n", "cannot unmarshal"},
		{"multiple documents", "version: 1\n---\nversion: 1\n", "exactly one YAML document"},
		{"not yaml", "{{{", "baseline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.input), "bad.yaml", known)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want mention of %q", err, tt.want)
			}
		})
	}
}

func TestParseReportsAllProblemsDeterministically(t *testing.T) {
	input := "version: 1\nseverity_overrides:\n  B-001: low\n  A-001: low\n"
	_, err1 := Parse([]byte(input), "x.yaml", known)
	_, err2 := Parse([]byte(input), "x.yaml", known)
	if err1 == nil || err1.Error() != err2.Error() || !strings.Contains(err1.Error(), "A-001") || !strings.Contains(err1.Error(), "B-001") {
		t.Fatalf("errors = %v / %v", err1, err2)
	}
}

// aliasBomb builds a "billion laughs" document whose full expansion has
// 10^levels elements.
func aliasBomb(levels int) string {
	var b strings.Builder
	b.WriteString("a0: &a0 [x,x,x,x,x,x,x,x,x,x]\n")
	for i := 1; i < levels; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [", i, i)
		for j := range 10 {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		b.WriteString("]\n")
	}
	return b.String()
}

// TestParseAliasBombs is a regression test for the property that hostile
// alias structures fail fast. Two layers provide it: the parser never
// decodes attacker-shaped data into dynamic types, and go-yaml itself
// rejects documents with excessive aliasing.
func TestParseAliasBombs(t *testing.T) {
	tests := map[string]string{
		// The strict schema has no field that accepts nested data, so the
		// aliases are never expanded; the unknown fields are rejected.
		"in the baseline document": "version: 1\n" + aliasBomb(12),
		// A trailing document is inspected as a yaml.Node, which does not
		// expand aliases.
		"as a trailing document": "version: 1\n---\n" + aliasBomb(12),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := Parse([]byte(input), "bomb.yaml", known)
			if err == nil {
				t.Fatal("expected an error")
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("parsing took %s; aliases were probably expanded", elapsed)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Run("size limit", func(t *testing.T) {
		fsys := platformtest.NewFS().Add("/b.yaml", platformtest.File{Data: make([]byte, MaxFileSize+1)})
		_, err := Load(fsys, "/b.yaml", known, false)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		fsys := platformtest.NewFS().Add("/b.yaml", platformtest.File{Err: fs.ErrPermission})
		if _, err := Load(fsys, "/b.yaml", known, false); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := Load(platform.OSFS{}, t.TempDir(), known, false); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("elevated audit refuses writable baseline", func(t *testing.T) {
		body := []byte("version: 1\n")
		tests := []struct {
			name    string
			file    platformtest.File
			wantErr bool
		}{
			{"world-writable", platformtest.File{Data: body, Mode: 0o666, UID: 1000}, true},
			{"group-writable", platformtest.File{Data: body, Mode: 0o664, UID: 0}, true},
			{"owner-only write", platformtest.File{Data: body, Mode: 0o644, UID: 1000}, false},
			{"ownership unknown (Windows)", platformtest.File{Data: body, Mode: 0o666, UID: -1}, false},
		}
		for _, tt := range tests {
			fsys := platformtest.NewFS().Add("/b.yaml", tt.file)
			_, err := Load(fsys, "/b.yaml", known, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: err = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			if _, err := Load(fsys, "/b.yaml", known, false); err != nil {
				t.Errorf("%s: unprivileged load must not check permissions: %v", tt.name, err)
			}
		}
	})
	t.Run("real file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "b.yaml")
		if err := os.WriteFile(p, []byte("version: 1\nrules: [USER-001]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := Load(platform.OSFS{}, p, known, false)
		if err != nil || len(b.Rules) != 1 {
			t.Fatalf("b = %+v, err = %v", b, err)
		}
	})
}
