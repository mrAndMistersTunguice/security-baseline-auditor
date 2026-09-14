package accounts

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestClassifyPassword(t *testing.T) {
	tests := map[string]model.PasswordState{
		"x":                model.PasswordShadowed,
		"":                 model.PasswordEmpty,
		"!":                model.PasswordLocked,
		"!!":               model.PasswordLocked,
		"*":                model.PasswordLocked,
		"!$6$salt$hash":    model.PasswordLocked,
		"$6$salt$hash":     model.PasswordHash,
		"$y$j9T$salt$hash": model.PasswordHash,
		"abcdefghijklm":    model.PasswordHash, // legacy DES
	}
	for field, want := range tests {
		if got := ClassifyPassword(field); got != want {
			t.Errorf("ClassifyPassword(%q) = %s, want %s", field, got, want)
		}
	}
}

func TestParsePasswd(t *testing.T) {
	users, warnings := ParsePasswd(readFixture(t, "passwd"))

	byName := map[string]model.User{}
	for _, u := range users {
		byName[u.Name] = u
	}
	if len(users) != 13 {
		t.Fatalf("parsed %d users, want 13", len(users))
	}
	if u := byName["toor"]; u.UID != 0 || u.Shell != "/bin/sh" || u.Line != 9 {
		t.Errorf("toor = %+v", u)
	}
	if byName["bob"].PasswordField != model.PasswordEmpty {
		t.Errorf("bob password field = %s", byName["bob"].PasswordField)
	}
	if byName["legacy"].PasswordField != model.PasswordHash {
		t.Errorf("legacy password field = %s", byName["legacy"].PasswordField)
	}
	if _, ok := byName["carol"]; ok {
		t.Error("entry with non-numeric UID must be skipped")
	}

	if len(warnings) != 3 {
		t.Fatalf("warnings = %q, want 3", warnings)
	}
	for _, w := range warnings {
		if strings.Contains(w, "NotARealHash") || strings.Contains(w, "carol") {
			t.Errorf("warning leaks line content: %q", w)
		}
	}
}

func TestParsePasswdMalformedInputs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantUsers int
		wantWarn  int
	}{
		{"empty", "", 0, 0},
		{"only newlines", "\n\n\r\n", 0, 0},
		{"crlf line endings", "root:x:0:0:root:/root:/bin/bash\r\n", 1, 0},
		{"too many fields", "a:x:0:0:::/bin/sh:extra\n", 0, 1},
		{"uid overflow", "a:x:4294967296:0:::/bin/sh\n", 0, 1},
		{"negative uid", "a:x:-1:0:::/bin/sh\n", 0, 1},
		{"empty name", ":x:0:0:::/bin/sh\n", 0, 1},
		{"binary garbage", "\x00\xff\xfe:::\n", 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users, warnings := ParsePasswd([]byte(tt.input))
			if len(users) != tt.wantUsers || len(warnings) != tt.wantWarn {
				t.Fatalf("users=%d warnings=%q, want %d/%d", len(users), warnings, tt.wantUsers, tt.wantWarn)
			}
		})
	}
}

func TestParseShadowDropsHashes(t *testing.T) {
	entries, warnings := ParseShadow(readFixture(t, "shadow"))
	if len(entries) != 5 || len(warnings) != 1 {
		t.Fatalf("entries=%d warnings=%q", len(entries), warnings)
	}
	want := map[string]model.PasswordState{
		"root": model.PasswordLocked, "daemon": model.PasswordLocked,
		"alice": model.PasswordHash, "bob": model.PasswordEmpty, "locked": model.PasswordLocked,
	}
	for _, e := range entries {
		if e.Password != want[e.Name] {
			t.Errorf("%s = %s, want %s", e.Name, e.Password, want[e.Name])
		}
	}
}

func TestParseUIDMin(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      int
		wantFound bool
		wantErr   bool
	}{
		{name: "fixture", input: string(readFixture(t, "login.defs")), want: 1000, wantFound: true},
		{name: "unset", input: "UID_MAX 60000\n", wantFound: false},
		{name: "last wins", input: "UID_MIN 500\nUID_MIN 1000\n", want: 1000, wantFound: true},
		{name: "invalid", input: "UID_MIN abc\n", wantErr: true},
		{name: "negative", input: "UID_MIN -5\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found, err := ParseUIDMin([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if got != tt.want || found != tt.wantFound {
				t.Fatalf("got (%d, %v), want (%d, %v)", got, found, tt.want, tt.wantFound)
			}
		})
	}
}

func TestCollect(t *testing.T) {
	t.Run("unprivileged: shadow unreadable", func(t *testing.T) {
		fsys := platformtest.NewFS().
			Add(PasswdPath, platformtest.File{Data: readFixture(t, "passwd")}).
			Add(ShadowPath, platformtest.File{Mode: 0o640, Err: fs.ErrPermission}).
			Add(LoginDefsPath, platformtest.File{Data: []byte("UID_MIN 500\n")})
		sec := Collect(fsys)
		if sec.Status != model.Collected {
			t.Fatalf("status = %s", sec.Status)
		}
		if sec.Data.Shadow.Status != model.PermissionDenied {
			t.Errorf("shadow status = %s", sec.Data.Shadow.Status)
		}
		if sec.Data.UIDMin != 500 || sec.Data.UIDMinSource != LoginDefsPath {
			t.Errorf("uid min = %d from %q", sec.Data.UIDMin, sec.Data.UIDMinSource)
		}
		if len(sec.Warnings) != 3 {
			t.Errorf("warnings = %q", sec.Warnings)
		}
	})

	t.Run("privileged", func(t *testing.T) {
		fsys := platformtest.NewFS().
			Add(PasswdPath, platformtest.File{Data: readFixture(t, "passwd")}).
			Add(ShadowPath, platformtest.File{Data: readFixture(t, "shadow")})
		sec := Collect(fsys)
		if sec.Data.Shadow.Status != model.Collected || len(sec.Data.Shadow.Data) != 5 {
			t.Fatalf("shadow = %+v", sec.Data.Shadow)
		}
		if sec.Data.UIDMin != DefaultUIDMin {
			t.Errorf("uid min = %d, want default", sec.Data.UIDMin)
		}
	})

	t.Run("passwd missing", func(t *testing.T) {
		if sec := Collect(platformtest.NewFS()); sec.Status != model.NotFound {
			t.Fatalf("status = %s", sec.Status)
		}
	})

	t.Run("passwd unreadable", func(t *testing.T) {
		fsys := platformtest.NewFS().Add(PasswdPath, platformtest.File{Err: fs.ErrPermission})
		if sec := Collect(fsys); sec.Status != model.PermissionDenied {
			t.Fatalf("status = %s", sec.Status)
		}
	})
}
