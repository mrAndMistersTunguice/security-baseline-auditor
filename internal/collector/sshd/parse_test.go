package sshd

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func TestTokenizeLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		keyword string
		args    []string
		wantErr error
	}{
		{name: "blank", line: "   \t", keyword: ""},
		{name: "comment", line: "# PermitRootLogin yes", keyword: ""},
		{name: "indented comment", line: "\t  #PasswordAuthentication yes", keyword: ""},
		{name: "simple", line: "PermitRootLogin no", keyword: "permitrootlogin", args: []string{"no"}},
		{name: "keyword case-insensitive", line: "PERMITROOTLOGIN yes", keyword: "permitrootlogin", args: []string{"yes"}},
		{name: "equals no spaces", line: "PasswordAuthentication=no", keyword: "passwordauthentication", args: []string{"no"}},
		{name: "equals with spaces", line: "PasswordAuthentication = no", keyword: "passwordauthentication", args: []string{"no"}},
		{name: "equals after space", line: "MaxAuthTries =3", keyword: "maxauthtries", args: []string{"3"}},
		{name: "second equals is argument", line: "Banner==x", keyword: "banner", args: []string{"=x"}},
		{name: "tabs and CRLF", line: "X11Forwarding\tyes\r", keyword: "x11forwarding", args: []string{"yes"}},
		{name: "trailing comment", line: "PermitRootLogin yes # legacy", keyword: "permitrootlogin", args: []string{"yes"}},
		{name: "hash inside token is not a comment", line: "Banner /etc/issue#net", keyword: "banner", args: []string{"/etc/issue#net"}},
		{name: "double quotes", line: `Subsystem sftp "/usr/lib/sftp server"`, keyword: "subsystem", args: []string{"sftp", "/usr/lib/sftp server"}},
		{name: "single quotes", line: `ForceCommand 'internal-sftp -d x'`, keyword: "forcecommand", args: []string{"internal-sftp -d x"}},
		{name: "escaped space", line: `ChrootDirectory /srv/a\ b`, keyword: "chrootdirectory", args: []string{"/srv/a b"}},
		{name: "quoted hash", line: `Banner "#x"`, keyword: "banner", args: []string{"#x"}},
		{name: "deprecated alias", line: "ChallengeResponseAuthentication yes", keyword: "kbdinteractiveauthentication", args: []string{"yes"}},
		{name: "multiple args", line: "AcceptEnv LANG LC_*", keyword: "acceptenv", args: []string{"LANG", "LC_*"}},
		{name: "missing argument", line: "PermitRootLogin", wantErr: ErrSyntax},
		{name: "missing argument trailing space", line: "PermitRootLogin   ", wantErr: ErrSyntax},
		{name: "only comment after keyword", line: "PermitRootLogin #no", wantErr: ErrSyntax},
		{name: "unterminated quote", line: `Banner "/etc/issue`, wantErr: ErrSyntax},
		{name: "quote in keyword", line: `Perm"it yes`, wantErr: ErrSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kw, args, err := tokenizeLine(tt.line)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kw != tt.keyword || !reflect.DeepEqual(args, tt.args) {
				t.Fatalf("got (%q, %q), want (%q, %q)", kw, args, tt.keyword, tt.args)
			}
		})
	}
}

// fixtureFS loads files from testdata into a fake filesystem at the given
// absolute paths.
func fixtureFS(t *testing.T, files map[string]string) *platformtest.FS {
	t.Helper()
	fsys := platformtest.NewFS()
	for target, fixture := range files {
		data, err := os.ReadFile(filepath.Join("testdata", fixture))
		if err != nil {
			t.Fatal(err)
		}
		fsys.Add(target, platformtest.File{Data: data})
	}
	return fsys
}

func value(t *testing.T, cfg model.SSHDConfig, keyword string) string {
	t.Helper()
	d, ok := cfg.Global(keyword)
	if !ok {
		return "<unset>"
	}
	return strings.Join(d.Args, " ")
}

func TestLoadDebianStyleDropIns(t *testing.T) {
	fsys := fixtureFS(t, map[string]string{
		"/etc/ssh/sshd_config":                     "debian-style/sshd_config",
		"/etc/ssh/sshd_config.d/10-hardening.conf": "debian-style/10-hardening.conf",
		"/etc/ssh/sshd_config.d/20-late.conf":      "debian-style/20-late.conf",
	})
	cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
	if err != nil {
		t.Fatal(err)
	}

	wantFiles := []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/10-hardening.conf", "/etc/ssh/sshd_config.d/20-late.conf"}
	var gotFiles []string
	for _, f := range cfg.Files {
		gotFiles = append(gotFiles, filepath.ToSlash(f))
	}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Errorf("files = %q, want %q", gotFiles, wantFiles)
	}

	// Drop-ins are included before the rest of the main file and are
	// processed in lexical order, so 10-hardening wins over 20-late.
	for kw, want := range map[string]string{
		"passwordauthentication":       "no",
		"permitrootlogin":              "no",
		"kbdinteractiveauthentication": "no",
		"x11forwarding":                "yes",
		"usepam":                       "yes",
		"maxauthtries":                 "<unset>",
	} {
		if got := value(t, cfg, kw); got != want {
			t.Errorf("%s = %q, want %q", kw, got, want)
		}
	}
	d, _ := cfg.Global("passwordauthentication")
	if filepath.ToSlash(d.File) != "/etc/ssh/sshd_config.d/10-hardening.conf" || d.Line != 2 {
		t.Errorf("passwordauthentication location = %s:%d", d.File, d.Line)
	}
}

func TestLoadRHELStyleNestedIncludeAndMatch(t *testing.T) {
	fsys := fixtureFS(t, map[string]string{
		"/etc/ssh/sshd_config":                                "rhel-style/sshd_config",
		"/etc/ssh/sshd_config.d/50-redhat.conf":               "rhel-style/50-redhat.conf",
		"/etc/crypto-policies/back-ends/opensshserver.config": "rhel-style/opensshserver.config",
	})
	cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Files); got != 3 {
		t.Fatalf("read %d files, want 3", got)
	}
	if got := value(t, cfg, "kbdinteractiveauthentication"); got != "no" {
		t.Errorf("alias ChallengeResponseAuthentication not mapped: %q", got)
	}
	if got := value(t, cfg, "passwordauthentication"); got != "<unset>" {
		t.Errorf("global passwordauthentication = %q, want unset", got)
	}
	cond := cfg.Conditional("passwordauthentication")
	if len(cond) != 1 || cond[0].Match != "Address 10.0.0.0/8" || cond[0].Args[0] != "yes" {
		t.Errorf("conditional = %+v", cond)
	}
	if !strings.HasPrefix(value(t, cfg, "ciphers"), "aes256-gcm@openssh.com,") {
		t.Errorf("ciphers from nested include missing")
	}
}

func TestLoadIncludeSemantics(t *testing.T) {
	t.Run("relative include resolves against config dir", func(t *testing.T) {
		fsys := platformtest.NewFS().
			AddText("/etc/ssh/sshd_config", "Include conf.d/*.conf\n").
			AddText("/etc/ssh/conf.d/a.conf", "PermitRootLogin yes\n")
		cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if err != nil {
			t.Fatal(err)
		}
		if got := value(t, cfg, "permitrootlogin"); got != "yes" {
			t.Fatalf("permitrootlogin = %q", got)
		}
	})

	t.Run("pattern without matches is not an error", func(t *testing.T) {
		fsys := platformtest.NewFS().AddText("/etc/ssh/sshd_config", "Include /etc/ssh/none/*.conf\nPermitRootLogin no\n")
		if _, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("multiple patterns on one line", func(t *testing.T) {
		fsys := platformtest.NewFS().
			AddText("/etc/ssh/sshd_config", "Include /b.conf /a.conf\n").
			AddText("/a.conf", "X11Forwarding no\n").
			AddText("/b.conf", "X11Forwarding yes\n")
		cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if err != nil {
			t.Fatal(err)
		}
		if got := value(t, cfg, "x11forwarding"); got != "yes" {
			t.Fatalf("patterns must be processed in the order written: got %q", got)
		}
	})

	t.Run("include inside match inherits the match", func(t *testing.T) {
		fsys := platformtest.NewFS().
			AddText("/etc/ssh/sshd_config", "Match User backup\n  Include /etc/ssh/backup.conf\n").
			AddText("/etc/ssh/backup.conf", "PermitRootLogin yes\n")
		cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := cfg.Global("permitrootlogin"); ok {
			t.Fatal("directive from include inside Match must not be global")
		}
		if c := cfg.Conditional("permitrootlogin"); len(c) != 1 || c[0].Match != "User backup" {
			t.Fatalf("conditional = %+v", c)
		}
	})

	t.Run("match in included file does not leak", func(t *testing.T) {
		fsys := platformtest.NewFS().
			AddText("/etc/ssh/sshd_config", "Include /etc/ssh/a.conf\nPasswordAuthentication yes\n").
			AddText("/etc/ssh/a.conf", "Match Group sftp\n  ForceCommand internal-sftp\n")
		cfg, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if err != nil {
			t.Fatal(err)
		}
		if got := value(t, cfg, "passwordauthentication"); got != "yes" {
			t.Fatalf("directive after include became conditional: %q", got)
		}
	})

	t.Run("recursive include hits depth limit", func(t *testing.T) {
		fsys := platformtest.NewFS().AddText("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config\n")
		_, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
	})

	t.Run("tilde include is rejected", func(t *testing.T) {
		fsys := platformtest.NewFS().AddText("/etc/ssh/sshd_config", "Include ~/x.conf\n")
		_, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if !errors.Is(err, ErrSyntax) {
			t.Fatalf("err = %v, want ErrSyntax", err)
		}
	})

	t.Run("bad glob pattern", func(t *testing.T) {
		fsys := platformtest.NewFS().AddText("/etc/ssh/sshd_config", "Include /etc/ssh/[.conf\n")
		if _, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh"); err == nil {
			t.Fatal("expected error for malformed glob")
		}
	})

	t.Run("syntax error reports file and line", func(t *testing.T) {
		fsys := platformtest.NewFS().AddText("/etc/ssh/sshd_config", "Port 22\nBanner \"oops\n")
		_, err := Load(fsys, "/etc/ssh/sshd_config", "/etc/ssh")
		if !errors.Is(err, ErrSyntax) || !strings.Contains(err.Error(), "sshd_config:2") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCollect(t *testing.T) {
	tests := []struct {
		name       string
		fs         *platformtest.FS
		wantStatus model.CollectionStatus
		wantMain   string
	}{
		{
			name:       "not installed",
			fs:         platformtest.NewFS(),
			wantStatus: model.NotFound,
		},
		{
			name:       "primary location",
			fs:         platformtest.NewFS().AddText("/etc/ssh/sshd_config", "PermitRootLogin no\n"),
			wantStatus: model.Collected,
			wantMain:   "/etc/ssh/sshd_config",
		},
		{
			name:       "vendor location fallback",
			fs:         platformtest.NewFS().AddText("/usr/etc/ssh/sshd_config", "PermitRootLogin no\n"),
			wantStatus: model.Collected,
			wantMain:   "/usr/etc/ssh/sshd_config",
		},
		{
			name: "unreadable main file",
			fs: platformtest.NewFS().Add("/etc/ssh/sshd_config", platformtest.File{
				Data: []byte("x"), Err: fs.ErrPermission,
			}),
			wantStatus: model.PermissionDenied,
		},
		{
			name: "unreadable include makes whole config unavailable",
			fs: platformtest.NewFS().
				AddText("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n").
				Add("/etc/ssh/sshd_config.d/00-secret.conf", platformtest.File{Err: fs.ErrPermission}),
			wantStatus: model.PermissionDenied,
		},
		{
			name:       "invalid syntax",
			fs:         platformtest.NewFS().AddText("/etc/ssh/sshd_config", "PermitRootLogin\n"),
			wantStatus: model.Failed,
		},
		{
			name: "oversized file",
			fs: platformtest.NewFS().Add("/etc/ssh/sshd_config", platformtest.File{
				Data: make([]byte, MaxFileSize+1),
			}),
			wantStatus: model.Failed,
		},
		{
			name: "directory instead of file",
			fs: platformtest.NewFS().Add("/etc/ssh/sshd_config", platformtest.File{
				Mode: fs.ModeDir | 0o755,
			}),
			wantStatus: model.Failed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec := Collect(tt.fs, UnixLocations)
			if sec.Status != tt.wantStatus {
				t.Fatalf("status = %s (%s), want %s", sec.Status, sec.Detail, tt.wantStatus)
			}
			if tt.wantStatus != model.Collected && sec.Detail == "" {
				t.Error("non-collected section must explain why")
			}
			if tt.wantMain != "" && sec.Data.MainFile != tt.wantMain {
				t.Errorf("main file = %q, want %q", sec.Data.MainFile, tt.wantMain)
			}
		})
	}
}

// TestLoadRealFiles exercises the OS filesystem implementation, including
// relative include resolution with native paths.
func TestLoadRealFiles(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Include sshd_config.d/*.conf\nPermitRootLogin yes\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "sshd_config.d", "01.conf"), []byte("PermitRootLogin no\n"), 0o644))

	sec := Collect(platform.OSFS{}, []Location{{MainFile: filepath.Join(dir, "sshd_config"), ConfigDir: dir}})
	if sec.Status != model.Collected {
		t.Fatalf("status = %s: %s", sec.Status, sec.Detail)
	}
	if got := value(t, sec.Data, "permitrootlogin"); got != "no" {
		t.Fatalf("permitrootlogin = %q, want no", got)
	}
}
