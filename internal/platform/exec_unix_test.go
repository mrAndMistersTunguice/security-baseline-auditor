//go:build unix

package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadFileDoesNotBlockOnFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo not available: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := OSFS{}.ReadFile(fifo, 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("err = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile blocked on a FIFO")
	}
}

func TestOSFSStatReportsOwnershipAndSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	info, err := OSFS{}.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsSymlink || !info.Mode.IsRegular() || info.Mode.Perm() != 0o640 {
		t.Errorf("info = %+v", info)
	}
	if info.UID != int64(os.Getuid()) {
		t.Errorf("uid = %d, want %d", info.UID, os.Getuid())
	}
}

func TestExecRunnerRefusesUntrustedBinary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("files created by root would be trusted")
	}
	script := filepath.Join(t.TempDir(), "fake-nft")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := ExecRunner{}.Run(context.Background(), script)
	if !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("err = %v, want ErrUntrustedBinary", err)
	}
}

func trustedSystemBinary(t *testing.T, candidates ...string) string {
	t.Helper()
	for _, c := range candidates {
		if _, err := checkTrustedBinary(c); err == nil {
			return c
		}
	}
	t.Skipf("none of %v is a trusted system binary here", candidates)
	return ""
}

func TestExecRunnerUsesMinimalEnvironment(t *testing.T) {
	env := trustedSystemBinary(t, "/usr/bin/env", "/bin/env")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("SBA_SECRET_TOKEN", "must-not-leak")

	out, err := ExecRunner{}.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	slices.Sort(lines)
	want := []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if !slices.Equal(lines, want) {
		t.Fatalf("child environment = %q, want %q", lines, want)
	}
}

func TestExecRunnerReportsFailure(t *testing.T) {
	bin := trustedSystemBinary(t, "/usr/bin/false", "/bin/false")
	if _, err := (ExecRunner{}).Run(context.Background(), bin); err == nil {
		t.Fatal("expected error from a failing command")
	}
}

func TestExecRunnerHonoursContext(t *testing.T) {
	bin := trustedSystemBinary(t, "/usr/bin/sleep", "/bin/sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ExecRunner{}.Run(ctx, bin, "30")
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}
