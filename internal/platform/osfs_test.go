package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOSFSReadFile(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	fsys := OSFS{}
	t.Run("regular file", func(t *testing.T) {
		data, err := fsys.ReadFile(small, 5)
		if err != nil || string(data) != "hello" {
			t.Fatalf("got %q, %v", data, err)
		}
	})
	t.Run("exceeds limit", func(t *testing.T) {
		_, err := fsys.ReadFile(small, 4)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		_, err := fsys.ReadFile(dir, 1024)
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("err = %v, want ErrNotRegular", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		_, err := fsys.ReadFile(filepath.Join(dir, "nope"), 1024)
		if !IsNotExist(err) {
			t.Fatalf("err = %v, want not-exist", err)
		}
	})
	t.Run("invalid limit", func(t *testing.T) {
		if _, err := fsys.ReadFile(small, 0); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestOSFSStatAndGlob(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"b.conf", "a.conf", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fsys := OSFS{}
	matches, err := fsys.Glob(filepath.Join(dir, "*.conf"))
	if err != nil || len(matches) != 2 || filepath.Base(matches[0]) != "a.conf" {
		t.Fatalf("glob = %q, %v", matches, err)
	}
	info, err := fsys.Stat(matches[0])
	if err != nil || !info.Mode.IsRegular() || info.IsSymlink {
		t.Fatalf("stat = %+v, %v", info, err)
	}
	names, err := fsys.ReadDirNames(dir)
	if err != nil || len(names) != 3 {
		t.Fatalf("names = %q, %v", names, err)
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := &limitedBuffer{limit: 4}
	if n, err := b.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := b.Write([]byte("cdef")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	if b.String() != "abcd" || !b.overflow {
		t.Fatalf("buffer = %q overflow=%v", b.String(), b.overflow)
	}
}

func TestExecRunnerRejectsRelativePath(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), "nft", "list", "ruleset")
	if err == nil {
		t.Fatal("relative program path must be rejected")
	}
	// On Unix the path check fires; elsewhere execution is refused outright.
	if !strings.Contains(err.Error(), "absolute") && !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("err = %v", err)
	}
}
