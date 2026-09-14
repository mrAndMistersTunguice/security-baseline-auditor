package files

import (
	"io/fs"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func TestCollect(t *testing.T) {
	fsys := platformtest.NewFS().
		Add("/etc/shadow", platformtest.File{Mode: 0o640, UID: 0, GID: 42}).
		Add("/etc/passwd", platformtest.File{Mode: 0o644, UID: 0, GID: 0, IsSymlink: true}).
		Add("/etc/sudoers", platformtest.File{Err: fs.ErrPermission}).
		Add("/tmp", platformtest.File{Mode: fs.ModeDir | fs.ModeSticky | 0o777})

	sec := Collect(fsys, []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/tmp", "/etc/gshadow"})
	if sec.Status != model.Collected || len(sec.Data) != 5 {
		t.Fatalf("section = %+v", sec)
	}

	shadow, _ := model.FindFile(sec.Data, "/etc/shadow")
	if !shadow.Exists || shadow.Mode.Perm() != 0o640 || shadow.GID != 42 || shadow.ModeString != "-rw-r-----" {
		t.Errorf("shadow = %+v", shadow)
	}
	if passwd, _ := model.FindFile(sec.Data, "/etc/passwd"); !passwd.IsSymlink {
		t.Errorf("symlink flag lost: %+v", passwd)
	}
	if sudoers, _ := model.FindFile(sec.Data, "/etc/sudoers"); sudoers.Exists || sudoers.Error == "" {
		t.Errorf("inaccessible path must carry an error: %+v", sudoers)
	}
	if tmp, _ := model.FindFile(sec.Data, "/tmp"); tmp.Mode&fs.ModeSticky == 0 {
		t.Errorf("sticky bit lost: %+v", tmp)
	}
	if gshadow, _ := model.FindFile(sec.Data, "/etc/gshadow"); gshadow.Exists || gshadow.Error != "" || gshadow.UID != -1 {
		t.Errorf("missing path = %+v", gshadow)
	}
}
