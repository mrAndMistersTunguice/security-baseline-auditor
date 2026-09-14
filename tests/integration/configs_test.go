package integration

import (
	"path/filepath"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/rules"
)

// TestShippedConfigsAreValid keeps the example baselines in configs/ in sync
// with the rule catalog.
func TestShippedConfigsAreValid(t *testing.T) {
	var ids []string
	for _, r := range rules.Builtin() {
		ids = append(ids, r.ID)
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "configs", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no configs found: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			if _, err := baseline.Load(platform.OSFS{}, f, ids, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}
