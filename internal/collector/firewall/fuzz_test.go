package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzAnalyzeRuleset checks that arbitrary nft output never panics or
// recurses without bound.
func FuzzAnalyzeRuleset(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	for _, s := range seeds {
		if data, err := os.ReadFile(s); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte(`{"nftables":[{"chain":{"family":"ip","table":"t","name":"c","type":"filter","hook":"input"}},{"rule":{"family":"ip","table":"t","chain":"c","expr":[{"jump":{"target":"c"}}]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := AnalyzeRuleset(data)
		if err == nil && res.InputChains < 0 {
			t.Fatal("negative chain count")
		}
	})
}
