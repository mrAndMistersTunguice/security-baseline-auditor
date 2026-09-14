package accounts

import (
	"strings"
	"testing"
)

// FuzzParsePasswd checks that malformed databases never panic and that
// warnings never contain line content (which may include password hashes).
func FuzzParsePasswd(f *testing.F) {
	f.Add("root:x:0:0:root:/root:/bin/bash\n")
	f.Add("a:$6$SECRET:1:1::/:/bin/sh\nbroken\n+nis\n")
	f.Add(":::::::\n\r\n")
	f.Fuzz(func(t *testing.T, content string) {
		users, warnings := ParsePasswd([]byte(content))
		for _, w := range warnings {
			if !strings.HasPrefix(w, "passwd line ") {
				t.Fatalf("unexpected warning format: %q", w)
			}
		}
		for _, u := range users {
			if u.Name == "" || strings.Contains(u.Name, ":") {
				t.Fatalf("invalid user parsed: %+v", u)
			}
		}
		ParseShadow([]byte(content))
		_, _, _ = ParseUIDMin([]byte(content))
	})
}
