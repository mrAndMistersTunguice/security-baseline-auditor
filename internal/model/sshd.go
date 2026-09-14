package model

// Global returns the effective global value of keyword: OpenSSH uses the
// first value obtained outside Match blocks. keyword must be lower-case.
func (c SSHDConfig) Global(keyword string) (SSHDirective, bool) {
	for _, d := range c.Directives {
		if d.Keyword == keyword && d.Match == "" {
			return d, true
		}
	}
	return SSHDirective{}, false
}

// Conditional returns directives for keyword that appear inside Match
// blocks. Each may override the global value for matching connections.
func (c SSHDConfig) Conditional(keyword string) []SSHDirective {
	var out []SSHDirective
	for _, d := range c.Directives {
		if d.Keyword == keyword && d.Match != "" {
			out = append(out, d)
		}
	}
	return out
}
