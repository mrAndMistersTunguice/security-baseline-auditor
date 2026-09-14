// Package sshd statically resolves an OpenSSH server configuration.
//
// The parser follows the behaviour of OpenSSH's servconf.c and misc.c:
//
//   - a line is a keyword followed by arguments; the keyword is separated by
//     whitespace or a single '=' and is case-insensitive;
//   - arguments may be quoted with ' or " and support \-escapes;
//     an unquoted '#' at the start of a token ends the line;
//   - Include accepts several glob patterns; relative patterns are resolved
//     against the SSH configuration directory; matches are processed in
//     lexical order; a pattern that matches nothing is not an error;
//   - Include may appear inside a Match block, and a Match block started in
//     an included file does not leak into the including file;
//   - includes may nest at most 16 levels.
//
// The parser does not evaluate Match criteria (it cannot know the future
// connection's user, address or host). Directives inside Match blocks are
// kept and labelled with their criteria so rules can reason about them.
package sshd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

const (
	// MaxFileSize bounds each configuration file.
	MaxFileSize = 1 << 20
	// MaxFiles bounds the number of files read through Include.
	MaxFiles = 256
	// MaxDepth mirrors SERVCONF_MAX_DEPTH in OpenSSH.
	MaxDepth = 16
	// MaxDirectives bounds the total number of directives kept.
	MaxDirectives = 100_000
)

// ErrSyntax marks configuration content that sshd itself would reject.
var ErrSyntax = errors.New("invalid sshd configuration syntax")

// ErrLimit marks configurations exceeding the parser's resource limits.
var ErrLimit = errors.New("sshd configuration exceeds parser limits")

// keywordAliases maps deprecated keywords to their current names.
var keywordAliases = map[string]string{
	"challengeresponseauthentication": "kbdinteractiveauthentication",
	"pubkeyacceptedkeytypes":          "pubkeyacceptedalgorithms",
	"hostbasedacceptedkeytypes":       "hostbasedacceptedalgorithms",
}

// Load parses mainFile and every file it includes. configDir is the
// directory relative Include patterns are resolved against (/etc/ssh on
// Unix, %ProgramData%\ssh on Windows).
func Load(fsys platform.FS, mainFile, configDir string) (model.SSHDConfig, error) {
	l := &loader{
		fs:        fsys,
		configDir: configDir,
		cfg:       model.SSHDConfig{MainFile: mainFile},
	}
	if err := l.parseFile(mainFile, 0, ""); err != nil {
		return model.SSHDConfig{}, err
	}
	return l.cfg, nil
}

type loader struct {
	fs        platform.FS
	configDir string
	cfg       model.SSHDConfig
}

func (l *loader) parseFile(name string, depth int, match string) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: include depth exceeds %d at %s", ErrLimit, MaxDepth, name)
	}
	if len(l.cfg.Files) >= MaxFiles {
		return fmt.Errorf("%w: more than %d files", ErrLimit, MaxFiles)
	}
	data, err := l.fs.ReadFile(name, MaxFileSize)
	if err != nil {
		return err
	}
	l.cfg.Files = append(l.cfg.Files, name)

	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		keyword, args, err := tokenizeLine(raw)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", name, lineNo, err)
		}
		if keyword == "" {
			continue
		}
		switch keyword {
		case "match":
			// A Match block lasts until the next Match line or the end of
			// the current file.
			match = strings.Join(args, " ")
		case "include":
			for _, pattern := range args {
				if err := l.include(pattern, name, lineNo, depth, match); err != nil {
					return err
				}
			}
		default:
			if !knownKeywords[keyword] {
				l.cfg.IgnoredDirectives++
				continue
			}
			if len(l.cfg.Directives) >= MaxDirectives {
				return fmt.Errorf("%w: more than %d directives", ErrLimit, MaxDirectives)
			}
			l.cfg.Directives = append(l.cfg.Directives, model.SSHDirective{
				Keyword: keyword,
				Args:    args,
				File:    name,
				Line:    lineNo,
				Match:   match,
			})
		}
	}
	return nil
}

func (l *loader) include(pattern, file string, line, depth int, match string) error {
	if strings.HasPrefix(pattern, "~") {
		return fmt.Errorf("%s:%d: %w: Include path %q starting with '~' is not supported", file, line, ErrSyntax, pattern)
	}
	if !isAbs(pattern) {
		pattern = filepath.Join(l.configDir, pattern)
	}
	matches, err := l.fs.Glob(pattern)
	if err != nil {
		return fmt.Errorf("%s:%d: Include %q: %w", file, line, pattern, err)
	}
	if len(l.cfg.Files)+len(matches) > MaxFiles {
		return fmt.Errorf("%w: Include %q at %s:%d matches %d files (limit %d in total)", ErrLimit, pattern, file, line, len(matches), MaxFiles)
	}
	for _, m := range matches {
		if err := l.parseFile(m, depth+1, match); err != nil {
			return err
		}
	}
	return nil
}

// isAbs treats a leading '/' as absolute on every OS, matching OpenSSH's
// check, and additionally accepts OS-native absolute paths (C:\...).
func isAbs(p string) bool {
	return strings.HasPrefix(p, "/") || filepath.IsAbs(p)
}

// tokenizeLine splits one configuration line into a lower-cased canonical
// keyword and its arguments. It returns an empty keyword for blank and
// comment lines.
func tokenizeLine(line string) (string, []string, error) {
	line = strings.TrimRight(line, " \t\r\n\f")
	line = strings.TrimLeft(line, " \t\r\n")
	if line == "" || line[0] == '#' {
		return "", nil, nil
	}

	end := strings.IndexAny(line, " \t\r\n=\"")
	if end < 0 {
		return "", nil, fmt.Errorf("%w: no argument after keyword %s", ErrSyntax, safeKeyword(line))
	}
	if line[end] == '"' {
		return "", nil, fmt.Errorf("%w: unexpected quote in keyword", ErrSyntax)
	}
	keyword := line[:end]
	rest := line[end:]
	sawEquals := rest[0] == '='
	rest = strings.TrimLeft(rest[1:], " \t\r\n")
	if !sawEquals && strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t\r\n")
	}
	if rest == "" {
		return "", nil, fmt.Errorf("%w: no argument after keyword %s", ErrSyntax, safeKeyword(keyword))
	}

	args, err := splitArgs(rest)
	if err != nil {
		return "", nil, err
	}
	if len(args) == 0 {
		return "", nil, fmt.Errorf("%w: no argument after keyword %s", ErrSyntax, safeKeyword(keyword))
	}

	keyword = strings.ToLower(keyword)
	if canonical, ok := keywordAliases[keyword]; ok {
		keyword = canonical
	}
	return keyword, args, nil
}

// safeKeyword quotes a keyword for an error message only if it looks like a
// real sshd keyword. Error messages end up in reports, and a line of an
// unexpected file (for example a password hash from a file pulled in by a
// malicious Include) must never be echoed.
func safeKeyword(k string) string {
	if len(k) == 0 || len(k) > 64 {
		return "(redacted)"
	}
	for _, r := range k {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return "(redacted)"
		}
	}
	return `"` + k + `"`
}

// splitArgs mirrors argv_split(..., terminate_on_comment=1) from OpenSSH.
func splitArgs(s string) ([]string, error) {
	var args []string
	i := 0
	for i < len(s) {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		if s[i] == '#' {
			break
		}
		var b strings.Builder
		var quote byte
		for ; i < len(s); i++ {
			c := s[i]
			switch {
			case c == '\\' && i+1 < len(s) &&
				(s[i+1] == '\'' || s[i+1] == '"' || s[i+1] == '\\' || (quote == 0 && s[i+1] == ' ')):
				i++
				b.WriteByte(s[i])
				continue
			case quote == 0 && (c == ' ' || c == '\t'):
			case quote == 0 && (c == '"' || c == '\''):
				quote = c
				continue
			case quote != 0 && c == quote:
				quote = 0
				continue
			default:
				b.WriteByte(c)
				continue
			}
			break // unquoted whitespace ends the token
		}
		if quote != 0 {
			return nil, fmt.Errorf("%w: unterminated quote", ErrSyntax)
		}
		args = append(args, b.String())
	}
	return args, nil
}
