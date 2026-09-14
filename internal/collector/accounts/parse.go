// Package accounts parses the local Unix account databases (/etc/passwd,
// /etc/shadow, /etc/login.defs).
//
// Password hashes are classified and then discarded; they never leave this
// package. Warnings refer to line numbers only, because a malformed line may
// contain secret material.
package accounts

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

// ClassifyPassword maps a passwd or shadow password field to a state.
func ClassifyPassword(field string) model.PasswordState {
	switch {
	case field == "x":
		return model.PasswordShadowed
	case field == "":
		return model.PasswordEmpty
	case strings.HasPrefix(field, "!"), strings.HasPrefix(field, "*"):
		return model.PasswordLocked
	default:
		return model.PasswordHash
	}
}

func lines(data []byte) []string {
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

// ParsePasswd parses passwd(5) content. Malformed lines are skipped and
// reported as warnings.
func ParsePasswd(data []byte) ([]model.User, []string) {
	var users []model.User
	var warnings []string
	for i, line := range lines(data) {
		lineNo := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] == '+' || line[0] == '-' {
			warnings = append(warnings, fmt.Sprintf("passwd line %d: NIS compatibility entry not evaluated", lineNo))
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			warnings = append(warnings, fmt.Sprintf("passwd line %d: expected 7 fields, found %d", lineNo, len(fields)))
			continue
		}
		if fields[0] == "" {
			warnings = append(warnings, fmt.Sprintf("passwd line %d: empty user name", lineNo))
			continue
		}
		uid, errUID := strconv.ParseUint(fields[2], 10, 32)
		gid, errGID := strconv.ParseUint(fields[3], 10, 32)
		if errUID != nil || errGID != nil {
			warnings = append(warnings, fmt.Sprintf("passwd line %d: invalid UID or GID", lineNo))
			continue
		}
		users = append(users, model.User{
			Name:          fields[0],
			UID:           uint32(uid),
			GID:           uint32(gid),
			Home:          fields[5],
			Shell:         fields[6],
			PasswordField: ClassifyPassword(fields[1]),
			Line:          lineNo,
		})
	}
	return users, warnings
}

// ParseShadow parses shadow(5) content, keeping only the password state.
func ParseShadow(data []byte) ([]model.ShadowEntry, []string) {
	var entries []model.ShadowEntry
	var warnings []string
	for i, line := range lines(data) {
		lineNo := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 9 || fields[0] == "" {
			warnings = append(warnings, fmt.Sprintf("shadow line %d: malformed entry", lineNo))
			continue
		}
		entries = append(entries, model.ShadowEntry{
			Name:     fields[0],
			Password: ClassifyPassword(fields[1]),
			Line:     lineNo,
		})
	}
	return entries, warnings
}

// ParseUIDMin extracts UID_MIN from login.defs(5) content.
func ParseUIDMin(data []byte) (int, bool, error) {
	var (
		value int
		found bool
	)
	for _, line := range lines(data) {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") || fields[0] != "UID_MIN" {
			continue
		}
		n, err := strconv.ParseInt(fields[1], 10, 32)
		if err != nil || n < 0 {
			return 0, false, fmt.Errorf("login.defs: invalid UID_MIN %q", fields[1])
		}
		// shadow-utils uses the last occurrence.
		value, found = int(n), true
	}
	return value, found, nil
}
