package model

import (
	"io/fs"
	"time"
)

// SnapshotSchemaVersion is bumped whenever the JSON shape of Snapshot changes
// incompatibly.
const SnapshotSchemaVersion = "1"

// CollectionStatus describes whether a snapshot section holds usable data.
type CollectionStatus string

const (
	// Collected means Data is complete and can be evaluated.
	Collected CollectionStatus = "collected"
	// Unsupported means no collector exists for this section on this platform.
	Unsupported CollectionStatus = "unsupported"
	// NotFound means the component (for example an SSH server) is not present.
	NotFound CollectionStatus = "not_found"
	// PermissionDenied means the data exists but the process lacks privileges.
	PermissionDenied CollectionStatus = "permission_denied"
	// Failed means collection was attempted and failed unexpectedly.
	Failed CollectionStatus = "failed"
)

// Section wraps a piece of collected data with the status of its collection.
// Rules must check Status before trusting Data: a zero-valued Data in a
// section that was not collected means "unknown", not "empty".
type Section[T any] struct {
	Status   CollectionStatus `json:"status"`
	Detail   string           `json:"detail,omitempty"`
	Warnings []string         `json:"warnings,omitempty"`
	Data     T                `json:"data"`
}

// CollectedSection returns a section marked as collected.
func CollectedSection[T any](data T) Section[T] {
	return Section[T]{Status: Collected, Data: data}
}

// Unavailable returns a section with the given non-collected status.
func Unavailable[T any](status CollectionStatus, detail string) Section[T] {
	return Section[T]{Status: status, Detail: detail}
}

// Snapshot is the normalized, platform-independent view of the audited
// system. Collectors produce it; rules only read it.
type Snapshot struct {
	SchemaVersion string    `json:"schema_version"`
	CollectedAt   time.Time `json:"collected_at"`
	Host          Host      `json:"host"`

	Accounts Section[Accounts]    `json:"accounts"`
	SSHD     Section[SSHDConfig]  `json:"sshd"`
	Firewall Section[Firewall]    `json:"firewall"`
	Files    Section[[]FileEntry] `json:"files"`
}

// Host identifies the audited system.
type Host struct {
	OS            string `json:"os"` // GOOS value, e.g. "linux", "windows"
	Arch          string `json:"arch"`
	Hostname      string `json:"hostname,omitempty"`
	DistroID      string `json:"distro_id,omitempty"`   // os-release ID
	DistroLike    string `json:"distro_like,omitempty"` // os-release ID_LIKE
	PrettyName    string `json:"pretty_name,omitempty"`
	Version       string `json:"version,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
	// Elevated is true when the auditor runs as root (Unix) or with an
	// elevated token (Windows).
	Elevated bool `json:"elevated"`
}

// Accounts holds local account data.
type Accounts struct {
	// Users are parsed from the local account database (/etc/passwd).
	// Accounts from NSS sources such as LDAP or SSSD are not included.
	Users []User `json:"users"`
	// Shadow requires elevated privileges on most systems.
	Shadow Section[[]ShadowEntry] `json:"shadow"`
	// UIDMin is the first UID of regular users (login.defs UID_MIN).
	UIDMin int `json:"uid_min"`
	// UIDMinSource explains where UIDMin came from.
	UIDMinSource string `json:"uid_min_source"`
}

// PasswordState classifies a password field without retaining the hash.
type PasswordState string

const (
	PasswordShadowed PasswordState = "shadowed" // passwd field "x": look in shadow
	PasswordEmpty    PasswordState = "empty"    // no password required
	PasswordLocked   PasswordState = "locked"   // "!" or "*" prefix: password login disabled
	PasswordHash     PasswordState = "hash"     // a password hash is present
)

// User is one entry of the local account database.
type User struct {
	Name          string        `json:"name"`
	UID           uint32        `json:"uid"`
	GID           uint32        `json:"gid"`
	Home          string        `json:"home"`
	Shell         string        `json:"shell"`
	PasswordField PasswordState `json:"password_field"`
	Line          int           `json:"line"`
}

// ShadowEntry is the non-secret part of a shadow database entry. Password
// hashes are never stored in the snapshot.
type ShadowEntry struct {
	Name     string        `json:"name"`
	Password PasswordState `json:"password"`
	Line     int           `json:"line"`
}

// SSHDConfig is the statically resolved OpenSSH server configuration.
type SSHDConfig struct {
	// MainFile is the top-level configuration file that was parsed.
	MainFile string `json:"main_file"`
	// Files lists every file read, in processing order.
	Files []string `json:"files"`
	// Directives in processing order, with Include files expanded inline.
	// Only documented sshd keywords are kept.
	Directives []SSHDirective `json:"directives"`
	// IgnoredDirectives counts lines with unrecognized keywords, whose
	// arguments were discarded.
	IgnoredDirectives int `json:"ignored_directives"`
}

// SSHDirective is one keyword line of an sshd configuration file.
type SSHDirective struct {
	// Keyword is lower-cased; deprecated aliases are mapped to their
	// canonical name (for example challengeresponseauthentication ->
	// kbdinteractiveauthentication).
	Keyword string   `json:"keyword"`
	Args    []string `json:"args"`
	File    string   `json:"file"`
	Line    int      `json:"line"`
	// Match holds the criteria of the enclosing Match block, or "" when the
	// directive is in the global section.
	Match string `json:"match,omitempty"`
}

// FirewallState is a tri-state firewall status.
type FirewallState string

const (
	FirewallEnabled  FirewallState = "enabled"
	FirewallDisabled FirewallState = "disabled"
	FirewallUnknown  FirewallState = "unknown"
)

// Firewall describes the host firewall providers that were detected.
type Firewall struct {
	Providers []FirewallProvider `json:"providers"`
}

// FirewallProvider is one source of firewall evidence (a kernel ruleset, a
// management daemon, a Windows firewall profile set, ...).
type FirewallProvider struct {
	Name  string        `json:"name"`
	State FirewallState `json:"state"`
	// RuntimeVerified is true when State reflects live state rather than
	// only persisted configuration.
	RuntimeVerified bool `json:"runtime_verified"`
	// Authoritative is true when this provider's view covers all inbound
	// filtering on the host, so a "disabled" state is conclusive.
	Authoritative bool     `json:"authoritative"`
	Evidence      []string `json:"evidence,omitempty"`
}

// FileEntry holds metadata of one security-relevant filesystem path.
type FileEntry struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	// Error is set when the path could not be inspected for a reason other
	// than not existing.
	Error     string      `json:"error,omitempty"`
	IsSymlink bool        `json:"is_symlink,omitempty"`
	Mode      fs.FileMode `json:"mode"`
	// ModeString is Mode rendered like ls(1), for human consumption.
	ModeString string `json:"mode_string,omitempty"`
	// UID and GID of the file (after following a symlink); -1 when unknown.
	UID int64 `json:"uid"`
	GID int64 `json:"gid"`
}

// FindFile returns the entry for path and whether it was found.
func FindFile(entries []FileEntry, path string) (FileEntry, bool) {
	for _, e := range entries {
		if e.Path == path {
			return e, true
		}
	}
	return FileEntry{}, false
}
