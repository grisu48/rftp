// SPDX-License-Identifier: MIT
//go:build linux

package security

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// IsRoot reports whether the process is running with root privileges.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// resolveUID resolves a user name or numeric uid to a uid. It first attempts
// to parse the value as an int and uses it directly if that succeeds (a
// negative value is rejected); only if parsing fails is the value looked up
// as a name in the user database (/etc/passwd). An unresolvable name is an
// error — fail-closed.
func resolveUID(name string) (int, error) {
	if uid, err := strconv.Atoi(name); err == nil {
		if uid < 0 {
			return 0, fmt.Errorf("invalid uid %q: must not be negative", name)
		}
		return uid, nil
	}
	usr, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("lookup user %q: %w", name, err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return 0, fmt.Errorf("parse uid %q for user %q: %w", usr.Uid, name, err)
	}
	return uid, nil
}

// resolveGID resolves a group name or numeric gid to a gid. It first attempts
// to parse the value as an int and uses it directly if that succeeds (a
// negative value is rejected); only if parsing fails is the value looked up
// as a name in the group database (/etc/group). An unresolvable name is an
// error — fail-closed.
func resolveGID(name string) (int, error) {
	if gid, err := strconv.Atoi(name); err == nil {
		if gid < 0 {
			return 0, fmt.Errorf("invalid gid %q: must not be negative", name)
		}
		return gid, nil
	}
	grp, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("lookup group %q: %w", name, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return 0, fmt.Errorf("parse gid %q for group %q: %w", grp.Gid, name, err)
	}
	return gid, nil
}

// DropPrivileges permanently drops root privileges to the given user and
// group. Supplementary groups are cleared first, then the group and
// finally the user ID are set. Dropping privileges is irreversible, so a
// failure to actually change the effective IDs is reported as an error.
//
// The user and group may each be given as a name (resolved via the user
// database, e.g. "nobody") or as a numeric ID (e.g. "65534"), so dropping
// also works on systems without a user/group database (scratch containers).
//
// It must be called after binding the listener and (optionally) chrooting,
// and requires root.
func DropPrivileges(userName, groupName string) error {
	if !IsRoot() {
		return errors.New("cannot drop privileges: not running as root")
	}

	gid, err := resolveGID(groupName)
	if err != nil {
		return err
	}
	uid, err := resolveUID(userName)
	if err != nil {
		return err
	}

	// Clear supplementary groups, then drop group, then drop user.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}

	// Verify the drop actually happened; failing silently would be a
	// security issue.
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("privilege drop failed: still running as root")
	}
	return nil
}
