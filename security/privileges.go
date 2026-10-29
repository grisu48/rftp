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

// DropPrivileges permanently drops root privileges to the given user and
// group. Supplementary groups are cleared first, then the group and
// finally the user ID are set. Dropping privileges is irreversible, so a
// failure to actually change the effective IDs is reported as an error.
//
// It must be called after binding the listener and (optionally) chrooting,
// and requires root.
func DropPrivileges(userName, groupName string) error {
	if !IsRoot() {
		return errors.New("cannot drop privileges: not running as root")
	}

	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("lookup group %q: %w", groupName, err)
	}
	usr, err := user.Lookup(userName)
	if err != nil {
		return fmt.Errorf("lookup user %q: %w", userName, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q for group %q: %w", grp.Gid, groupName, err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("parse uid %q for user %q: %w", usr.Uid, userName, err)
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
