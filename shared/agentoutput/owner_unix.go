//go:build !windows

package agentoutput

import (
	"os"
	"strconv"
)

// giveToSudoUser hands a file the run created back to the person who ran the
// command with sudo, so they can read their own result: live capture needs
// root, and a 0600 file owned by root is unreadable to the user who asked for
// it. It does nothing unless the process runs as root with SUDO_UID and
// SUDO_GID set (sudo sets both).
func giveToSudoUser(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 {
		return nil
	}
	return os.Chown(path, uid, gid)
}
