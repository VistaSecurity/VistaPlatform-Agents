//go:build !windows

package main

import (
	"fmt"
	"os"
)

// checkCredentialsFileMode refuses a credentials file that group or others can
// read or write: the file holds a device administrator's password, and the
// managed agent's own configuration is held to the same owner-only rule.
func checkCredentialsFileMode(path string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("the credentials file %s is accessible by group or others (mode %#o); "+
			"restrict it with: chmod 600 %s", path, perm, path)
	}
	return nil
}
