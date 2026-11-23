//go:build windows

package main

import "os"

// checkCredentialsFileMode does nothing on Windows: a file's mode bits there
// do not say who can read it (that is its ACL), so a Unix-style check would
// either refuse every file or pass every file. Keep the file in a directory
// only the operator's account can read.
func checkCredentialsFileMode(_ string, _ os.FileInfo) error {
	return nil
}
