//go:build !windows

package agentoutput

import "os"

// createOwnerOnly creates the temporary output file 0600, as every output
// file is on Linux and macOS: os.CreateTemp makes it so from the start.
func createOwnerOnly(dir, prefix string, _ bool) (*os.File, error) {
	return os.CreateTemp(dir, prefix+"*")
}
