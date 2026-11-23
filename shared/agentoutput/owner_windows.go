//go:build windows

package agentoutput

// giveToSudoUser: Windows has no sudo, and the file belongs to the account
// that ran the command.
func giveToSudoUser(string) error { return nil }
