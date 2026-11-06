//go:build !windows

package agentservice

// RunIfService has no Service Control Manager to talk to outside Windows: the
// agent always runs as a console process (which is also how systemd and
// launchd run it).
func RunIfService(Service) bool { return false }
