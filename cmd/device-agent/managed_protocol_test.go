package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/api"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// D-P2: an enrollment the platform answered without protocol 1, or in breach
// of it, exits 78 like a rejected key — the installers' units do not restart
// it into the same answer. Anything else may clear, and exits 1.
func TestRegistrationFailureExitCode_ProtocolRefusalsNeedTheOperator(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{&managedprotocol.IncompatibleError{}, exitNeedsOperator},
		{fmt.Errorf("registration: %w", &managedprotocol.IncompatibleError{PlatformVersion: 2}), exitNeedsOperator},
		{&managedprotocol.ViolationError{Reason: "client_key"}, exitNeedsOperator},
		{&api.RegistrationRejectedError{StatusCode: 400}, exitNeedsOperator},
		{errors.New("connection refused"), 1},
	} {
		if got := registrationFailureExitCode(c.err); got != c.want {
			t.Errorf("registrationFailureExitCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}
