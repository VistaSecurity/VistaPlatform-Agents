package main

import (
	"log"
	"os"

	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// exitNeedsOperator is the exit status for a start that can only be fixed by a
// person: a registration key the control plane rejected, a platform that does
// not speak managed protocol 1, or a config file that cannot be parsed. It is sysexits.h EX_CONFIG. The installer's systemd unit
// names it in RestartPreventExitStatus, so the service stops instead of
// re-trying the same doomed start every RestartSec.
const exitNeedsOperator = 78

// exitProcess is os.Exit, replaceable so tests can observe the status.
var exitProcess = os.Exit

// isProtocolRefusal reports whether a registration failed because this sensor
// and the platform do not share managed protocol 1: an answer that named no
// version or another one, a 426, or an answer that broke protocol 1. Retrying
// returns the same answer; only an operator can change the agent or the
// platform.
func isProtocolRefusal(err error) bool {
	return managedprotocol.IsIncompatible(err) || managedprotocol.IsViolation(err)
}

// logProtocolRefusal says why the sensor stops, in the line the managed
// protocol specifies (D-P2), and what to do about it.
func logProtocolRefusal(err error) {
	log.Printf("⛔ %v", err)
	log.Printf("⛔ Install the agent version the platform lists under Discovery → Sensors & Agents, or upgrade the platform; the sensor stops (exit %d) so it is not restarted into the same answer.", exitNeedsOperator)
}
