package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vistasecurity/vistaplatform-agents/shared/agentlogs"
)

// agentLogRing holds this process's most recent log lines, tee'd off the
// standard logger in main, for the console's Logs tab. Process-wide because
// the standard logger is.
var agentLogRing = agentlogs.NewRing(agentlogs.MaxLines)

// deviceAgentLogFileName is the agent's log under <data_path>/logs when it
// runs as a Windows service. install-device-agent.ps1 points operators at it
// and reads it to tell a rejected key from a slow network, so renaming it
// means changing the installer too.
const deviceAgentLogFileName = "device-agent.log"

// deviceAgentLogMaxBytes caps device-agent.log before it rotates to
// device-agent.log.1; one backup is kept.
const deviceAgentLogMaxBytes = 10 << 20

// teeLogToFile adds <dataPath>/logs/device-agent.log to the standard logger's
// outputs, alongside the in-memory ring (and stderr when alsoStderr). The ring
// already holds what was logged before the data path was known, so those
// lines are copied into the file first.
func teeLogToFile(dataPath string, alsoStderr bool) (string, error) {
	if strings.TrimSpace(dataPath) == "" {
		return "", fmt.Errorf("no data path configured")
	}
	path := filepath.Join(dataPath, "logs", deviceAgentLogFileName)
	var extra []io.Writer
	if alsoStderr {
		extra = append(extra, os.Stderr)
	}
	if err := agentlogs.TeeStandardLog(path, deviceAgentLogMaxBytes, agentLogRing.Tail(0), agentLogRing, extra...); err != nil {
		return "", err
	}
	return path, nil
}
