package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vistasecurity/vistaplatform-agents/shared/agentlogs"
)

// sensorLogFileName is the sensor's log under <dataPath>/logs. The installers
// point operators at it, so renaming it means changing install-sensor.ps1 too.
const sensorLogFileName = "sensor.log"

// sensorLogMaxBytes caps sensor.log before it rotates to sensor.log.1. One
// backup is kept, so the log never holds more than twice this on disk. A
// verbose sensor logs every discovery, and a service runs for months.
const sensorLogMaxBytes = 10 << 20

// teeLogToFile adds <dataPath>/logs/sensor.log to the standard logger's
// outputs, alongside the in-memory ring (and stderr when alsoStderr). The ring
// already holds what was logged before the data path was known, so those
// lines are copied into the file first.
func teeLogToFile(dataPath string, alsoStderr bool) (string, error) {
	if strings.TrimSpace(dataPath) == "" {
		return "", fmt.Errorf("no data path configured")
	}
	path := filepath.Join(dataPath, "logs", sensorLogFileName)
	var extra []io.Writer
	if alsoStderr {
		extra = append(extra, os.Stderr)
	}
	if err := agentlogs.TeeStandardLog(path, sensorLogMaxBytes, logRing.tail(0), logRing, extra...); err != nil {
		return "", err
	}
	return path, nil
}
