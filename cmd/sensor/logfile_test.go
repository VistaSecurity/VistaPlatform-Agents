package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// teeLogToFile is what gives a Windows service a log at all: stderr goes
// nowhere there. The file must start with what was logged before the data
// path was known, keep the in-memory ring fed (export_logs), and receive
// everything after.
func TestTeeLogToFile_BackfillsTheRingAndKeepsItFed(t *testing.T) {
	savedRing, savedOut, savedFlags := logRing, log.Writer(), log.Flags()
	t.Cleanup(func() {
		logRing = savedRing
		log.SetOutput(savedOut)
		log.SetFlags(savedFlags)
	})
	logRing = newLogRingBuffer(100)
	log.SetFlags(0)
	log.SetOutput(logRing)

	log.Println("before the config was loaded")

	dataPath := t.TempDir()
	path, err := teeLogToFile(dataPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dataPath, "logs", "sensor.log"); path != want {
		t.Fatalf("log path = %q, want %q (the installer points operators there)", path, want)
	}

	log.Println("after")

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "before the config was loaded\nafter\n" {
		t.Fatalf("log file = %q", got)
	}
	if tail := logRing.tail(0); len(tail) != 2 || tail[1] != "after" {
		t.Fatalf("ring = %q: export_logs must still see new lines", tail)
	}
}

func TestTeeLogToFile_RequiresADataPath(t *testing.T) {
	savedOut := log.Writer()
	t.Cleanup(func() { log.SetOutput(savedOut) })
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if _, err := teeLogToFile("  ", false); err == nil {
		t.Fatal("expected an error for an empty data path")
	}
	if log.Writer() != &buf {
		t.Fatal("a failed tee must leave the logger's output alone")
	}
}
