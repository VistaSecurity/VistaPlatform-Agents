//go:build container

package main

import "testing"

// Run with the image's tags (go test -tags container,nocapture ./cmd/sensor/):
// the build that goes into the container image never reports its own host.
func TestOwnHost_ContainerBuildDoesNotReport(t *testing.T) {
	if ownHostReported || reportOwnHost {
		t.Fatal("the container build reports its pod as the sensor's host")
	}
}
