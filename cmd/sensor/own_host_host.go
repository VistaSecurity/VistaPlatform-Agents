//go:build !container

package main

// ownHostReported: a sensor on a host reports that host (the heartbeat's Host
// block), so the platform can name it as an asset. See own_host_container.go
// for the container image.
const ownHostReported = true
