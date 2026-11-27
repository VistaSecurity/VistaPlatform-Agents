//go:build container

package main

// ownHostReported is false in the container image. The sensor's "host" there
// is its pod: a hostname that is the pod's name and an address that changes
// with every replacement. Reported, the platform would record each pod as a
// server asset of its own, and a new one after every restart, upgrade or node
// drain. The heartbeat's Host block is optional (an absent block means
// "unchanged" to the platform), so the image simply never sends it.
const ownHostReported = false
