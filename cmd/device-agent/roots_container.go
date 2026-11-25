//go:build container

package main

// The container image holds this executable and nothing of an operating
// system, so there is no system trust store for TLS to read. This import
// embeds the Mozilla root certificates, which Go uses only when the system
// has none: it is what lets the agent in a pod verify a platform that holds a
// publicly trusted certificate. A platform behind a private CA is pinned with
// PLATFORM_CA_FINGERPRINT, as on a host. Host builds do not carry this.
import _ "golang.org/x/crypto/x509roots/fallback"
