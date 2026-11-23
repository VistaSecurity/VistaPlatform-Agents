package main

// crypto-sensor capture: passive decoding of a capture file or of one
// interface for a fixed time, through the managed sensor's own decoders. It
// sends no packets: no TLS enricher, no prober, no API client, no heartbeat
// and no registration is constructed on this path.

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
)

func runCapture(env standaloneEnv, args []string) int {
	var (
		pcapPath string
		iface    string
		duration time.Duration
		output   outputFlags
	)
	fs := newFlagSet(env, "capture", "--pcap FILE | --interface IF --duration D [output flags]",
		"Decode TLS, SSH, STARTTLS, QUIC, IKE, WireGuard, OpenVPN, SMB, Kerberos, the OT protocols and\n"+
			"host-observation traffic (ARP, DHCP, mDNS, NetBIOS, LLDP, CDP) passively, from a capture\n"+
			"file or one interface. Passive only: it sends no packets. Live capture needs the privileges\n"+
			"the managed sensor needs (root or the capture capabilities on Linux, Npcap on Windows).")
	fs.StringVar(&pcapPath, "pcap", "", "read the capture `FILE` (pcap or pcapng) to the end; needs no privileges")
	fs.StringVar(&iface, "interface", "", "capture live on interface `IF` (needs --duration)")
	fs.DurationVar(&duration, "duration", 0, "how long to capture live, e.g. 10m (required with --interface; Ctrl-C ends early)")
	output.register(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	switch {
	case pcapPath == "" && iface == "":
		return usageError(env, "capture", "name what to read: --pcap FILE, or --interface IF --duration D")
	case pcapPath != "" && iface != "":
		return usageError(env, "capture", "--pcap and --interface cannot be used together: one run reads one source")
	case iface != "" && duration <= 0:
		return usageError(env, "capture", "--interface needs --duration (for example --duration 10m), so the run always ends")
	case pcapPath != "" && duration != 0:
		return usageError(env, "capture", "--duration applies to --interface only: a capture file is read to its end")
	}
	opts, err := output.options(env)
	if err != nil {
		return usageError(env, "capture", "%v", err)
	}
	defer output.quietLogs(env)()

	source := pcapPath
	if iface != "" {
		source = iface
	}
	w, err := agentoutput.Open(opts, agentoutput.Run{Command: "capture", Flags: setFlags(fs), Targets: []string{source}})
	if err != nil {
		return usageError(env, "capture", "%v", err)
	}

	cfg := standaloneCaptureConfig(iface)
	var pc *capture.PacketCapture
	if pcapPath != "" {
		pc = capture.NewFileCapture(cfg)
	} else {
		pc = capture.NewPacketCapture(cfg)
	}

	// Everything the decoders emit is written as it arrives; the channel
	// closes when the capture has stopped and flushed, and the run ends after
	// the last record.
	var drained sync.WaitGroup
	var writeErrs []error
	drained.Go(func() {
		for d := range pc.GetDiscoveries() {
			if err := w.Write(agentoutput.KindPassiveObservation, d, endpointsOf(d)...); err != nil {
				writeErrs = append(writeErrs, err)
			}
		}
	})
	drained.Go(func() {
		for err := range pc.GetErrors() {
			_ = w.Error(source, "capture", err.Error())
		}
	})

	nothingWorked := false
	partial := false
	var scope string
	if pcapPath != "" {
		err := pc.RunFile(env.ctx, pcapPath)
		drained.Wait()
		packets, _ := pc.GetStats()
		if err != nil {
			_ = w.Error(pcapPath, "capture", err.Error())
			nothingWorked = packets == 0
		}
		if env.ctx.Err() != nil {
			w.Warn("interrupted: the file was not read to its end")
			partial = true
		}
		scope = fmt.Sprintf("capture file %s: %s", pcapPath, plural(packets, "packet"))
	} else {
		started := time.Now()
		if err := pc.Start(); err != nil {
			pc.Stop()
			drained.Wait()
			_ = w.Error(iface, "capture", err.Error())
			nothingWorked = true
		} else {
			timer := time.NewTimer(duration)
			select {
			case <-timer.C:
			case <-env.ctx.Done():
				timer.Stop()
				w.Warn("interrupted after %s of the %s asked for", time.Since(started).Round(time.Second), duration)
				partial = true
			}
			pc.Stop()
			drained.Wait()
		}
		packets, drops := pc.GetStats()
		if drops > 0 {
			w.Warn("%s dropped because the decoders could not keep up", plural(drops, "packet"))
			partial = true
		}
		scope = fmt.Sprintf("interface %s for %s: %s", iface, duration, plural(packets, "packet"))
	}
	for _, err := range writeErrs {
		w.Warn("an observation could not be written: %v", err)
		partial = true
	}
	sum, err := w.Close(partial, scope)
	return agentoutput.ExitCode(sum, err, nothingWorked)
}

// standaloneCaptureConfig is the decoders' configuration for a standalone
// capture: the managed sensor's defaults (config.Load: built-in defaults,
// overridable by the same environment variables), with everything that would
// send a packet off and nothing tied to a platform.
func standaloneCaptureConfig(iface string) *config.Config {
	cfg := config.Load()
	cfg.SensorID = "standalone"
	cfg.ControlPlaneURL = ""
	cfg.RegistrationKey = ""
	cfg.Capture.ActiveProbing = false
	cfg.Capture.ThirdPartyTLSEnrichment = false
	cfg.Capture.OwnedNetworks = nil
	cfg.Capture.Interfaces = nil
	if iface != "" {
		cfg.Capture.Interfaces = []string{iface}
	}
	return cfg
}

// endpointsOf is the CSV view of one passive observation: the service it
// shows, with the leaf certificate when the handshake carried one. A host
// observation (no port) shows no endpoint.
func endpointsOf(d *models.CryptoDiscovery) []agentoutput.Endpoint {
	if d == nil || d.Port <= 0 || d.DiscoveryType == "host_observation" {
		return nil
	}
	e := agentoutput.Endpoint{
		Address:         d.DestIP,
		Port:            d.Port,
		Transport:       passiveTransport(d),
		Protocol:        d.Protocol,
		ProtocolVersion: d.Version,
		CipherSuite:     d.CipherSuite,
		Source:          d.DiscoveryMethod,
	}
	md := d.RawMetadata
	e.Host = metaString(md, "sni")
	e.KeyExchange = metaString(md, "key_exchange_algorithm")
	if leaf := leafCertificate(md["certificates"]); leaf != nil {
		e.CertificateSubject = metaString(leaf, "subject_dn")
		e.CertificateIssuer = metaString(leaf, "issuer_dn")
		e.CertificateNotAfter = metaString(leaf, "not_after")
		e.CertificateKeyAlgorithm = metaString(leaf, "key_algorithm")
		e.CertificateKeySize = metaInt(leaf, "key_size")
		e.CertificateSignatureAlgorithm = metaString(leaf, "signature_alg")
		e.CertificateFingerprintSHA256 = metaString(leaf, "fingerprint_sha256")
	}
	return []agentoutput.Endpoint{e}
}

// passiveTransport is the observation's transport: what the decoder recorded,
// else what the protocol runs over. "" when the protocol runs over both and
// the decoder did not say (Kerberos).
func passiveTransport(d *models.CryptoDiscovery) string {
	if t := metaString(d.RawMetadata, "transport"); t != "" {
		return t
	}
	switch d.Protocol {
	case "QUIC", "IKE", "WireGuard", "OpenVPN":
		return "udp"
	case "Kerberos", "DNP3", "HART_IP":
		return ""
	}
	return "tcp"
}

// leafCertificate is the leaf of the canonical certificates array: the entry
// with chain_order 0, else the first.
func leafCertificate(v any) map[string]any {
	var certs []map[string]any
	switch list := v.(type) {
	case []any:
		for _, c := range list {
			if m, ok := c.(map[string]any); ok {
				certs = append(certs, m)
			}
		}
	case []map[string]any:
		certs = list
	}
	for _, c := range certs {
		if metaInt(c, "chain_order") == 0 {
			if _, ok := c["chain_order"]; ok {
				return c
			}
		}
	}
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

func metaString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	}
	return ""
}

func metaInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func plural(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "s") {
		return fmt.Sprintf("%d %ses", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
