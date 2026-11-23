package main

// crypto-sensor scan: an active scan of targets the operator names, on the
// scan engine the managed sensor runs for a platform job
// (shared/sensordispatch/planrun). The named targets are the whole scope: the
// allow rule is built from them (planrun.NamedTargetsRule), every dial and
// every certificate-driven fetch passes it, reserved addresses are refused
// even when named, and a public address needs --allow-public.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	"github.com/vistasecurity/vistaplatform-agents/shared/discovery"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch/planrun"
)

// scanResolveTimeout bounds the one resolution of each hostname target.
const scanResolveTimeout = 10 * time.Second

// privatePrefixes is the address space a scan needs no --allow-public for:
// RFC 1918, shared address space (RFC 6598) and unique local IPv6 (RFC 4193).
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// reservedPrefixes are refused by the scan rule whatever --allow-public says
// (planrun's reserved set), so a target inside them is not called public: it
// is refused, with that reason, when the scan reaches it.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// scanTarget is one target as the operator named it.
type scanTarget struct {
	input string
	// prefixes are the addresses it names; for a hostname, its resolved
	// addresses as /32 or /128.
	prefixes []netip.Prefix
	hostname bool
	pinned   []string
}

func runScan(env standaloneEnv, args []string) int {
	var (
		targets     stringList
		targetsFile string
		depthFlag   string
		paceFlag    string
		allowPublic bool
		timeout     time.Duration
		output      outputFlags
	)
	fs := newFlagSet(env, "scan", "--target T [--target T ...] | --targets-file FILE [flags]",
		"Actively scan the targets named here, and nothing else, on the managed sensor's scan engine:\n"+
			"liveness, the depth's TCP (and UDP) ports, and identification of what answers (TLS, SSH,\n"+
			"SMB, ...). Reserved addresses (loopback, link-local, multicast, broadcast) are always\n"+
			"refused. OT protocol probes are not offered.")
	fs.Var(&targets, "target", "a `TARGET` to scan: an address, a CIDR range, an a-b range or a hostname (repeatable)")
	fs.StringVar(&targetsFile, "targets-file", "", "read targets from `FILE`, one per line; # starts a comment")
	fs.StringVar(&depthFlag, "depth", string(discovery.DepthStandard), "port preset: quick, standard or thorough")
	fs.StringVar(&paceFlag, "pace", string(discovery.PacePolite), "concurrency and timeouts: polite, normal or fast")
	fs.BoolVar(&allowPublic, "allow-public", false, "allow targets outside private address space: you state that you own them or are authorised to scan them")
	fs.DurationVar(&timeout, "timeout", 0, "stop the whole scan after this long, e.g. 30m (default: no limit); what finished is written")
	output.register(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	inputs := append([]string(nil), targets...)
	if targetsFile != "" {
		fromFile, err := readTargetsFile(targetsFile)
		if err != nil {
			return usageError(env, "scan", "%v", err)
		}
		inputs = append(inputs, fromFile...)
	}
	if len(inputs) == 0 {
		return usageError(env, "scan", "name what to scan: --target T (repeatable) or --targets-file FILE")
	}
	depth := discovery.ScanDepth(strings.ToLower(strings.TrimSpace(depthFlag)))
	switch depth {
	case discovery.DepthQuick, discovery.DepthStandard, discovery.DepthThorough:
	default:
		return usageError(env, "scan", "--depth %q is not one of quick, standard, thorough", depthFlag)
	}
	shape, err := discovery.ResolveJobRequest(discovery.JobRequestFields{ScanDepth: string(depth), Pace: paceFlag})
	if err != nil {
		return usageError(env, "scan", "%v", err)
	}
	spec := shape.Spec
	if timeout < 0 {
		return usageError(env, "scan", "--timeout must be positive")
	}
	opts, err := output.options(env)
	if err != nil {
		return usageError(env, "scan", "%v", err)
	}

	// Every target is parsed and sized before anything is resolved or sent.
	var parsed []*scanTarget
	var ranges []string
	for _, in := range inputs {
		t, err := parseScanTarget(in)
		if err != nil {
			return usageError(env, "scan", "%v", err)
		}
		parsed = append(parsed, t)
		if !t.hostname {
			ranges = append(ranges, t.input)
		}
	}
	if err := discovery.CheckTargetSizes(ranges); err != nil {
		return usageError(env, "scan", "%v", err)
	}
	defer output.quietLogs(env)()

	// Each hostname is resolved once; the scan connects to these addresses
	// only, and offers the name as SNI.
	resolved := map[string][]string{}
	unresolved := map[string]string{}
	for _, t := range parsed {
		if !t.hostname {
			continue
		}
		addrs, err := resolveOnce(env, t.input)
		if err != nil {
			unresolved[t.input] = err.Error()
			continue
		}
		for _, a := range addrs {
			t.pinned = append(t.pinned, a.String())
			t.prefixes = append(t.prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
		resolved[t.input] = t.pinned
	}

	var public []string
	for _, t := range parsed {
		if targetIsPublic(t) {
			public = append(public, t.input)
		}
	}
	if len(public) > 0 && !allowPublic {
		return usageError(env, "scan", "%s outside private address space; nothing was sent. "+
			"Add --allow-public only if you own these addresses or are authorised to scan them",
			describeList(public, "is", "are"))
	}

	var allowed []netip.Prefix
	var planInputs []discovery.PlanTargetInput
	byInput := map[string]*scanTarget{}
	for _, t := range parsed {
		if _, dup := byInput[t.input]; dup || (t.hostname && len(t.pinned) == 0) {
			continue
		}
		byInput[t.input] = t
		allowed = append(allowed, t.prefixes...)
		class := discovery.ClassPrivate
		if targetIsPublic(t) {
			class = discovery.ClassExternal
		}
		planInputs = append(planInputs, discovery.PlanTargetInput{Target: t.input, Class: class})
	}
	plan, err := discovery.BuildScanPlan(spec, nil, planInputs)
	if err != nil {
		return usageError(env, "scan", "%v", err)
	}

	run := agentoutput.Run{Command: "scan", Flags: setFlags(fs), Targets: inputs, Resolved: resolved}
	for _, adj := range plan.DepthAdjustments {
		run.Notes = append(run.Notes, fmt.Sprintf("%s scanned at %s, not %s: public address space is scanned at standard depth at most", adj.Target, adj.Applied, adj.Requested))
	}
	w, err := agentoutput.Open(opts, run)
	if err != nil {
		return usageError(env, "scan", "%v", err)
	}
	for _, name := range sortedKeys(unresolved) {
		_ = w.Error(name, "resolve", "not scanned: the name did not resolve: "+unresolved[name])
	}

	payload := sensordispatch.PlanPayload{Version: sensordispatch.PlanPayloadVersion, Attempt: 1, Pace: spec.Pace}
	rep := &scanReporter{w: w, names: map[string]string{}}
	var addresses int
	for _, pt := range plan.Targets {
		t := byInput[pt.Target]
		work := sensordispatch.PlanTargetWork{PlanTarget: pt, TargetID: uuid.NewString()}
		if t.hostname {
			work.PinnedAddresses = t.pinned
			addresses += len(t.pinned)
		} else {
			addresses += int(pt.Addresses)
		}
		rep.names[work.TargetID] = pt.Target
		payload.Targets = append(payload.Targets, work)
	}

	nothingWorked := len(payload.Targets) == 0
	partial := false
	if len(payload.Targets) > 0 {
		ctx := env.ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		allow := planrun.NamedTargetsRule(allowed)
		logf := func(string, ...interface{}) {}
		if output.verbose {
			logf = func(format string, args ...interface{}) { _, _ = fmt.Fprintf(env.stderr, format+"\n", args...) }
		}
		sum, err := planrun.Run(ctx, payload, planrun.Config{
			Allow: allow,
			// A scanned certificate's OCSP responder is not a named target:
			// the same rule refuses it, so the run touches nothing else.
			OutboundGuard: discovery.AddressGuard(allow),
			Reporter:      rep,
			Dialer:        env.dialer,
			// Nothing to renew: a standalone run has no lease.
			PingInterval: 24 * time.Hour,
			Logf:         logf,
		})
		switch {
		case err != nil && ctx.Err() != nil:
			reason := "interrupted"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				reason = fmt.Sprintf("--timeout %s reached", timeout)
			}
			w.Warn("%s: %d of %d addresses were not scanned", reason, sum.Units-sum.Done-sum.Failed, sum.Units)
			partial = true
		case err != nil:
			_ = w.Error("", "scan", err.Error())
		}
		nothingWorked = sum.Done == 0
	}
	scope := fmt.Sprintf("%s in %s, depth %s, pace %s", plural(int64(addresses), "address"), plural(int64(len(inputs)), "target"), spec.Depth, spec.Pace)
	sum, err := w.Close(partial, scope)
	return agentoutput.ExitCode(sum, err, nothingWorked)
}

// readTargetsFile reads one target per line; # starts a comment.
func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the targets file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return parseTargetsList(f)
}

func parseTargetsList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the targets file: %w", err)
	}
	return out, nil
}

// parseScanTarget accepts an address, a CIDR range, an IPv4 a-b range or a
// hostname, and refuses anything else before the engine could take it for a
// name.
func parseScanTarget(raw string) (*scanTarget, error) {
	in := strings.TrimSpace(raw)
	if in == "" {
		return nil, errors.New("an empty target")
	}
	if a, err := netip.ParseAddr(in); err == nil {
		if a.Zone() != "" {
			return nil, fmt.Errorf("target %q: an address with a zone cannot be scanned", raw)
		}
		a = a.Unmap()
		return &scanTarget{input: a.String(), prefixes: []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}}, nil
	}
	if strings.Contains(in, "/") {
		p, err := netip.ParsePrefix(in)
		if err != nil {
			return nil, fmt.Errorf("target %q is not a CIDR range: %v", raw, err)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("target %q: write an IPv4 range in IPv4 form", raw)
		}
		return &scanTarget{input: p.Masked().String(), prefixes: []netip.Prefix{p.Masked()}}, nil
	}
	if discovery.IsNetworkRange(in) {
		parts := strings.SplitN(in, "-", 2)
		start, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		end, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || !start.Is4() || !end.Is4() {
			return nil, fmt.Errorf("target %q is not an IPv4 a-b range (ranges are IPv4 only; use CIDR for IPv6)", raw)
		}
		if end.Less(start) {
			return nil, fmt.Errorf("target %q is a range that ends before it starts", raw)
		}
		return &scanTarget{input: start.String() + "-" + end.String(), prefixes: rangePrefixes(start, end)}, nil
	}
	if !validHostname(in) {
		return nil, fmt.Errorf("target %q is not an address, a CIDR range, an a-b range or a hostname", raw)
	}
	return &scanTarget{input: strings.ToLower(strings.TrimSuffix(in, ".")), hostname: true}, nil
}

// validHostname reports whether s is a DNS name: dot-separated labels of
// letters, digits, hyphens and underscores, none starting or ending with a
// hyphen.
func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// rangePrefixes is the smallest set of prefixes covering exactly start..end
// (IPv4).
func rangePrefixes(start, end netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for {
		bits := 32
		// Widen while the wider prefix starts at start and stays inside end.
		for bits > 0 {
			wider := netip.PrefixFrom(start, bits-1).Masked()
			if wider.Addr() != start || lastAddr(wider).Compare(end) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(start, bits)
		out = append(out, p)
		last := lastAddr(p)
		if last.Compare(end) >= 0 || !last.Next().IsValid() {
			return out
		}
		start = last.Next()
	}
}

// lastAddr is the last address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	if p.Bits() == 0 {
		host = ^uint32(0)
	}
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= host
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// resolveOnce resolves a hostname target with a bounded timeout. IPv4
// addresses are preferred when there are any, as the engine's own expansion
// does; the order is the resolver's.
func resolveOnce(env standaloneEnv, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(env.ctx, scanResolveTimeout)
	defer cancel()
	addrs, err := env.lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	if len(v4) > 0 {
		return v4, nil
	}
	if len(v6) == 0 {
		return nil, errors.New("no addresses")
	}
	return v6, nil
}

// targetIsPublic reports whether any address a target names is outside
// private space and outside the reserved ranges (which are refused anyway).
func targetIsPublic(t *scanTarget) bool {
	for _, p := range t.prefixes {
		if !insideAny(p, privatePrefixes) && !insideAny(p, reservedPrefixes) {
			return true
		}
	}
	return false
}

// insideAny reports whether p lies wholly inside one of list.
func insideAny(p netip.Prefix, list []netip.Prefix) bool {
	for _, q := range list {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func describeList(items []string, one, many string) string {
	if len(items) == 1 {
		return items[0] + " " + one
	}
	return strings.Join(items, ", ") + " " + many
}

// scanReporter writes each host the engine finishes.
type scanReporter struct {
	w     *agentoutput.Writer
	mu    sync.Mutex
	names map[string]string // target id -> the target as named
}

// scanHostData is a scan_host record's data: the managed protocol's unit
// result, with the target as the operator named it.
type scanHostData struct {
	Target string `json:"target"`
	sensordispatch.UnitResult
}

func (r *scanReporter) Report(_ context.Context, units []sensordispatch.UnitResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range units {
		target := r.names[u.TargetID]
		if u.Failed {
			if err := r.w.Error(u.Address, "scan", u.Error); err != nil {
				return err
			}
			continue
		}
		if err := r.w.Write(agentoutput.KindScanHost, scanHostData{Target: target, UnitResult: u}, scanEndpoints(target, u)...); err != nil {
			return err
		}
	}
	return nil
}

// scanEndpoints is the CSV view of one host: a row per port that answered,
// with what identification learned there.
func scanEndpoints(target string, u sensordispatch.UnitResult) []agentoutput.Endpoint {
	host := ""
	if discovery.PlanTargetHostname(target) != "" {
		host = target
	}
	var out []agentoutput.Endpoint
	for _, list := range [][]discovery.Observation{u.TCP, u.UDP} {
		for _, o := range list {
			if o.State != "open" && !o.Identified {
				continue
			}
			e := agentoutput.Endpoint{Host: host, Address: u.Address, Port: o.Port, Transport: o.Transport, Protocol: o.Protocol, Source: "scan"}
			if res := o.Result; res != nil {
				if len(res.TLSVersions) > 0 {
					e.ProtocolVersion = res.TLSVersions[0]
				}
				e.CipherSuite = res.SelectedCipher
				e.KeyExchange = metaString(res.Metadata, discovery.MetaKeyExchangeAlgorithm)
				if res.SSHProtocolVersion != "" {
					e.ProtocolVersion = res.SSHProtocolVersion
					e.KeyExchange = res.SSHKexAlgorithm
					e.CipherSuite = res.SSHEncryptionAlgS2C
				}
				if len(res.Certificates) > 0 {
					leaf := res.Certificates[0]
					for _, c := range res.Certificates {
						if c.ChainOrder == 0 {
							leaf = c
							break
						}
					}
					e.CertificateSubject = leaf.SubjectDN
					e.CertificateIssuer = leaf.IssuerDN
					if !leaf.NotAfter.IsZero() {
						e.CertificateNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
					}
					e.CertificateKeyAlgorithm = leaf.KeyAlgorithm
					e.CertificateKeySize = leaf.KeySize
					e.CertificateSignatureAlgorithm = leaf.SignatureAlg
					e.CertificateFingerprintSHA256 = leaf.FingerprintSHA256
				}
			}
			out = append(out, e)
		}
	}
	return out
}
