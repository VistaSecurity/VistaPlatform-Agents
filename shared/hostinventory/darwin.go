package hostinventory

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// The macOS command set.
var (
	darwinCmdSwVers   = []string{"sw_vers"}
	darwinCmdKernel   = []string{"uname", "-r"}
	darwinCmdNodename = []string{"uname", "-n"}
	darwinCmdHostname = []string{"hostname", "-f"}

	darwinCmdHardware = []string{"system_profiler", "SPHardwareDataType", "-json"}

	darwinCmdPkgutil = []string{"pkgutil", "--pkgs"}
	darwinCmdApps    = []string{"find", "/Applications", "-maxdepth", "3", "-name", "Info.plist", "-type", "f"}

	// netstat is the socket source. `-v` adds the owning process, `-l` prints
	// IPv6 addresses whole (without it they are cut to the column width).
	darwinCmdNetstatTCP = []string{"netstat", "-anvl", "-p", "tcp"}
	darwinCmdNetstatUDP = []string{"netstat", "-anvl", "-p", "udp"}
	darwinCmdID         = []string{"id", "-u"}

	// lsof is the fallback, for a host where netstat does not answer. See
	// collectDarwinListeners for what it can and cannot see.
	darwinCmdLsof            = []string{"lsof", "-nP", "-iTCP", "-sTCP:LISTEN"}
	darwinCmdLsofUDP         = []string{"lsof", "-nP", "-iUDP"}
	darwinCmdLsofConnections = []string{"lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"}
	darwinCmdIfconfig        = []string{"ifconfig", "-a"}
)

// darwinCertStorePaths are the FILE-based trust stores macOS exposes.
//
// The System and login Keychains are deliberately NOT read. Reading a keychain
// means `security` prompting for, or being granted, access to a store that also
// holds private keys and passwords — a different capability with a different
// risk profile, and not one a host inventory needs to take on.
var darwinCertStorePaths = []string{
	"/etc/ssl/cert.pem",
	"/private/etc/ssl/certs",
}

// maxDarwinApps bounds the /Applications scan — one ReadFile per bundle.
const maxDarwinApps = 250

func collectDarwin(ctx context.Context, r Runner, rep *Report, opts Options) {
	collectDarwinHost(ctx, r, rep)
	collectDarwinHardware(ctx, r, rep)
	collectDarwinInterfaces(ctx, r, rep, opts)
	collectDarwinPackages(ctx, r, rep, opts)
	sockets := collectDarwinListeners(ctx, r, rep)
	collectDarwinConnections(ctx, r, rep, opts, sockets)
	collectCertStoresUnix(ctx, r, rep, darwinCertStorePaths, opts)
}

func collectDarwinHost(ctx context.Context, r Runner, rep *Report) {
	var problems []string

	if out, err := runText(ctx, r, darwinCmdSwVers); err == nil {
		name, version, build := ParseSwVers([]byte(out))
		rep.Host.OS = name
		rep.Host.OSVersion = version
		// The build is the identifier beneath the marketing version — the same
		// role the kernel release plays on Linux — but the kernel release is
		// what os.kernel is registered to mean, so the build rides in neither
		// place unless uname fails.
		if build != "" && rep.Host.Kernel == "" {
			rep.Host.Kernel = build
		}
	} else {
		problems = append(problems, err.Error())
	}

	if out, err := runText(ctx, r, darwinCmdKernel); err == nil {
		rep.Host.Kernel = strings.TrimSpace(out)
	} else {
		problems = append(problems, err.Error())
	}

	if out, err := runText(ctx, r, darwinCmdNodename); err == nil {
		// macOS nodenames commonly carry ".local" from mDNS. Keep the short
		// name here; the FQDN probe below decides whether there is a real one.
		short, _ := splitFQDN(strings.TrimSpace(out))
		rep.Host.Hostname = short
	} else {
		problems = append(problems, err.Error())
	}

	if out, err := runText(ctx, r, darwinCmdHostname); err == nil {
		if short, domain := splitFQDN(out); domain != "" && !strings.EqualFold(domain, "local") {
			// ".local" is mDNS, not a DNS domain. Recording it as an FQDN would
			// give every Mac on every network the same domain.
			rep.Host.FQDN = short + "." + domain
			rep.Host.Domain = domain
		}
	}

	if len(problems) > 0 {
		rep.fail(SectionHost, errors.New(strings.Join(problems, "; ")))
		return
	}
	rep.mark(SectionHost, SectionOK)
}

// ParseSwVers parses `sw_vers` key/value output.
func ParseSwVers(b []byte) (name, version, build string) {
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ProductName":
			name = value
		case "ProductVersion":
			version = value
		case "BuildVersion":
			build = value
		}
	}
	return name, version, build
}

// darwinHardware mirrors the shape `system_profiler SPHardwareDataType -json`
// returns. Typed, with json tags, so every field Apple adds is discarded
// structurally — the cloud collectors are safe for exactly this reason.
type darwinHardware struct {
	SPHardwareDataType []struct {
		MachineModel  string `json:"machine_model"`
		MachineName   string `json:"machine_name"`
		ModelNumber   string `json:"model_number"`
		SerialNumber  string `json:"serial_number"`
		PlatformUUID  string `json:"platform_UUID"`
		ProvisionUDID string `json:"provisioning_UDID"`
		BootROM       string `json:"boot_rom_version"`
	} `json:"SPHardwareDataType"`
}

func collectDarwinHardware(ctx context.Context, r Runner, rep *Report) {
	out, err := runText(ctx, r, darwinCmdHardware)
	if err != nil {
		rep.fail(SectionHardware, err)
		return
	}
	hw, perr := ParseDarwinHardware([]byte(out))
	if perr != nil {
		rep.fail(SectionHardware, perr)
		return
	}
	rep.Hardware = hw
	rep.mark(SectionHardware, SectionOK)
}

// ParseDarwinHardware projects system_profiler's hardware block.
//
// provisioning_UDID is deliberately not collected. It is a per-device
// enrolment identifier that ties the machine to an MDM tenancy, and the
// platform UUID and serial already identify the machine.
func ParseDarwinHardware(b []byte) (Hardware, error) {
	var raw darwinHardware
	if err := json.Unmarshal(b, &raw); err != nil {
		return Hardware{}, fmt.Errorf("system_profiler: %w", err)
	}
	if len(raw.SPHardwareDataType) == 0 {
		return Hardware{}, errors.New("system_profiler returned no hardware entry")
	}
	e := raw.SPHardwareDataType[0]
	model := strings.TrimSpace(e.MachineName)
	if model == "" {
		model = strings.TrimSpace(e.MachineModel)
	}
	return Hardware{
		// Every machine running macOS is Apple hardware. This is a derived
		// value, not a measured one, and it is marked as such where the fact is
		// emitted (ConfidenceDerived in observations.go).
		Vendor:   "Apple Inc.",
		Model:    model,
		Serial:   sanitiseDMI(e.SerialNumber),
		UUID:     sanitiseDMI(e.PlatformUUID),
		Firmware: strings.TrimSpace(e.BootROM),
	}, nil
}

func collectDarwinInterfaces(ctx context.Context, r Runner, rep *Report, opts Options) {
	out, err := runText(ctx, r, darwinCmdIfconfig)
	if err == nil {
		rep.Interfaces = ParseIfconfig([]byte(out))
		darwinIPv4Assignments(ctx, r, rep.Interfaces)
		rep.mark(SectionInterfaces, SectionOK)
		return
	}
	if opts.Mode == ModeLocal && opts.LocalInterfaceFallback {
		if ifaces, lerr := localInterfaces(); lerr == nil {
			rep.Interfaces = ifaces
			rep.mark(SectionInterfaces, SectionOK)
			rep.Errors = append(rep.Errors, StepError{
				Step:    SectionInterfaces,
				Message: fmt.Sprintf("ifconfig unavailable (%v); used the local net.Interfaces() fallback", err),
			})
			return
		}
	}
	rep.fail(SectionInterfaces, err)
}

// ParseIfconfig parses BSD `ifconfig -a` output.
func ParseIfconfig(b []byte) []Interface {
	var out []Interface
	var cur *Interface
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			name, rest, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			cur = &Interface{
				Name:    strings.TrimSpace(name),
				State:   "unknown",
				Virtual: isVirtualInterface(name, strings.Contains(rest, "LOOPBACK")),
			}
			continue
		}
		if cur == nil {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "ether", "lladdr":
			cur.MAC = normaliseMAC(f[1])
		case "inet":
			// `inet 198.51.100.10 netmask 0xffffff00 broadcast ...`
			cur.Addresses = append(cur.Addresses, f[1]+maskSuffix(f))
		case "inet6":
			addr := f[1]
			if z := strings.Index(addr, "%"); z >= 0 {
				addr = addr[:z]
			}
			cur.Addresses = append(cur.Addresses, addr+prefixlenSuffix(f))
			// SLAAC and DHCPv6 addresses carry `autoconf` / `dynamic`
			// (and `temporary` for privacy addresses). A manual one carries
			// none of them — but neither does one whose flags this build does
			// not print, so the absence stays unknown.
			for _, flag := range f[2:] {
				if flag == "autoconf" || flag == "dynamic" || flag == "temporary" {
					cur.assign(addr+prefixlenSuffix(f), assignedDynamic)
					break
				}
			}
		case "status:":
			switch strings.TrimSpace(f[1]) {
			case "active":
				cur.State = "up"
			case "inactive":
				cur.State = "down"
			}
		}
	}
	flush()
	return out
}

// maskSuffix turns ifconfig's `netmask 0xffffff00` into "/24". An unparseable
// mask yields no suffix: /32 would claim the interface serves one host and /24
// would invent a segment, and both are statements the host did not make.
func maskSuffix(fields []string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] != "netmask" {
			continue
		}
		raw := strings.TrimPrefix(fields[i+1], "0x")
		v, err := strconv.ParseUint(raw, 16, 32)
		if err != nil {
			return ""
		}
		bits := 0
		for b := 31; b >= 0; b-- {
			if v&(1<<uint(b)) == 0 {
				break
			}
			bits++
		}
		return "/" + strconv.Itoa(bits)
	}
	return ""
}

// prefixlenSuffix turns ifconfig's `prefixlen 64` into "/64".
func prefixlenSuffix(fields []string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "prefixlen" {
			if _, err := strconv.Atoi(fields[i+1]); err == nil {
				return "/" + fields[i+1]
			}
			return ""
		}
	}
	return ""
}

func collectDarwinPackages(ctx context.Context, r Runner, rep *Report, opts Options) {
	var pkgs []Package
	var problems []string

	// Receipts: every installer package that has ever been applied. Names only
	// — `pkgutil --pkgs` prints no version, and asking for one is a command per
	// package. An absent version is honest; a fabricated one is not.
	if out, err := runText(ctx, r, darwinCmdPkgutil); err == nil {
		pkgs = append(pkgs, ParsePkgutil([]byte(out))...)
	} else {
		problems = append(problems, err.Error())
	}

	// Applications: the bundles a user would name if asked what is installed.
	if out, err := runText(ctx, r, darwinCmdApps); err == nil {
		plists := strings.Split(strings.TrimSpace(out), "\n")
		binary := 0
		for i, p := range plists {
			p = strings.TrimSpace(p)
			if p == "" || i >= maxDarwinApps {
				continue
			}
			b, rerr := r.ReadFile(ctx, p)
			if rerr != nil {
				continue
			}
			app, ok := ParseInfoPlist(b, p)
			if !ok {
				// A binary plist. Recorded as a count, not decoded: a bplist
				// parser is a real dependency and guessing at the bytes is
				// worse than saying how many were skipped.
				binary++
				continue
			}
			pkgs = append(pkgs, app)
		}
		if binary > 0 {
			problems = append(problems, fmt.Sprintf("%d /Applications Info.plist files are binary plists and were not decoded", binary))
		}
	} else {
		problems = append(problems, err.Error())
	}

	rep.Packages = capPackages(pkgs, opts.maxPackages())
	if len(pkgs) == 0 && len(problems) > 0 {
		rep.fail(SectionPackages, errors.New(strings.Join(problems, "; ")))
		return
	}
	rep.mark(SectionPackages, SectionOK)
	if len(problems) > 0 {
		rep.Errors = append(rep.Errors, StepError{Step: SectionPackages, Message: strings.Join(problems, "; ")})
	}
}

// ParsePkgutil parses `pkgutil --pkgs`, one receipt id per line.
func ParsePkgutil(b []byte) []Package {
	var out []Package
	for _, line := range strings.Split(string(b), "\n") {
		id := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if id == "" {
			continue
		}
		out = append(out, Package{Name: id, Manager: "pkgutil"})
	}
	return out
}

// plistDict is the minimal XML plist shape: a flat <dict> of alternating
// <key> and value elements.
type plistDict struct {
	Dict struct {
		Keys   []string `xml:"key"`
		Values []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"dict"`
}

// ParseInfoPlist reads CFBundleName and CFBundleShortVersionString from an
// application's XML Info.plist. ok is false for a binary plist.
//
// Only three keys are read. An Info.plist is a whole application manifest —
// entitlements, URL schemes, bundled tool paths — and none of that is a
// software inventory.
func ParseInfoPlist(b []byte, path string) (Package, bool) {
	if strings.HasPrefix(string(b[:min(8, len(b))]), "bplist") {
		return Package{}, false
	}
	var doc plistDict
	if err := xml.Unmarshal(b, &doc); err != nil {
		return Package{}, false
	}

	// <key> and its value alternate, but the parser collects them into two
	// slices; the value at index i belongs to the key at index i only when the
	// dict is flat, which an Info.plist's top level is.
	get := func(want string) string {
		for i, k := range doc.Dict.Keys {
			if k == want && i < len(doc.Dict.Values) {
				return strings.TrimSpace(doc.Dict.Values[i].Value)
			}
		}
		return ""
	}

	name := get("CFBundleName")
	if name == "" {
		// Fall back to the bundle directory name — "Safari.app" → "Safari".
		// Derived from the path the find returned, not invented.
		app := filepath.Base(filepath.Dir(filepath.Dir(path)))
		name = strings.TrimSuffix(app, ".app")
	}
	if name == "" {
		return Package{}, false
	}
	version := get("CFBundleShortVersionString")
	if version == "" {
		version = get("CFBundleVersion")
	}
	return Package{
		Name:    name,
		Version: version,
		Vendor:  get("CFBundleIdentifier"),
		Manager: "macos_app",
	}, true
}

// darwinSockets is what collectDarwinListeners read, so the connection step
// works from the same snapshot of the socket table. tcp and udp are nil when
// netstat did not answer for that protocol.
type darwinSockets struct {
	tcp, udp *NetstatSockets
	// root says lsof could see every process on this host. Only established
	// when netstat failed, the one case where it matters.
	root bool
}

// collectDarwinListeners reads the host's listening and bound sockets.
//
// netstat first, because what the two tools see differs by account. The agent
// runs as an unprivileged service account, and macOS's lsof shows a non-root
// caller only that caller's own processes. An account that owns no sockets gets
// exit 1 and no output, which reads exactly like a host with no listeners:
// reporting that as "ok" is how a Mac came to claim it served nothing while it
// was listening on 22. netstat reads the kernel's socket tables, which macOS
// shows every account, and names the owning process of each socket.
//
// When netstat does not answer, lsof still gives what it can, and the section
// says partial unless the collector is root: a non-root lsof answer is never
// marked ok, whatever it lists.
func collectDarwinListeners(ctx context.Context, r Runner, rep *Report) darwinSockets {
	var sockets darwinSockets

	tcp, tcpErr := readNetstat(ctx, r, darwinCmdNetstatTCP)
	udp, udpErr := readNetstat(ctx, r, darwinCmdNetstatUDP)
	if tcpErr != nil || udpErr != nil {
		sockets.root = darwinRunsAsRoot(ctx, r)
	}

	if tcpErr == nil {
		sockets.tcp = &tcp
		rep.Listeners = tcp.Listeners
		markNetstatSection(rep, SectionListeners, tcp)
	} else if out, ok := runLsof(ctx, r, darwinCmdLsof); ok {
		rep.Listeners = ParseLsof([]byte(out))
		markLsofFallback(rep, SectionListeners, tcpErr, sockets.root)
	} else {
		rep.fail(SectionListeners, fmt.Errorf("%w; lsof produced no usable output", tcpErr))
	}

	if udpErr == nil {
		sockets.udp = &udp
		rep.BoundUDPSockets = coalesceBoundUDP(udp.BoundUDP)
		markNetstatSection(rep, SectionBoundUDP, udp)
	} else if out, ok := runLsof(ctx, r, darwinCmdLsofUDP); ok {
		_, bound := ParseLsofUDP([]byte(out))
		rep.BoundUDPSockets = coalesceBoundUDP(bound)
		markLsofFallback(rep, SectionBoundUDP, udpErr, sockets.root)
	} else {
		rep.fail(SectionBoundUDP, fmt.Errorf("%w; lsof UDP query produced no usable output", udpErr))
	}
	return sockets
}

// markNetstatSection records the outcome of a netstat read. A row the parser
// could not read may be a socket, so a table with one is not a complete table.
func markNetstatSection(rep *Report, section string, s NetstatSockets) {
	if s.Malformed > 0 {
		rep.partial(section, fmt.Errorf("%d netstat rows could not be read", s.Malformed))
		return
	}
	rep.mark(section, SectionOK)
}

// markLsofFallback records an answer that came from lsof instead of netstat.
func markLsofFallback(rep *Report, section string, netstatErr error, root bool) {
	if root {
		rep.mark(section, SectionOK)
		rep.recordError(section, fmt.Errorf("%w; used lsof as root", netstatErr))
		return
	}
	rep.partial(section, fmt.Errorf("%w; lsof as a non-root account sees only that account's own sockets", netstatErr))
}

// darwinRunsAsRoot reports whether the collector's account is root. Anything
// other than a clear "0" is not root: the cost of being wrong that way is a
// partial label on a complete list, and the other way a false complete one.
func darwinRunsAsRoot(ctx context.Context, r Runner) bool {
	out, err := runText(ctx, r, darwinCmdID)
	return err == nil && strings.TrimSpace(out) == "0"
}

// readNetstat runs one netstat query. The error names the failure, never the
// output: this is a command transcript, and StepError does not carry those.
func readNetstat(ctx context.Context, r Runner, argv []string) (NetstatSockets, error) {
	out, _, exit, err := r.Run(ctx, argv)
	if err != nil {
		return NetstatSockets{}, fmt.Errorf("netstat could not run: %w", err)
	}
	if exit != 0 {
		return NetstatSockets{}, fmt.Errorf("netstat exited %d", exit)
	}
	sockets, ok := ParseNetstat(out)
	if !ok {
		return NetstatSockets{}, errors.New("netstat printed no socket table")
	}
	return sockets, nil
}

// NetstatSockets is one parsed `netstat -anvl -p <proto>`.
type NetstatSockets struct {
	Listeners   []Listener
	BoundUDP    []BoundUDPSocket
	Connections []Connection
	// Malformed counts socket rows that could not be read. It stays a number
	// because a row the parser refused may be a real socket, so the caller must
	// not call the table complete.
	Malformed int
}

// ParseNetstat parses macOS `netstat -anvl -p tcp` or `-p udp`. ok is false
// when the output holds no socket table at all, which is a failed query and
// not a host with no sockets.
//
// A row is
//
//	proto recv-q send-q local foreign [state] <counters...> <process:pid> ...
//
// where state is printed for TCP only, so the columns after it are found from
// the header, by their position after `(state)`. An address is host.port, the
// port after the LAST dot since an IPv6 host has none and an IPv4 host has
// three. The owning process column is `process:pid` on current macOS, and a
// bare `pid` (no name) on older releases. A process name can hold spaces, so
// `process:pid` may span several fields and ends at the first one that closes
// with :<digits>.
func ParseNetstat(b []byte) (NetstatSockets, bool) {
	var out NetstatSockets
	pidColumn := -1
	named := false
	header := false
	seen := make(map[string]bool)

	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) == 0 {
			continue
		}
		if f[0] == "Proto" {
			for i, col := range f {
				if col != "(state)" {
					continue
				}
				header = true
				for j, after := range f[i+1:] {
					if after == "process:pid" || after == "pid" {
						pidColumn, named = j, after == "process:pid"
						break
					}
				}
				break
			}
			continue
		}
		proto := strings.TrimRight(f[0], "46")
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if len(f) < 5 || (proto == "tcp" && len(f) < 6) {
			out.Malformed++
			continue
		}
		rest := f[5:]
		state := ""
		if proto == "tcp" {
			state, rest = rest[0], rest[1:]
		}
		process, pid := netstatOwner(rest, pidColumn, named)

		local, localPort, localOK := splitNetstatAddress(f[3])
		remote, remotePort, remoteOK := splitNetstatAddress(f[4])
		if !localOK || !remoteOK {
			out.Malformed++
			continue
		}
		switch {
		case state == "LISTEN":
			if localPort == 0 {
				out.Malformed++
				continue
			}
			// One socket per address family and one row per descriptor on the
			// same address are one service, as in ParseLsof.
			key := fmt.Sprintf("%s|%d|%d", local, localPort, pid)
			if !seen[key] {
				seen[key] = true
				out.Listeners = append(out.Listeners, Listener{Proto: "tcp", Address: local, Port: localPort, Process: process, PID: pid})
			}
		case state == "ESTABLISHED" || (proto == "udp" && remotePort != 0):
			out.Connections = append(out.Connections, Connection{Proto: proto, LocalAddress: local, LocalPort: localPort,
				RemoteAddress: remote, RemotePort: remotePort, Process: process, PID: pid})
		case proto == "udp" && localPort != 0:
			out.BoundUDP = append(out.BoundUDP, BoundUDPSocket{Address: local, Port: localPort, Process: process, PID: pid})
		}
	}
	return out, header
}

// netstatOwner reads the owning process from the columns after state. A row
// whose owner cannot be read keeps the socket and names nobody: the socket is
// the measurement and the owner an attribute of it.
func netstatOwner(rest []string, column int, named bool) (string, int) {
	if column < 0 || column >= len(rest) {
		return "", 0
	}
	if !named {
		pid, _ := strconv.Atoi(rest[column])
		return "", pid
	}
	for i := column; i < len(rest); i++ {
		sep := strings.LastIndex(rest[i], ":")
		if sep < 0 {
			continue
		}
		pid, err := strconv.Atoi(rest[i][sep+1:])
		if err != nil {
			continue
		}
		name := strings.Join(append(append([]string{}, rest[column:i]...), rest[i][:sep]), " ")
		return strings.TrimSpace(name), pid
	}
	return "", 0
}

// splitNetstatAddress splits netstat's host.port. A `*` host is the wildcard
// and normalises as the other collectors do; a `*` port is no port, reported
// as 0. Anything that is not an address is refused: an address cut short at the
// column width must not become a host's identity.
func splitNetstatAddress(s string) (string, int, bool) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return "", 0, false
	}
	host, rawPort := s[:i], s[i+1:]
	port := 0
	if rawPort != "*" {
		p, err := strconv.Atoi(rawPort)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, false
		}
		port = p
	}
	if host == "*" {
		return "0.0.0.0", port, true
	}
	// Drop an IPv6 zone: %en0 on one host is not the same interface on another.
	if z := strings.Index(host, "%"); z >= 0 {
		host = host[:z]
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", 0, false
	}
	return host, port, true
}

// ParseLsof parses `lsof -nP -iTCP -sTCP:LISTEN`.
//
// Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME, where NAME is
// "addr:port (LISTEN)".
func ParseLsof(b []byte) []Listener {
	var out []Listener
	seen := make(map[string]bool)
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		if i == 0 && strings.EqualFold(f[0], "COMMAND") {
			continue
		}
		addr, port, ok := splitHostPortSuffix(strings.TrimSuffix(f[8], "(LISTEN)"))
		if !ok {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		// lsof prints one row per file descriptor, so a server listening on two
		// descriptors of the same socket appears twice.
		key := fmt.Sprintf("%s|%d|%d", addr, port, pid)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Listener{Proto: "tcp", Address: addr, Port: port, Process: f[0], PID: pid})
	}
	return out
}

func collectDarwinConnections(ctx context.Context, r Runner, rep *Report, opts Options, sockets darwinSockets) {
	if !opts.CollectConnections {
		return
	}
	if !rep.SectionOK(SectionListeners) {
		rep.fail(SectionConnections, errors.New("listener snapshot incomplete; established TCP direction cannot be determined"))
		return
	}
	var connections []Connection
	switch {
	case sockets.tcp != nil && sockets.udp != nil:
		if sockets.udp.Malformed > 0 {
			rep.fail(SectionConnections, errors.New("netstat connection snapshot incomplete"))
			return
		}
		connections = append(append(connections, sockets.tcp.Connections...), sockets.udp.Connections...)
	case sockets.root:
		tcpOut, tcpOK := runLsof(ctx, r, darwinCmdLsofConnections)
		udpOut, udpOK := runLsof(ctx, r, darwinCmdLsofUDP)
		if !tcpOK || !udpOK {
			rep.fail(SectionConnections, errors.New("lsof connection snapshot incomplete"))
			return
		}
		connections = ParseLsofConnections([]byte(tcpOut), "tcp")
		udp, _ := ParseLsofUDP([]byte(udpOut))
		connections = append(connections, udp...)
	default:
		rep.fail(SectionConnections, errors.New("netstat did not answer, and lsof as a non-root account cannot see the host's connections"))
		return
	}
	rep.Connections = coalesceConnections(excludeAcceptedConnections(connections, rep.Listeners), opts.maxConnections())
	rep.mark(SectionConnections, SectionOK)
}

// runLsof treats exit 1 as a successful empty answer. lsof uses it when no
// file matches; for an inventory query that means "none", not "not assessed".
func runLsof(ctx context.Context, r Runner, argv []string) (string, bool) {
	out, errOut, exit, err := r.Run(ctx, argv)
	// lsof exit 1 with no output and no diagnostic means "no matches". Exit 1
	// with stderr is a failed query and must not become an empty complete list.
	if err != nil || (exit != 0 && (exit != 1 || len(out) != 0 || len(errOut) != 0)) {
		return "", false
	}
	return string(out), true
}

func ParseLsofConnections(b []byte, proto string) []Connection {
	var out []Connection
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || (i == 0 && strings.EqualFold(f[0], "COMMAND")) {
			continue
		}
		localRaw, remoteRaw, ok := strings.Cut(f[8], "->")
		if !ok {
			continue
		}
		local, localPort, lok := splitHostPortSuffix(localRaw)
		remote, port, rok := splitHostPortSuffix(remoteRaw)
		if !lok || !rok {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		out = append(out, Connection{Proto: proto, LocalAddress: local, LocalPort: localPort, RemoteAddress: remote, RemotePort: port, Process: f[0], PID: pid})
	}
	return out
}

func ParseLsofUDP(b []byte) ([]Connection, []BoundUDPSocket) {
	connections := ParseLsofConnections(b, "udp")
	var bound []BoundUDPSocket
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || (i == 0 && strings.EqualFold(f[0], "COMMAND")) || strings.Contains(f[8], "->") {
			continue
		}
		addr, port, ok := splitHostPortSuffix(f[8])
		if !ok {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		bound = append(bound, BoundUDPSocket{Address: addr, Port: port, Process: f[0], PID: pid})
	}
	return connections, bound
}

// darwinIPv4Assignments asks configd how each physical interface's IPv4
// address was configured (#2205). `ifconfig` cannot say; `ipconfig` can:
//
//   - `ipconfig getsummary <if>` names the IPv4 ConfigMethod — Manual is a
//     static address, DHCP or BOOTP a lease;
//   - failing that, `ipconfig getpacket <if>` prints the DHCP packet the
//     interface's lease came from, so an address equal to its `yiaddr` is a
//     lease.
//
// Both are optional: a command that is missing, refuses, or says something
// else leaves the address unknown, which is the honest answer.
func darwinIPv4Assignments(ctx context.Context, r Runner, ifaces []Interface) {
	for i := range ifaces {
		ifc := &ifaces[i]
		var v4 []string
		for _, a := range ifc.Addresses {
			if !strings.Contains(a, ":") {
				v4 = append(v4, a)
			}
		}
		if ifc.Virtual || len(v4) == 0 {
			continue
		}
		method := ""
		if out, ok := commandPresent(ctx, r, []string{"ipconfig", "getsummary", ifc.Name}); ok {
			method = ParseIPConfigSummaryMethod(out)
		}
		switch method {
		case "manual":
			for _, a := range v4 {
				ifc.assign(a, assignedStatic)
			}
			continue
		case "dhcp", "bootp":
			for _, a := range v4 {
				ifc.assign(a, assignedDynamic)
			}
			continue
		}
		out, ok := commandPresent(ctx, r, []string{"ipconfig", "getpacket", ifc.Name})
		if !ok {
			continue
		}
		leased := ParseIPConfigPacketYIAddr(out)
		for _, a := range v4 {
			if leased != "" && strings.SplitN(a, "/", 2)[0] == leased {
				ifc.assign(a, assignedDynamic)
			}
		}
	}
}

// ParseIPConfigSummaryMethod returns the lower-cased IPv4 ConfigMethod from
// `ipconfig getsummary` output, empty when there is none.
func ParseIPConfigSummaryMethod(out string) string {
	section := ""
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "IPv4 :"):
			section = "v4"
		case strings.HasPrefix(t, "IPv6 :"):
			section = "v6"
		case section == "v4" && strings.HasPrefix(t, "ConfigMethod :"):
			return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(t, "ConfigMethod :")))
		}
	}
	return ""
}

// ParseIPConfigPacketYIAddr returns the `yiaddr` (the address the DHCP server
// handed out) from `ipconfig getpacket` output, empty when there is none.
func ParseIPConfigPacketYIAddr(out string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == "yiaddr" {
			v = strings.TrimSpace(v)
			if v == "0.0.0.0" {
				return ""
			}
			return v
		}
	}
	return ""
}
