package main

// Standalone mode (docs/design/standalone-mode.md): `device-agent collect` and
// `device-agent host-inventory` and `device-agent kubernetes-inventory` collect once, write what they observed through
// shared/agentoutput, and exit. They read no managed configuration, never
// enroll and never open a connection to a control plane; the only network
// traffic is the interrogation of the device the operator named.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/devices"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/security"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// standaloneUsageHint opens the managed agent's --help, so a person who runs
// `device-agent --help` learns the standalone commands exist.
const standaloneUsageHint = `Standalone commands (no Vista Platform, nothing uploaded; see docs/standalone.md):
  collect          interrogate one device you name
  host-inventory   inventory this machine
  host-crypto      describe the certificates, keys and crypto policy of this machine or one over SSH
  kubernetes-inventory
                   inventory the Kubernetes cluster this runs in (in a pod)
Run "device-agent <command> --help" for a command's flags.

`

// standaloneAgent names this binary in every output record.
const standaloneAgent = "device-agent"

// defaultCollectTimeout bounds one standalone interrogation end to end.
const defaultCollectTimeout = 5 * time.Minute

// The environment variables collect reads credentials from when no
// --credentials file is given. Secrets never come from a flag, where they would
// land in shell history and the process list.
const (
	envDeviceUsername = "VISTA_DEVICE_USERNAME"
	envDevicePassword = "VISTA_DEVICE_PASSWORD"
	envDeviceAPIKey   = "VISTA_DEVICE_API_KEY"
	envDeviceToken    = "VISTA_DEVICE_TOKEN"
)

// standaloneEnv is what a standalone command needs from the process. The zero
// value of each func field means the real one; tests replace them.
type standaloneEnv struct {
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	// registry dispatches collect; nil is di.NewRegistry().
	registry *di.Registry
	// collectHost is the host-inventory collection; nil is the real one.
	collectHost func(ctx context.Context) (*hostinventory.Report, *di.InterrogateResult, error)
	// collectHostCrypto is the local host crypto collection; nil is the real one.
	collectHostCrypto func(ctx context.Context, opts hostcrypto.Options) (*hostcrypto.Report, error)
	// dialHostCrypto opens host-crypto --remote's SSH connection; nil is the
	// real one.
	dialHostCrypto func(cfg hostinventory.SSHConfig) (hostCryptoDial, error)
	// kubeClient is the client for kubernetes-inventory; nil is the cluster
	// this process runs in.
	kubeClient func() (*kubeinventory.Client, error)
}

func (e standaloneEnv) withDefaults() standaloneEnv {
	if e.stdout == nil {
		e.stdout = os.Stdout
	}
	if e.stderr == nil {
		e.stderr = os.Stderr
	}
	if e.getenv == nil {
		e.getenv = os.Getenv
	}
	if e.registry == nil {
		e.registry = di.NewRegistry()
	}
	if e.collectHost == nil {
		e.collectHost = func(ctx context.Context) (*hostinventory.Report, *di.InterrogateResult, error) {
			return devices.CollectLocalHostInventory(ctx, "")
		}
	}
	if e.collectHostCrypto == nil {
		e.collectHostCrypto = func(ctx context.Context, opts hostcrypto.Options) (*hostcrypto.Report, error) {
			return devices.CollectLocalHostCrypto(ctx, "", opts)
		}
	}
	if e.dialHostCrypto == nil {
		e.dialHostCrypto = dialHostCryptoSSH
	}
	if e.kubeClient == nil {
		e.kubeClient = kubeinventory.InCluster
	}
	return e
}

// runStandalone runs a standalone subcommand when args (os.Args[1:]) names
// one. ok is false for anything else, so main carries on exactly as before.
func runStandalone(args []string, env standaloneEnv) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "collect":
		return runCollect(args[1:], env.withDefaults()), true
	case "host-inventory":
		return runHostInventory(args[1:], env.withDefaults()), true
	case "host-crypto":
		return runHostCrypto(args[1:], env.withDefaults()), true
	case "kubernetes-inventory":
		return runKubernetesInventory(args[1:], env.withDefaults()), true
	}
	return 0, false
}

// outputFlags are the flags every standalone command shares.
type outputFlags struct {
	out    string
	format string
	quiet  bool
}

func (o *outputFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&o.out, "out", "-", "Write the output to this file (created 0600 on Linux and macOS; an existing file is replaced); - is standard output")
	fs.StringVar(&o.format, "format", "jsonl", "Output format: jsonl, json or csv")
	fs.BoolVar(&o.quiet, "quiet", false, "Do not print the human summary on standard error")
}

func (o *outputFlags) options(stdout, stderr io.Writer) (agentoutput.Options, error) {
	format, err := agentoutput.ParseFormat(o.format)
	if err != nil {
		return agentoutput.Options{}, err
	}
	return agentoutput.Options{
		Path: o.out, Format: format, Agent: standaloneAgent, AgentVersion: standaloneVersion(),
		Quiet: o.quiet, Stdout: stdout, Stderr: stderr,
	}, nil
}

// standaloneVersion is the version stamped on every record; the schema wants
// a non-empty string.
func standaloneVersion() string {
	if strings.TrimSpace(Version) == "" {
		return "dev"
	}
	return Version
}

// parseStandaloneFlags parses args, printing help to stdout for -h/--help
// (exit 0) and the problem plus help to stderr for anything else (exit 1).
// done is true when the caller should return code at once.
func parseStandaloneFlags(fs *flag.FlagSet, args []string, usage func(io.Writer), env standaloneEnv) (code int, done bool) {
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		usage(env.stdout)
		return 0, true
	case err != nil:
		_, _ = fmt.Fprintf(env.stderr, "%s %s: %v\n\n", standaloneAgent, fs.Name(), err)
		usage(env.stderr)
		return 1, true
	case fs.NArg() > 0:
		_, _ = fmt.Fprintf(env.stderr, "%s %s: unexpected argument %q\n\n", standaloneAgent, fs.Name(), fs.Arg(0))
		usage(env.stderr)
		return 1, true
	}
	return 0, false
}

func printFlagDefaults(fs *flag.FlagSet, w io.Writer) {
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
}

// usageError reports a bad invocation: nothing has been contacted and no
// output written.
func usageError(env standaloneEnv, command, format string, args ...any) int {
	_, _ = fmt.Fprintf(env.stderr, "%s %s: %s\n", standaloneAgent, command, fmt.Sprintf(format, args...))
	_, _ = fmt.Fprintf(env.stderr, "Run '%s %s --help' for the flags.\n", standaloneAgent, command)
	return 1
}

// setFlags returns the flags given on the command line, for the run record.
// No flag of these commands takes a secret, so recording them leaks nothing.
func setFlags(fs *flag.FlagSet) map[string]string {
	flags := map[string]string{}
	fs.Visit(func(f *flag.Flag) { flags[f.Name] = f.Value.String() })
	if len(flags) == 0 {
		return nil
	}
	return flags
}

// sortedDeviceTypes lists the registry's device types for help text.
func sortedDeviceTypes(r *di.Registry) []string {
	types := r.SupportedDeviceTypes()
	sort.Strings(types)
	return types
}

// ---------------------------------------------------------------------------
// collect

type collectFlags struct {
	output             outputFlags
	deviceType         string
	target             string
	port               int
	managementURL      string
	site               string
	credentialsFile    string
	sshHostKey         string
	insecureSkipVerify bool
	timeout            time.Duration
}

func runCollect(args []string, env standaloneEnv) int {
	var f collectFlags
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.StringVar(&f.deviceType, "type", "", "Device type to interrogate (required; see the list below)")
	fs.StringVar(&f.target, "target", "", "The device's IP address or host name (required)")
	fs.IntVar(&f.port, "port", 0, "Management or SSH port, when it is not the collector's default")
	fs.StringVar(&f.managementURL, "management-url", "", "Management URL, for collectors that use one (scheme, host, optional port and path)")
	fs.StringVar(&f.site, "site", "", "UniFi site name")
	fs.StringVar(&f.credentialsFile, "credentials", "", "YAML or JSON file with username, password, api_key, token and vendor-specific keys; "+
		"on Linux and macOS it must not be readable by group or others")
	fs.StringVar(&f.sshHostKey, "ssh-host-key", "", "Expected SSH host key fingerprint (SHA256:...); a different key aborts before any credential is sent")
	fs.BoolVar(&f.insecureSkipVerify, "insecure-skip-verify", false, "Do not verify the management endpoint's TLS certificate (recorded in the output)")
	fs.DurationVar(&f.timeout, "timeout", defaultCollectTimeout, "Bound on the whole interrogation")
	f.output.register(fs)

	usage := func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "Usage: %s collect --type TYPE --target HOST [flags]\n\n", standaloneAgent)
		_, _ = fmt.Fprintln(w, "Interrogates one device once and writes what it observed. It contacts no Vista Platform:")
		_, _ = fmt.Fprintln(w, "no enrollment, no upload, and nothing is assessed. Only the named device is contacted.")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintf(w, "Credentials come from --credentials FILE, or else from %s, %s,\n", envDeviceUsername, envDevicePassword)
		_, _ = fmt.Fprintf(w, "%s and %s. No flag takes a secret.\n\n", envDeviceAPIKey, envDeviceToken)
		_, _ = fmt.Fprintf(w, "Device types: %s\n\n", strings.Join(sortedDeviceTypes(env.registry), ", "))
		_, _ = fmt.Fprintln(w, "Flags:")
		printFlagDefaults(fs, w)
		_, _ = fmt.Fprintln(w, "\nExit status: 0 complete, 1 the run could not do its work, 2 partial result.")
	}
	if code, done := parseStandaloneFlags(fs, args, usage, env); done {
		return code
	}

	// Everything that can be refused is refused here, before any connection.
	opts, err := f.output.options(env.stdout, env.stderr)
	if err != nil {
		return usageError(env, "collect", "%v", err)
	}
	f.deviceType = strings.TrimSpace(f.deviceType)
	f.target = strings.TrimSpace(f.target)
	if f.deviceType == "" {
		return usageError(env, "collect", "--type is required (one of: %s)", strings.Join(sortedDeviceTypes(env.registry), ", "))
	}
	interrogator, err := env.registry.Get(f.deviceType)
	if err != nil {
		return usageError(env, "collect", "unknown device type %q (one of: %s)", f.deviceType, strings.Join(sortedDeviceTypes(env.registry), ", "))
	}
	if f.target == "" {
		return usageError(env, "collect", "--target is required: the device's IP address or host name")
	}
	if strings.ContainsAny(f.target, " \t\r\n/\\?#@") {
		return usageError(env, "collect", "--target %q is not an IP address or host name", f.target)
	}
	if f.port < 0 || f.port > 65535 {
		return usageError(env, "collect", "--port %d is not a TCP port", f.port)
	}
	if f.timeout <= 0 {
		return usageError(env, "collect", "--timeout must be positive")
	}
	if f.managementURL != "" {
		// A URL can carry a password (user:pass@host) or a key in its query.
		// Refusing both keeps the rule that no flag holds a secret, and keeps
		// the URL safe to record in the run record.
		u, perr := url.Parse(f.managementURL)
		if perr != nil || u.Scheme == "" || u.Host == "" {
			return usageError(env, "collect", "--management-url must be an absolute URL such as https://192.0.2.10:8443")
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return usageError(env, "collect", "--management-url may not carry credentials, a query or a fragment; put credentials in --credentials")
		}
	}
	if f.sshHostKey != "" && !strings.HasPrefix(f.sshHostKey, "SHA256:") {
		return usageError(env, "collect", "--ssh-host-key must be a SHA256 fingerprint, e.g. SHA256:AbC... (ssh-keygen -lf shows it)")
	}

	secrets, notes, err := loadCollectCredentials(f.credentialsFile, env.getenv)
	if err != nil {
		return usageError(env, "collect", "%v", err)
	}
	defer security.ClearCredentials(secrets)
	creds := devices.CredentialsFromMap(secrets, f.insecureSkipVerify)

	device := di.DeviceInfo{
		DeviceType:            f.deviceType,
		Port:                  f.port,
		ManagementURL:         f.managementURL,
		SiteID:                f.site,
		SSHHostKeyFingerprint: f.sshHostKey,
	}
	if net.ParseIP(f.target) != nil {
		device.IPAddress = f.target
	} else {
		device.Hostname = f.target
	}
	if f.insecureSkipVerify {
		notes = append(notes, "TLS verification of the management endpoint was disabled (--insecure-skip-verify)")
	}

	w, err := agentoutput.Open(opts, agentoutput.Run{
		Command: "collect",
		Flags:   setFlags(fs),
		Targets: []string{f.target},
		Notes:   notes,
	})
	if err != nil {
		_, _ = fmt.Fprintf(env.stderr, "%s collect: %v\n", standaloneAgent, err)
		return 1
	}
	scope := fmt.Sprintf("%s device %s", f.deviceType, f.target)

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	result, err := interrogateRecovering(ctx, interrogator, device, creds)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("timed out after %s", f.timeout)
		}
		reason := scrubSecrets("interrogation failed: "+err.Error(), creds)
		if werr := w.Error(f.target, "interrogate", reason); werr != nil {
			_, _ = fmt.Fprintf(env.stderr, "%s collect: %v\n", standaloneAgent, werr)
		}
		// Nothing was collected, so the run failed whatever Close reports.
		w.Fail()
		_, _ = w.Close(true, scope)
		return 1
	}

	if err := w.Write(agentoutput.KindDeviceInterrogation, result, endpointsOf(result, f.deviceType)...); err != nil {
		w.Fail()
		_, _ = w.Close(true, scope)
		_, _ = fmt.Fprintf(env.stderr, "%s collect: %v\n", standaloneAgent, err)
		return 1
	}
	for _, warn := range result.Warnings {
		w.Warn("%s", scrubSecrets(describeWarning(warn), creds))
	}
	if f.sshHostKey == "" {
		for _, fp := range sshHostKeysSeen(result) {
			w.Warn("accepted SSH host key %s from %s without a pin; check it, then pin it next time with --ssh-host-key %s", fp, f.target, fp)
		}
	}
	sum, err := w.Close(len(result.Warnings) > 0, scope)
	return agentoutput.ExitCode(sum, err, false)
}

// interrogateRecovering is devices.InterrogateBounded with a collector panic
// turned into an error, so one broken collector ends the run with an error
// record rather than a stack trace.
func interrogateRecovering(ctx context.Context, i di.DeviceInterrogator, device di.DeviceInfo, creds di.Credentials) (res *di.InterrogateResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("the collector failed unexpectedly: %v", r)
		}
	}()
	res, err = devices.InterrogateBounded(ctx, i, device, creds)
	if err == nil && res == nil {
		err = errors.New("the collector returned no result")
	}
	return res, err
}

// scrubSecrets redacts a message that may have been assembled from a vendor
// error. redact.Text removes credentials by shape and by name (URL userinfo,
// key query parameters, Authorization headers, PEM keys); replacing the
// literal values the run was given covers a device that echoes a password
// back in an error we have never seen. The username is not a secret and stays,
// so an operator can still tell which account was refused.
func scrubSecrets(msg string, creds di.Credentials) string {
	msg = redact.Text(msg)
	values := []string{creds.Password, creds.APIKey, creds.Token}
	for k, v := range creds.Custom {
		if s, ok := v.(string); ok && k != "username" {
			values = append(values, s)
		}
	}
	// Longest first, so a secret that contains another is replaced whole.
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, v := range values {
		if v != "" {
			msg = strings.ReplaceAll(msg, v, redact.Marker)
		}
	}
	return msg
}

func describeWarning(w di.CollectionWarning) string {
	parts := []string{w.Collector}
	if w.Endpoint != "" {
		parts = append(parts, w.Endpoint)
	}
	s := strings.Join(parts, " ") + ": " + string(w.Reason)
	if w.Effect != "" {
		s += " (" + w.Effect + ")"
	}
	return s
}

// sshHostKeysSeen lists the SSH host keys the collector connected through, so
// a run without --ssh-host-key can say what to pin next time.
func sshHostKeysSeen(result *di.InterrogateResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range result.Assets {
		if a.SSHInfo == nil || a.SSHInfo.HostKeyFingerprint == "" || seen[a.SSHInfo.HostKeyFingerprint] {
			continue
		}
		seen[a.SSHInfo.HostKeyFingerprint] = true
		out = append(out, a.SSHInfo.HostKeyFingerprint)
	}
	return out
}

// endpointsOf maps each crypto asset onto a CSV row. The leaf certificate is
// the chain's first entry, or the convenience Certificate field.
func endpointsOf(result *di.InterrogateResult, deviceType string) []agentoutput.Endpoint {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	out := make([]agentoutput.Endpoint, 0, len(result.Assets))
	for _, a := range result.Assets {
		e := agentoutput.Endpoint{
			Kind:            agentoutput.KindDeviceInterrogation,
			Host:            a.Hostname,
			Address:         a.IPAddress,
			Port:            a.Port,
			Protocol:        a.Protocol,
			ProtocolVersion: deref(a.ProtocolVersion),
			CipherSuite:     deref(a.CipherSuite),
			KeyExchange:     deref(a.KeyExchangeAlg),
			Source:          deviceType,
		}
		leaf := a.Certificate
		if len(a.Certificates) > 0 {
			leaf = &a.Certificates[0]
		}
		if leaf != nil {
			e.CertificateSubject = firstNonEmpty(leaf.SubjectDN, leaf.Subject)
			e.CertificateIssuer = firstNonEmpty(leaf.IssuerDN, leaf.Issuer)
			notAfter := leaf.NotAfter
			if notAfter.IsZero() {
				notAfter = leaf.ValidTo
			}
			if !notAfter.IsZero() {
				e.CertificateNotAfter = notAfter.UTC().Format(time.RFC3339)
			}
			e.CertificateKeyAlgorithm = leaf.KeyAlgorithm
			e.CertificateKeySize = leaf.KeySize
			e.CertificateSignatureAlgorithm = firstNonEmpty(leaf.SignatureAlg, leaf.Signature)
			e.CertificateFingerprintSHA256 = leaf.FingerprintSHA256
		}
		out = append(out, e)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// loadCollectCredentials reads the credentials file, or else the environment.
// notes say where the credentials came from, never what they are.
func loadCollectCredentials(path string, getenv func(string) string) (map[string]interface{}, []string, error) {
	envNames := []string{envDeviceUsername, envDevicePassword, envDeviceAPIKey, envDeviceToken}
	var envSet []string
	for _, name := range envNames {
		if getenv(name) != "" {
			envSet = append(envSet, name)
		}
	}

	if path != "" {
		secrets, err := readCredentialsFile(path)
		if err != nil {
			return nil, nil, err
		}
		notes := []string{"credentials: from the --credentials file"}
		if len(envSet) > 0 {
			notes = append(notes, "credentials: "+strings.Join(envSet, ", ")+" ignored because --credentials was given")
		}
		return secrets, notes, nil
	}

	secrets := map[string]interface{}{}
	for name, key := range map[string]string{
		envDeviceUsername: "username", envDevicePassword: "password",
		envDeviceAPIKey: "api_key", envDeviceToken: "token",
	} {
		if v := getenv(name); v != "" {
			secrets[key] = v
		}
	}
	if len(envSet) == 0 {
		return secrets, []string{"credentials: none given"}, nil
	}
	return secrets, []string{"credentials: from the environment (" + strings.Join(envSet, ", ") + ")"}, nil
}

// readCredentialsFile parses a YAML or JSON credentials file (YAML is a
// superset of JSON, so one parser reads both) after checking it is private.
// Parse errors never quote the file: a line of it could be the password.
func readCredentialsFile(path string) (map[string]interface{}, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the credentials file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the credentials file %s is not a regular file", path)
	}
	if err := checkCredentialsFileMode(path, info); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the credentials file: %w", err)
	}
	var secrets map[string]interface{}
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("the credentials file %s is not valid YAML or JSON: %s", path, yamlErrorLine(err))
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("the credentials file %s holds no credentials: expected keys such as username, password, api_key or token", path)
	}
	for k, v := range secrets {
		// Numbers and booleans are fine as vendor-specific values; a password
		// written as a bare number would otherwise be lost, so keep it a string.
		switch n := v.(type) {
		case int:
			if k == "password" || k == "api_key" || k == "token" || k == "username" {
				secrets[k] = strconv.Itoa(n)
			}
		}
	}
	return secrets, nil
}

// yamlErrorLine keeps the position of a YAML error and drops anything that
// quotes the input.
func yamlErrorLine(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "line "); i >= 0 {
		rest := msg[i:]
		if j := strings.IndexByte(rest, ':'); j >= 0 {
			return rest[:j]
		}
	}
	return "the file could not be parsed"
}

// ---------------------------------------------------------------------------
// host-inventory

func runHostInventory(args []string, env standaloneEnv) int {
	var o outputFlags
	fs := flag.NewFlagSet("host-inventory", flag.ContinueOnError)
	o.register(fs)
	usage := func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "Usage: %s host-inventory [flags]\n\n", standaloneAgent)
		_, _ = fmt.Fprintln(w, "Collects the inventory of the machine this runs on once and writes it. It contacts no")
		_, _ = fmt.Fprintln(w, "Vista Platform and nothing else on the network: no enrollment, no upload, no assessment.")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Flags:")
		printFlagDefaults(fs, w)
		_, _ = fmt.Fprintln(w, "\nExit status: 0 complete, 1 the collection failed, 2 some sections did not complete.")
	}
	if code, done := parseStandaloneFlags(fs, args, usage, env); done {
		return code
	}
	opts, err := o.options(env.stdout, env.stderr)
	if err != nil {
		return usageError(env, "host-inventory", "%v", err)
	}
	w, err := agentoutput.Open(opts, agentoutput.Run{Command: "host-inventory", Flags: setFlags(fs)})
	if err != nil {
		_, _ = fmt.Fprintf(env.stderr, "%s host-inventory: %v\n", standaloneAgent, err)
		return 1
	}
	const scope = "this host"

	ctx, cancel := context.WithTimeout(context.Background(), hostInventoryCollectTimeout)
	defer cancel()
	report, observations, err := env.collectHost(ctx)
	if err != nil {
		_ = w.Error("", "host_inventory", redact.Text("host inventory failed: "+err.Error()))
		w.Fail()
		_, _ = w.Close(true, scope)
		return 1
	}
	if err := w.Write(agentoutput.KindHostInventory, map[string]any{"report": report, "observations": observations}); err != nil {
		w.Fail()
		_, _ = w.Close(true, scope)
		_, _ = fmt.Fprintf(env.stderr, "%s host-inventory: %v\n", standaloneAgent, err)
		return 1
	}
	partial := false
	if failed := failedSectionSuffix(report); failed != "" {
		partial = true
		w.Warn("some sections did not complete%s", failed)
	}
	sum, err := w.Close(partial, scope)
	return agentoutput.ExitCode(sum, err, false)
}

// ---------------------------------------------------------------------------
// kubernetes-inventory

// repeatedFlag collects a flag given more than once.
type repeatedFlag []string

func (r *repeatedFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error { *r = append(*r, v); return nil }

func runKubernetesInventory(args []string, env standaloneEnv) int {
	const command = "kubernetes-inventory"
	var (
		o           outputFlags
		readSecrets bool
		noKubelets  bool
		noPEM       bool
		labelKeys   repeatedFlag
		timeout     time.Duration
	)
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	o.register(fs)
	fs.BoolVar(&readSecrets, "read-tls-secrets", false, "Also read the certificates of Secrets of type kubernetes.io/tls (the service account needs permission to list Secrets; the private key is never decoded). Also on when "+devices.EnvReadTLSSecrets+"=true")
	fs.BoolVar(&noKubelets, "no-kubelet-probe", false, "Do not handshake with each node's kubelet port")
	fs.BoolVar(&noPEM, "no-certificate-pem", false, "Write each certificate's parsed fields without its PEM")
	fs.Var(&labelKeys, "label-key", "Report this label key in addition to the built-in list (repeatable)")
	fs.DurationVar(&timeout, "timeout", kubeinventory.DefaultTimeout, "Whole-collection time limit")
	usage := func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "Usage: %s %s [flags]\n\n", standaloneAgent, command)
		_, _ = fmt.Fprintln(w, "Reads the Kubernetes API of the cluster this runs in, once, and writes what the cluster")
		_, _ = fmt.Fprintln(w, "declares about its cryptography. It must run in a pod: it uses the pod's service account and")
		_, _ = fmt.Fprintln(w, "takes no kubeconfig, token or API server address. It only reads (get and list), connects to")
		_, _ = fmt.Fprintln(w, "the API server and to each node's kubelet port and to nothing else, and contacts no Vista")
		_, _ = fmt.Fprintln(w, "Platform. See docs/design/kubernetes-inventory.md for what is read.")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Flags:")
		printFlagDefaults(fs, w)
		_, _ = fmt.Fprintln(w, "\nExit status: 0 complete, 1 the collection failed, 2 some classes could not be read.")
	}
	if code, done := parseStandaloneFlags(fs, args, usage, env); done {
		return code
	}
	if fs.NArg() > 0 {
		return usageError(env, command, "unexpected argument %q", fs.Arg(0))
	}
	if timeout <= 0 {
		return usageError(env, command, "--timeout must be positive")
	}
	opts, err := o.options(env.stdout, env.stderr)
	if err != nil {
		return usageError(env, command, "%v", err)
	}
	// Before the output file is opened: outside a cluster there is nothing to
	// write.
	client, err := env.kubeClient()
	if err != nil {
		_, _ = fmt.Fprintf(env.stderr, "%s %s: %v\n", standaloneAgent, command, err)
		return 1
	}
	w, err := agentoutput.Open(opts, agentoutput.Run{Command: command, Flags: setFlags(fs)})
	if err != nil {
		_, _ = fmt.Fprintf(env.stderr, "%s %s: %v\n", standaloneAgent, command, err)
		return 1
	}
	const scope = "this cluster"

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	inv, err := kubeinventory.Collect(ctx, client, kubeinventory.Options{
		SkipKubeletProbe: noKubelets, OmitCertificatePEM: noPEM, ExtraLabelKeys: labelKeys,
		ReadTLSSecrets: readSecrets || strings.EqualFold(strings.TrimSpace(env.getenv(devices.EnvReadTLSSecrets)), "true"),
	})
	if err != nil {
		_ = w.Error("", "kubernetes_inventory", redact.Text("kubernetes inventory failed: "+err.Error()))
		w.Fail()
		_, _ = w.Close(true, scope)
		return 1
	}
	if err := w.Write(agentoutput.KindKubernetesInventory, inv); err != nil {
		w.Fail()
		_, _ = w.Close(true, scope)
		_, _ = fmt.Fprintf(env.stderr, "%s %s: %v\n", standaloneAgent, command, err)
		return 1
	}
	var failed []string
	for _, class := range kubeinventory.Classes {
		if s := inv.Sections[class]; s.Status == kubeinventory.StatusFailed {
			failed = append(failed, class+" ("+s.Reason+")")
		}
	}
	if len(failed) > 0 {
		w.Warn("some classes could not be read: %s", strings.Join(failed, ", "))
	}
	sum, err := w.Close(len(failed) > 0, scope)
	return agentoutput.ExitCode(sum, err, false)
}
