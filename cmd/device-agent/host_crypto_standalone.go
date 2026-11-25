package main

// `device-agent host-crypto`: one host crypto collection, written as
// vista.agent-output/v1 records (docs/host-crypto.md). This machine by
// default; with --remote, another host over SSH, read exactly as a managed
// remote job reads it. Nothing is sent to any platform.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/devices"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/security"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// envKeyPassphrase decrypts an --identity-file key. Never a flag.
const envKeyPassphrase = "VISTA_DEVICE_KEY_PASSPHRASE"

// hostCryptoDial is what a remote run needs from an SSH connection: the
// runner and how its host key was trusted.
type hostCryptoDial struct {
	runner hostinventory.Runner
	// hostKey is the SHA256 fingerprint connected through; verified is how
	// it was trusted (shared/sshtrust: pinned, known_hosts, first_use).
	hostKey, verified string
	close             func()
}

// dialHostCryptoSSH is the real dial.
func dialHostCryptoSSH(cfg hostinventory.SSHConfig) (hostCryptoDial, error) {
	r, err := hostinventory.NewSSHRunner(cfg)
	if err != nil {
		return hostCryptoDial{}, err
	}
	return hostCryptoDial{runner: r, hostKey: r.HostKeyFingerprint, verified: r.HostKeyVerified, close: func() { _ = r.Close() }}, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type hostCryptoFlags struct {
	output                   outputFlags
	remote                   string
	port                     int
	identityFile             string
	credentialsFile          string
	sshHostKey               string
	homeDirectories          bool
	defaultKeystorePasswords bool
	exclude                  stringList
	roots                    stringList
	maxDuration              time.Duration
	allowInherited           bool
}

func runHostCrypto(args []string, env standaloneEnv) int {
	var f hostCryptoFlags
	fs := flag.NewFlagSet("host-crypto", flag.ContinueOnError)
	fs.StringVar(&f.remote, "remote", "", "Collect another host over SSH: user@host (default: this machine)")
	fs.IntVar(&f.port, "port", 22, "SSH port, with --remote")
	fs.StringVar(&f.identityFile, "identity-file", "", "SSH private key for --remote; on Linux and macOS it must not be readable by group or others. "+
		"Its passphrase, if any, comes from "+envKeyPassphrase)
	fs.StringVar(&f.credentialsFile, "credentials", "", "YAML or JSON file with username, password, private_key and passphrase for --remote")
	fs.StringVar(&f.sshHostKey, "ssh-host-key", "", "Expected SSH host key fingerprint (SHA256:...); a different key aborts before any credential is sent")
	fs.BoolVar(&f.homeDirectories, "home-directories", false, "Also describe per-user material in home directories (SSH keys, GnuPG homes, keychains)")
	fs.BoolVar(&f.defaultKeystorePasswords, "default-keystore-passwords", false, "Try well-known default passwords on Java and PKCS#12 keystores; only whether one worked is recorded")
	fs.Var(&f.exclude, "exclude", "Absolute path never entered (repeatable)")
	fs.Var(&f.roots, "root", "Absolute path to sweep for key material by content (by name and size with --remote; repeatable). No sweep without one")
	fs.DurationVar(&f.maxDuration, "max-duration", 15*time.Minute, "Bound on the whole collection (1m to 1h)")
	fs.BoolVar(&f.allowInherited, "allow-inherited-permissions", false, "On Windows, accept an output file that keeps its folder's permissions when the volume cannot hold "+
		"an owner-only ACL (FAT, some shares). Without it such a run stops before writing")
	f.output.register(fs)

	usage := func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "Usage: %s host-crypto [--remote user@host] [flags]\n\n", standaloneAgent)
		_, _ = fmt.Fprintln(w, "Describes the cryptographic material and configuration on a host once and writes it:")
		_, _ = fmt.Fprintln(w, "certificates, private keys (what they are, never their contents), keystores, SSH material,")
		_, _ = fmt.Fprintln(w, "TLS and SSH policy, crypto libraries and platform protection. It contacts no Vista Platform:")
		_, _ = fmt.Fprintln(w, "no enrollment, no upload, nothing assessed. With --remote only the named host is contacted, and")
		_, _ = fmt.Fprintln(w, "no byte of a private key file crosses the connection.")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Run as root (Administrator on Windows) to see every user's processes and protected files; on")
		_, _ = fmt.Fprintln(w, "macOS grant Full Disk Access too. Without, the affected sections say partial.")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintf(w, "Remote credentials come from --identity-file, --credentials FILE, or %s.\n", envDevicePassword)
		_, _ = fmt.Fprintln(w, "No flag takes a secret.")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Flags:")
		printFlagDefaults(fs, w)
		_, _ = fmt.Fprintln(w, "\nExit status: 0 complete, 1 the collection failed, 2 a section failed or a bound cut one short.")
	}
	if code, done := parseStandaloneFlags(fs, args, usage, env); done {
		return code
	}

	// Everything that can be refused is refused here, before any connection.
	opts, err := f.output.options(env.stdout, env.stderr)
	if err != nil {
		return usageError(env, "host-crypto", "%v", err)
	}
	// The output says where every key on the host is and who can read it:
	// owner-only on every platform (on Windows: the running user, SYSTEM and
	// Administrators, nothing inherited), set when the file is created.
	opts.OwnerOnly, opts.AllowInherited = true, f.allowInherited
	collectOpts := hostcrypto.Options{
		HomeDirectories:          f.homeDirectories,
		DefaultKeystorePasswords: f.defaultKeystorePasswords,
		ExcludePaths:             f.exclude,
		SweepRoots:               f.roots,
	}
	for _, list := range []struct {
		name  string
		paths []string
		max   int
	}{{"--exclude", f.exclude, devices.HostCryptoMaxExcludePaths}, {"--root", f.roots, devices.HostCryptoMaxSweepRoots}} {
		if len(list.paths) > list.max {
			return usageError(env, "host-crypto", "%s is given %d times; at most %d are allowed", list.name, len(list.paths), list.max)
		}
		for _, p := range list.paths {
			if problem := agentconfig.CheckPath(p); problem != "" {
				return usageError(env, "host-crypto", "%s: %s", list.name, problem)
			}
		}
	}
	if f.maxDuration < devices.HostCryptoMinDuration || f.maxDuration > devices.HostCryptoMaxDuration {
		return usageError(env, "host-crypto", "--max-duration must be between %s and %s", devices.HostCryptoMinDuration, devices.HostCryptoMaxDuration)
	}
	collectOpts.MaxDuration = f.maxDuration
	if f.sshHostKey != "" && !strings.HasPrefix(f.sshHostKey, "SHA256:") {
		return usageError(env, "host-crypto", "--ssh-host-key must be a SHA256 fingerprint, e.g. SHA256:AbC... (ssh-keygen -lf shows it)")
	}
	remote := strings.TrimSpace(f.remote)
	if remote == "" {
		for name, set := range map[string]bool{"--identity-file": f.identityFile != "", "--credentials": f.credentialsFile != "", "--ssh-host-key": f.sshHostKey != ""} {
			if set {
				return usageError(env, "host-crypto", "%s needs --remote", name)
			}
		}
	}

	var (
		sshCfg  hostinventory.SSHConfig
		notes   []string
		targets []string
		scope   = "this host"
	)
	if remote != "" {
		user, host, ok := strings.Cut(remote, "@")
		if strings.Contains(host, "@") {
			ok = false
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if !ok || host == "" || strings.ContainsAny(host, " \t\r\n/\\?#") || strings.ContainsAny(user, " \t\r\n:") {
			return usageError(env, "host-crypto", "--remote %q is not user@host", remote)
		}
		if f.port < 1 || f.port > 65535 {
			return usageError(env, "host-crypto", "--port %d is not a TCP port", f.port)
		}
		secrets, credNotes, err := hostCryptoCredentials(f, env)
		if err != nil {
			return usageError(env, "host-crypto", "%v", err)
		}
		defer security.ClearCredentials(secrets)
		if user == "" {
			user = credString(secrets, "username")
		}
		if user == "" {
			return usageError(env, "host-crypto", "--remote needs a user: user@host")
		}
		sshCfg = hostinventory.SSHConfig{
			Host: host, Port: f.port, User: user,
			Password:                 credString(secrets, "password"),
			PrivateKeyPEM:            credString(secrets, "private_key"),
			Passphrase:               credString(secrets, "passphrase"),
			PinnedHostKeyFingerprint: f.sshHostKey,
		}
		if sshCfg.Password == "" && sshCfg.PrivateKeyPEM == "" {
			return usageError(env, "host-crypto", "--remote needs a credential: --identity-file, --credentials or %s", envDevicePassword)
		}
		notes = credNotes
		targets = []string{host}
		scope = "host " + host
	}

	w, err := agentoutput.Open(opts, agentoutput.Run{Command: "host-crypto", Flags: setFlags(fs), Targets: targets, Notes: notes})
	if err != nil {
		_, _ = fmt.Fprintf(env.stderr, "%s host-crypto: %v\n", standaloneAgent, err)
		return 1
	}
	fail := func(target, stage, reason string) int {
		_ = w.Error(target, stage, redact.Text(reason))
		w.Fail()
		_, _ = w.Close(true, scope)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.maxDuration+time.Minute)
	defer cancel()

	var report *hostcrypto.Report
	var collectErr error
	if remote == "" {
		report, collectErr = env.collectHostCrypto(ctx, collectOpts)
	} else {
		dial, err := env.dialHostCrypto(sshCfg)
		sshCfg.Password, sshCfg.PrivateKeyPEM, sshCfg.Passphrase = "", "", ""
		if err != nil {
			return fail(sshCfg.Host, "connect", "could not connect: "+err.Error())
		}
		if dial.close != nil {
			defer dial.close()
		}
		if f.sshHostKey == "" && dial.hostKey != "" {
			switch dial.verified {
			case "known_hosts":
				w.Warn("SSH host key %s of %s was verified from known_hosts; pin it next time with --ssh-host-key %s", dial.hostKey, sshCfg.Host, dial.hostKey)
			default:
				w.Warn("accepted SSH host key %s from %s without a pin; check it, then pin it next time with --ssh-host-key %s", dial.hostKey, sshCfg.Host, dial.hostKey)
			}
		}
		report, collectErr = devices.CollectRemoteHostCrypto(ctx, dial.runner, collectOpts)
	}
	target := ""
	if remote != "" {
		target = sshCfg.Host
	}
	if report == nil {
		if collectErr == nil {
			collectErr = errors.New("the collector returned no report")
		}
		return fail(target, "host_crypto", "host crypto inventory failed: "+collectErr.Error())
	}
	if collectErr != nil {
		_ = w.Error(target, "host_crypto", redact.Text("host crypto inventory did not complete: "+collectErr.Error()))
	}
	data, err := hostcrypto.OutputData(report)
	if err != nil {
		// ErrKeyMaterial: nothing of the report is written.
		return fail(target, "host_crypto", err.Error())
	}
	if err := w.Write(agentoutput.KindHostCrypto, data); err != nil {
		w.Fail()
		_, _ = w.Close(true, scope)
		_, _ = fmt.Fprintf(env.stderr, "%s host-crypto: %v\n", standaloneAgent, err)
		return 1
	}
	partial := collectErr != nil || len(report.Limits) > 0
	for _, s := range hostCryptoSortedSections(report) {
		switch report.Sections[s] {
		case hostcrypto.SectionFailed:
			partial = true
			w.Warn("section %s failed", s)
		case hostcrypto.SectionPartial:
			w.Warn("section %s is partial", s)
		}
	}
	for _, l := range report.Limits {
		w.Warn("%s: bound %s: %s", l.Section, l.Limit, l.Detail)
	}
	sum, err := w.Close(partial, scope)
	return agentoutput.ExitCode(sum, err, false)
}

// hostCryptoCredentials reads a remote run's credentials: the identity file
// (and its passphrase from the environment), else the credentials file, else
// the password from the environment. notes say where they came from, never
// what they are.
func hostCryptoCredentials(f hostCryptoFlags, env standaloneEnv) (map[string]interface{}, []string, error) {
	if f.identityFile != "" && f.credentialsFile != "" {
		return nil, nil, errors.New("give --identity-file or --credentials, not both")
	}
	if f.identityFile != "" {
		info, err := os.Stat(f.identityFile)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot read the identity file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("the identity file %s is not a regular file", f.identityFile)
		}
		if err := checkCredentialsFileMode(f.identityFile, info); err != nil {
			return nil, nil, err
		}
		key, err := os.ReadFile(f.identityFile)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot read the identity file: %w", err)
		}
		secrets := map[string]interface{}{"private_key": string(key)}
		notes := []string{"credentials: SSH key from --identity-file"}
		if p := env.getenv(envKeyPassphrase); p != "" {
			secrets["passphrase"] = p
			notes = append(notes, "credentials: key passphrase from "+envKeyPassphrase)
		}
		return secrets, notes, nil
	}
	return loadCollectCredentials(f.credentialsFile, env.getenv)
}

func credString(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}

func hostCryptoSortedSections(r *hostcrypto.Report) []string {
	out := make([]string, 0, len(r.Sections))
	for s := range r.Sections {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
