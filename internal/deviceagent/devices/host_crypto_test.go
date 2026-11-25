package devices

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// The executor's host_crypto branch, driven through the REAL Execute dispatch
// (deleting `case JobTypeHostCrypto` fails these), against the real
// collector.

// hcjParams turns a Go literal into what a job's parameters are after JSON:
// numbers float64, lists []interface{}.
func hcjParams(t *testing.T, v map[string]any) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func hcjJob(t *testing.T, params map[string]any) *models.Job {
	return &models.Job{ID: uuid.New(), Type: JobTypeHostCrypto, Parameters: hcjParams(t, params)}
}

// hcjKeyDir holds a generated EC key under a name that says nothing, and its
// certificate. It returns the directory and the key's private scalar.
func hcjKeyDir(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return dir, priv
}

// hcjFindSecret reports where a 16-byte window of secret appears in b: raw,
// hex (either case) or base64 (standard or URL alphabet, every alignment).
func hcjFindSecret(b, secret []byte) string {
	s, lower := string(b), strings.ToLower(string(b))
	for i := 0; i+16 <= len(secret); i++ {
		w := secret[i : i+16]
		if strings.Contains(s, string(w)) {
			return "raw"
		}
		if strings.Contains(lower, hex.EncodeToString(w)) {
			return "hex"
		}
	}
	for off := 0; off < 3; off++ {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			e := enc.EncodeToString(secret[off:])
			for i := 4; i+20 <= len(e); i += 4 {
				if strings.Contains(s, e[i:i+20]) {
					return "base64"
				}
			}
		}
	}
	return ""
}

func hcjValidateResult(t *testing.T, res *models.JobResult) {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Validate("job-result.device-agent", res); err != nil {
		t.Fatalf("the result does not satisfy job-result.device-agent: %v", err)
	}
}

func hcjReport(t *testing.T, res *models.JobResult) *hostcrypto.Report {
	t.Helper()
	if len(res.HostCrypto) == 0 {
		t.Fatalf("no report in the result: %+v", res)
	}
	var r hostcrypto.Report
	if err := json.Unmarshal(res.HostCrypto, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// A local job collects this host with the job's options and sends the report
// in its result: schema-valid, the agent id stamped, the sweep root's key
// described and no run of its private bytes anywhere in the result.
func TestExecute_HostCryptoLocalJob(t *testing.T) {
	dir, secret := hcjKeyDir(t)
	exec, rec := newTestExecutor()
	exec.config.AgentID = "7f2e9a4c-5d63-4b80-9caf-3e4d5c6f7a81"
	job := hcjJob(t, map[string]any{"mode": "local", "options": map[string]any{
		"sweep_roots": []string{dir}, "max_duration_seconds": 120, "max_records_per_section": 50000,
	}})
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	res := rec.last()
	if res == nil || !res.Success {
		t.Fatalf("result %+v", res)
	}
	hcjValidateResult(t, res)
	r := hcjReport(t, res)
	if r.Mode != hostinventory.ModeLocal || r.AgentID != exec.config.AgentID {
		t.Fatalf("mode %q agent %q", r.Mode, r.AgentID)
	}
	if len(r.Scope.SweepRoots) != 1 || r.Scope.SweepRoots[0] != dir {
		t.Fatalf("the job's sweep root did not reach the collector: %+v", r.Scope)
	}
	found := false
	for _, k := range r.PrivateKeys {
		found = found || filepath.Dir(k.Location.Path) == dir || strings.HasPrefix(k.Location.Path, dir)
	}
	if !found {
		t.Fatalf("the generated key was not found (sections %v)", r.Sections)
	}
	b, _ := json.Marshal(res)
	if where := hcjFindSecret(b, secret); where != "" {
		t.Fatalf("the private key's bytes are in the result (%s)", where)
	}
}

// The job path's refusals, each before anything is collected.
func TestExecute_HostCryptoRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		params map[string]any
		want   string
	}{
		"no mode":            {map[string]any{}, "parameters.mode"},
		"unknown mode":       {map[string]any{"mode": "both"}, "unknown host crypto mode"},
		"unknown option":     {map[string]any{"mode": "local", "options": map[string]any{"follow_everything": true}}, "unknown host crypto option(s): follow_everything"},
		"options not object": {map[string]any{"mode": "local", "options": []string{"x"}}, "must be an object"},
		"relative exclude":   {map[string]any{"mode": "local", "options": map[string]any{"exclude_paths": []string{"var/lib"}}}, "not an absolute path"},
		"climbing root":      {map[string]any{"mode": "local", "options": map[string]any{"sweep_roots": []string{"/a/../etc"}}}, "climbs"},
		"string bool":        {map[string]any{"mode": "local", "options": map[string]any{"home_directories": "yes"}}, "true or false"},
		"fractional bound":   {map[string]any{"mode": "local", "options": map[string]any{"max_files": 1.5}}, "positive whole number"},
		"zero bound":         {map[string]any{"mode": "local", "options": map[string]any{"max_files": 0}}, "positive whole number"},
		"winrm":              {map[string]any{"mode": "remote", "transport": "winrm", "ip_address": "192.0.2.1"}, "winrm"},
	} {
		t.Run(name, func(t *testing.T) {
			exec, rec := newTestExecutor()
			if err := exec.Execute(context.Background(), hcjJob(t, c.params)); err != nil {
				t.Fatal(err)
			}
			res := rec.last()
			if res == nil || res.Success || !strings.Contains(strings.ToLower(res.Error), strings.ToLower(c.want)) || len(res.HostCrypto) != 0 {
				t.Fatalf("result %+v, want a failure naming %q and no report", res, c.want)
			}
			hcjValidateResult(t, res)
		})
	}
}

// Bounds above the published maxima are lowered, never refused, and a run
// bound under a minute is raised.
func TestParseHostCryptoOptions_ClampsBounds(t *testing.T) {
	opts, lowered, err := ParseHostCryptoOptions(hcjParams(t, map[string]any{
		"max_files": 5e7, "max_file_bytes": 1 << 40, "max_records_per_section": 1e9, "max_duration_seconds": 1e6,
		"home_directories": true, "default_keystore_passwords": true,
		"exclude_paths": []string{`C:\Windows\WinSxS`, "/var/lib/docker"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if opts.MaxFiles != HostCryptoMaxFiles || opts.MaxFileBytes != HostCryptoMaxFileBytes ||
		opts.MaxRecordsPerSection != HostCryptoMaxRecordsPerSection || opts.MaxDuration != HostCryptoMaxDuration {
		t.Fatalf("not clamped: %+v", opts)
	}
	if strings.Join(lowered, ",") != "max_files,max_file_bytes,max_records_per_section,max_duration_seconds" {
		t.Fatalf("lowered %v", lowered)
	}
	if !opts.HomeDirectories || !opts.DefaultKeystorePasswords || len(opts.ExcludePaths) != 2 {
		t.Fatalf("opt-ins or excludes lost: %+v", opts)
	}
	opts, lowered, err = ParseHostCryptoOptions(hcjParams(t, map[string]any{"max_duration_seconds": 5, "max_files": 10}))
	if err != nil || opts.MaxDuration != HostCryptoMinDuration || opts.MaxFiles != 10 || len(lowered) != 1 {
		t.Fatalf("%+v %v %v", opts, lowered, err)
	}
	// Defaults stay the collector's own: nothing set, nothing forced.
	opts, _, err = ParseHostCryptoOptions(map[string]interface{}{})
	if err != nil || opts.MaxFiles != 0 || opts.MaxDuration != 0 || opts.HomeDirectories || opts.DefaultKeystorePasswords {
		t.Fatalf("empty options: %+v %v", opts, err)
	}
	// Too many paths is a refusal, not a cut.
	many := make([]string, HostCryptoMaxSweepRoots+1)
	for i := range many {
		many[i] = "/r" + string(rune('a'+i))
	}
	if _, _, err := ParseHostCryptoOptions(hcjParams(t, map[string]any{"sweep_roots": many})); err == nil {
		t.Fatal("17 sweep roots accepted")
	}
}

// A job's overall timeout covers its run bound; DefaultJobTimeout would cut
// a fifteen-minute collection at five.
func TestTimeoutFor_HostCrypto(t *testing.T) {
	exec, _ := newTestExecutor()
	if got := exec.timeoutFor(hcjJob(t, map[string]any{"mode": "local"})); got != 15*time.Minute+hostCryptoJobMargin {
		t.Errorf("default = %v", got)
	}
	if got := exec.timeoutFor(hcjJob(t, map[string]any{"mode": "local", "options": map[string]any{"max_duration_seconds": 3600}})); got != time.Hour+hostCryptoJobMargin {
		t.Errorf("an hour = %v", got)
	}
	if got := exec.timeoutFor(hcjJob(t, map[string]any{"mode": "local", "timeout_seconds": 90})); got != 90*time.Second {
		t.Errorf("explicit = %v", got)
	}
}

// A platform that did not negotiate host_crypto_v1 gets unsupported_command
// and nothing runs.
func TestExecute_HostCryptoNeedsTheCapability(t *testing.T) {
	exec, rec := newTestExecutor()
	exec.negotiated = func(c string) bool { return c != hostcrypto.CapabilityHostCrypto }
	if err := exec.Execute(context.Background(), hcjJob(t, map[string]any{"mode": "local"})); err != nil {
		t.Fatal(err)
	}
	if res := rec.last(); res == nil || res.FailureCode != managedprotocol.CodeUnsupportedCommand || len(res.HostCrypto) != 0 {
		t.Fatalf("result %+v", res)
	}
}

// hcjRunner is the fake SSH transport: it runs each command HERE, as the
// remote targets' own tests do (a remote target over a local transport), and
// records what was asked. What crosses it is exactly what would cross SSH.
type hcjRunner struct {
	inner *hostinventory.LocalRunner
	mu    sync.Mutex
	argv  [][]string
	reads []string
	close int
}

func (r *hcjRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	r.mu.Lock()
	r.argv = append(r.argv, argv)
	r.mu.Unlock()
	return r.inner.Run(ctx, argv)
}

func (r *hcjRunner) RunInput(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	r.mu.Lock()
	r.argv = append(r.argv, argv)
	r.mu.Unlock()
	return r.inner.RunInput(ctx, argv, stdin)
}

func (r *hcjRunner) ReadFile(ctx context.Context, path string) ([]byte, error) {
	r.mu.Lock()
	r.reads = append(r.reads, path)
	r.mu.Unlock()
	return nil, errors.New("hcjRunner: the remote targets never read a whole file")
}

func (r *hcjRunner) Close() error { r.close++; return nil }

// HostKeyInfo is what an SSH runner learned in the handshake.
func (r *hcjRunner) HostKeyInfo() (string, string, string) {
	return "SHA256:" + strings.Repeat("Q", 43), "ssh-ed25519", "first_use"
}

// A remote job: sealed credentials opened with the agent secret and handed
// to the dial with the job's address and pinned host key, the platform asked
// of the host, the remote target used (no agent id, mode remote, no private
// key byte read whole), the transport closed, and a schema-valid result.
func TestExecute_HostCryptoRemoteJob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake transport runs POSIX commands locally")
	}
	dir, secret := hcjKeyDir(t)
	rec := &recordingClient{}
	runner := &hcjRunner{inner: hostinventory.NewLocalRunner()}
	var dialed struct {
		params, creds map[string]interface{}
	}
	exec := &JobExecutor{submitter: rec, config: secretConfig(),
		dialRemote: func(transport hostinventory.Transport, params, creds map[string]interface{}) (hostinventory.Runner, error) {
			if transport != hostinventory.TransportSSH {
				t.Errorf("transport %q", transport)
			}
			dialed.params = params
			dialed.creds = map[string]interface{}{}
			for k, v := range creds {
				dialed.creds[k] = v
			}
			return runner, nil
		}}
	job := hcjJob(t, map[string]any{"mode": "remote", "ip_address": "192.0.2.40", "ssh_port": 2222,
		"ssh_host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"options":                  map[string]any{"sweep_roots": []string{dir}, "max_duration_seconds": 120}})
	job.Credentials = map[string]interface{}{"username": "collector", "password": "remote-password-123"}
	sealJob(job)

	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	res := rec.last()
	if res == nil || !res.Success {
		t.Fatalf("result %+v", res)
	}
	hcjValidateResult(t, res)
	if dialed.creds["username"] != "collector" || dialed.creds["password"] != "remote-password-123" {
		t.Fatalf("the dial did not get the sealed credentials: %v", dialed.creds)
	}
	if dialed.params["ip_address"] != "192.0.2.40" || dialed.params["ssh_host_key_fingerprint"] == nil {
		t.Fatalf("the dial did not get the address and pin: %v", dialed.params)
	}
	r := hcjReport(t, res)
	if r.Mode != hostinventory.ModeRemote || r.AgentID != "" || r.Platform != runtime.GOOS {
		t.Fatalf("mode %q agent %q platform %q", r.Mode, r.AgentID, r.Platform)
	}
	if r.Sections[hostcrypto.SectionSweep] == "" {
		t.Fatalf("no sweep section: %v", r.Sections)
	}
	if len(runner.argv) == 0 || runner.argv[0][0] != "uname" {
		t.Fatalf("the platform was not asked of the host first: %v", runner.argv)
	}
	if len(runner.reads) != 0 {
		t.Fatalf("whole-file reads crossed the transport: %v", runner.reads)
	}
	if runner.close != 1 {
		t.Fatalf("transport closed %d times", runner.close)
	}
	// The host key the job connected through rides in the result, so the
	// platform can pin what a first-use connection trusted.
	if res.Metadata["ssh_host_key_fingerprint"] != "SHA256:"+strings.Repeat("Q", 43) ||
		res.Metadata["ssh_host_key_verification"] != "first_use" || res.Metadata["ssh_host_key_type"] != "ssh-ed25519" {
		t.Fatalf("host key not in the result: %v", res.Metadata)
	}
	b, _ := json.Marshal(res)
	if where := hcjFindSecret(b, secret); where != "" {
		t.Fatalf("the private key's bytes are in the remote result (%s)", where)
	}
	if strings.Contains(string(b), "remote-password-123") {
		t.Fatal("the credential is in the result")
	}
}

// A dial that fails is a failure with no report, and the credential is not
// in its message.
func TestExecute_HostCryptoRemoteDialFailure(t *testing.T) {
	rec := &recordingClient{}
	exec := &JobExecutor{submitter: rec, config: secretConfig(),
		dialRemote: func(hostinventory.Transport, map[string]interface{}, map[string]interface{}) (hostinventory.Runner, error) {
			return nil, errors.New("ssh: handshake failed: host key mismatch")
		}}
	job := hcjJob(t, map[string]any{"mode": "remote", "hostname": "h.example.test"})
	job.Credentials = map[string]interface{}{"username": "u", "password": "p-123456"}
	sealJob(job)
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	res := rec.last()
	if res == nil || res.Success || !strings.Contains(res.Error, "host key mismatch") || len(res.HostCrypto) != 0 {
		t.Fatalf("result %+v", res)
	}
}

// Shutdown cancels a collection; what it read is sent as a FAILED result that
// still carries the report and its section states.
func TestExecute_HostCryptoShutdownSendsThePartialReport(t *testing.T) {
	exec, rec := newTestExecutor()
	life, stop := context.WithCancel(context.Background())
	stop()
	exec.SetShutdown(life)
	if err := exec.Execute(context.Background(), hcjJob(t, map[string]any{"mode": "local"})); err != nil {
		t.Fatal(err)
	}
	res := rec.last()
	if res == nil || res.Success || !strings.Contains(res.Error, "stopped") {
		t.Fatalf("result %+v", res)
	}
	hcjValidateResult(t, res)
	if r := hcjReport(t, res); len(r.Sections) == 0 {
		t.Fatal("the partial report lost its sections")
	}
}

// One collection at a time: a job that cannot get the slot before its
// deadline fails, saying why, and the slot's holder is not disturbed.
func TestExecute_HostCryptoOneAtATime(t *testing.T) {
	release, ok := TryAcquireHostCrypto()
	if !ok {
		t.Fatal("the slot is held at the start of the test")
	}
	defer release()
	if _, ok := TryAcquireHostCrypto(); ok {
		t.Fatal("the slot admitted a second collection")
	}
	exec, rec := newTestExecutor()
	job := hcjJob(t, map[string]any{"mode": "local", "timeout_seconds": 0.2})
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if res := rec.last(); res == nil || res.Success || !strings.Contains(res.Error, "another host crypto collection") {
		t.Fatalf("result %+v", res)
	}
}

// The result builder: a report that trips the backstop is never sent, a
// failed collection with a report sends it as a failure, and no report means
// no host_crypto field.
func TestHostCryptoJobResult(t *testing.T) {
	job := &models.Job{ID: uuid.New(), Type: JobTypeHostCrypto}
	rep := &hostcrypto.Report{Collected: time.Now(), Mode: hostinventory.ModeLocal, Platform: "linux",
		Sections: map[string]string{hostcrypto.SectionPlatform: hostcrypto.SectionOK}}

	if res := HostCryptoJobResult(job, rep, nil, false); !res.Success || len(res.HostCrypto) == 0 {
		t.Fatalf("ok: %+v", res)
	}
	res := HostCryptoJobResult(job, rep, errors.New("platform: boom"), false)
	if res.Success || len(res.HostCrypto) == 0 || !strings.Contains(res.Error, "boom") {
		t.Fatalf("failure with a report: %+v", res)
	}
	hcjValidateResult(t, res)
	if res := HostCryptoJobResult(job, nil, errors.New("no platform"), false); res.Success || len(res.HostCrypto) != 0 {
		t.Fatalf("no report: %+v", res)
	}
	leaky := *rep
	leaky.Configs = []hostcrypto.CryptoConfig{{Location: hostcrypto.Location{FoundBy: hostcrypto.FoundByConfig}, Product: "x",
		Settings: map[string]string{"k": "-----BEGIN EC PRIVATE KEY-----"}}}
	res = HostCryptoJobResult(job, &leaky, nil, false)
	// A key-SHAPED value is data: withheld, and the report still sent.
	if !res.Success || strings.Contains(string(res.HostCrypto), "BEGIN EC PRIVATE KEY") || !strings.Contains(string(res.HostCrypto), "name withheld") {
		t.Fatalf("a key-shaped setting: %+v %s", res, res.HostCrypto)
	}
}

// The operator's host_crypto_exclude_paths bind every job, local and remote:
// with the setting naming the sweep root, the key there is not found and the
// scope lists the path beside the job's own; without it, the key is found.
func TestExecute_HostCryptoSettingExcludesBindEveryJob(t *testing.T) {
	dir, _ := hcjKeyDir(t)
	// A remote sweep goes by name: give it one it identifies.
	b, err := os.ReadFile(filepath.Join(dir, "notes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	found := func(r *hostcrypto.Report) bool {
		for _, k := range r.PrivateKeys {
			if strings.HasPrefix(k.Location.Path, dir) {
				return true
			}
		}
		return false
	}
	run := func(t *testing.T, mode string, setting []string) *hostcrypto.Report {
		t.Helper()
		rec := &recordingClient{}
		exec := &JobExecutor{submitter: rec, config: secretConfig(),
			dialRemote: func(hostinventory.Transport, map[string]interface{}, map[string]interface{}) (hostinventory.Runner, error) {
				return &hcjRunner{inner: hostinventory.NewLocalRunner()}, nil
			}}
		if setting != nil {
			exec.SetHostCryptoExcludes(func() []string { return setting })
		}
		job := hcjJob(t, map[string]any{"mode": mode, "ip_address": "192.0.2.41",
			"options": map[string]any{"sweep_roots": []string{dir}, "exclude_paths": []string{"/job/own"}, "max_duration_seconds": 120}})
		if mode == "remote" {
			job.Credentials = map[string]interface{}{"username": "u", "password": "p-123456"}
			sealJob(job)
		}
		if err := exec.Execute(context.Background(), job); err != nil {
			t.Fatal(err)
		}
		res := rec.last()
		if res == nil || !res.Success {
			t.Fatalf("result %+v", res)
		}
		return hcjReport(t, res)
	}
	modes := []string{"local"}
	if runtime.GOOS != "windows" {
		modes = append(modes, "remote")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			without := run(t, mode, nil)
			if !found(without) || strings.Join(without.Scope.ExcludedPaths, ",") != "/job/own" {
				t.Fatalf("without the setting: found %v, excluded %v", found(without), without.Scope.ExcludedPaths)
			}
			with := run(t, mode, []string{dir, "/job/own"})
			if found(with) {
				t.Fatal("the setting's excluded path was entered")
			}
			ex := strings.Join(with.Scope.ExcludedPaths, ",")
			if !strings.Contains(ex, dir) || strings.Count(ex, "/job/own") != 1 {
				t.Fatalf("excluded %v: want the job's and the setting's, each once", with.Scope.ExcludedPaths)
			}
		})
	}
}

func TestMergeHostCryptoExcludes(t *testing.T) {
	if got := MergeHostCryptoExcludes([]string{"/a", "/b"}, []string{"/b", "/c"}); strings.Join(got, ",") != "/a,/b,/c" {
		t.Fatalf("%v", got)
	}
	if got := MergeHostCryptoExcludes(nil, nil); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// A job's opt-ins never exceed the agent's confirmed ones: unconfirmed, they
// are lowered and the report says why; confirmed, they stand.
func TestExecute_HostCryptoJobOptInsAreClampedToConsents(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		exec, rec := newTestExecutor()
		exec.SetHostCryptoConsents(func() (bool, bool) { return confirmed, confirmed })
		job := hcjJob(t, map[string]any{"mode": "local", "options": map[string]any{
			"home_directories": true, "default_keystore_passwords": true, "max_duration_seconds": 60, "max_files": 50}})
		if err := exec.Execute(context.Background(), job); err != nil {
			t.Fatal(err)
		}
		r := hcjReport(t, rec.last())
		if r.Scope.HomeDirectories != confirmed || r.Scope.DefaultKeystorePasswords != confirmed {
			t.Fatalf("confirmed=%v: scope %+v", confirmed, r.Scope)
		}
		noted := 0
		for _, e := range r.Errors {
			if e.Step == "scope" && strings.Contains(e.Message, "not confirmed") {
				noted++
			}
		}
		if (noted == 2) == confirmed {
			t.Fatalf("confirmed=%v: %d clamp notes", confirmed, noted)
		}
	}
}
