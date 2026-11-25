package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/devices"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/outputschema"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocoltest"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig/desiredstate"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func hcjReport(mode hostinventory.Mode, sections map[string]string) *hostcrypto.Report {
	if sections == nil {
		sections = map[string]string{hostcrypto.SectionPlatform: hostcrypto.SectionOK, hostcrypto.SectionCertificates: hostcrypto.SectionOK}
	}
	return &hostcrypto.Report{Collected: time.Now().UTC(), Mode: mode, Platform: "linux", Sections: sections}
}

func hcjReady() bool { return true }

// hcjSubmitter records what the loop sends.
type hcjSubmitter struct {
	mu         sync.Mutex
	negotiated error
	submitted  []*hostcrypto.Report
}

func (s *hcjSubmitter) HostCryptoNegotiated() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.negotiated
}

func (s *hcjSubmitter) SubmitHostCrypto(r *hostcrypto.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submitted = append(s.submitted, r)
	return nil
}

func (s *hcjSubmitter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.submitted)
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

// ---------------------------------------------------------------------------
// The supervisor and its settings
// ---------------------------------------------------------------------------

func TestHostCryptoSupervisorSettings(t *testing.T) {
	var runs atomic.Int32
	s := newHostCryptoSupervisor(0, hostCryptoSettings{}, func(_ *interval, stop <-chan struct{}) {
		runs.Add(1)
		<-stop
	})
	if s.interval != config.DefaultHostCryptoInterval {
		t.Fatalf("default interval %v", s.interval)
	}
	if err := s.setEnabled(true); err != nil || !s.isEnabled() {
		t.Fatal(err)
	}
	_ = s.setEnabled(true) // idempotent: one loop
	waitFor(t, func() bool { return runs.Load() == 1 }, "the loop to start once")
	if err := s.setEnabled(false); err != nil || s.isEnabled() {
		t.Fatal(err)
	}
	if err := s.setInterval(time.Minute); err == nil {
		t.Fatal("a one-minute interval was accepted")
	}
	if err := s.setInterval(2 * time.Hour); err != nil {
		t.Fatal(err)
	}
	_ = s.setHomeDirectories(true)
	_ = s.setDefaultKeystorePasswords(true)
	if err := s.setExcludePaths("/var/lib/docker\n/opt/b"); err != nil {
		t.Fatal(err)
	}
	if err := s.setExcludePaths("/ok\nrelative"); err == nil {
		t.Fatal("a relative path was accepted")
	}
	o := s.options()
	if !o.HomeDirectories || !o.DefaultKeystorePasswords || strings.Join(o.ExcludePaths, ",") != "/opt/b,/var/lib/docker" {
		t.Fatalf("options %+v: the refused list must leave the previous one", o)
	}
	if len(o.SweepRoots) != 0 {
		t.Fatal("the schedule must not sweep")
	}
}

// Each host crypto setting reaches the supervisor through the applier.
func TestHostCryptoSettingsAreApplied(t *testing.T) {
	applier := desiredstate.New()
	s := newHostCryptoSupervisor(time.Hour, hostCryptoSettings{}, func(_ *interval, stop <-chan struct{}) { <-stop })
	registerHostCryptoSettings(applier, s)
	applier.Apply("rev-2", agentconfig.Values{
		agentconfig.KeyHostCryptoEnabled:                  agentconfig.Bool(true),
		agentconfig.KeyHostCryptoInterval:                 agentconfig.Int(7200),
		agentconfig.KeyHostCryptoHomeDirectories:          agentconfig.Bool(true),
		agentconfig.KeyHostCryptoDefaultKeystorePasswords: agentconfig.Bool(true),
		agentconfig.KeyHostCryptoExcludePaths:             agentconfig.Text("/srv/secret"),
	})
	t.Cleanup(func() { _ = s.setEnabled(false) })
	if _, failures, _ := applier.Report(); len(failures) != 0 {
		t.Fatalf("failures %v", failures)
	}
	o := s.options()
	if !s.isEnabled() || s.interval != 2*time.Hour || !o.HomeDirectories || !o.DefaultKeystorePasswords || o.ExcludePaths[0] != "/srv/secret" {
		t.Fatalf("enabled %v interval %v options %+v", s.isEnabled(), s.interval, o)
	}
}

// ---------------------------------------------------------------------------
// The local loop
// ---------------------------------------------------------------------------

// Nothing is collected for a platform that has not negotiated host_crypto_v1.
func TestHostCryptoLoop_NotNegotiatedCollectsNothing(t *testing.T) {
	sub := &hcjSubmitter{negotiated: api.ErrHostCryptoNotNegotiated}
	var calls atomic.Int32
	stop := make(chan struct{})
	close(stop)
	runLocalHostCryptoLoop(sub, "a", newInterval(time.Hour), stop, hcjReady, func() hostcrypto.Options { return hostcrypto.Options{} },
		func(context.Context, string, hostcrypto.Options) (*hostcrypto.Report, error) {
			calls.Add(1)
			return hcjReport(hostinventory.ModeLocal, nil), nil
		}, time.Millisecond)
	if calls.Load() != 0 || sub.count() != 0 {
		t.Fatalf("collected %d, submitted %d", calls.Load(), sub.count())
	}
}

// On start and then at the interval, with the settings as they are at each
// collection; the agent id rides along.
func TestHostCryptoLoop_CollectsAtTheInterval(t *testing.T) {
	sub := &hcjSubmitter{}
	var mu sync.Mutex
	var seen []hostcrypto.Options
	var ids []string
	stop := make(chan struct{})
	home := atomic.Bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLocalHostCryptoLoop(sub, "agent-1", newInterval(20*time.Millisecond), stop, hcjReady,
			func() hostcrypto.Options { return hostcrypto.Options{HomeDirectories: home.Load()} },
			func(_ context.Context, id string, o hostcrypto.Options) (*hostcrypto.Report, error) {
				mu.Lock()
				seen, ids = append(seen, o), append(ids, id)
				mu.Unlock()
				home.Store(true)
				return hcjReport(hostinventory.ModeLocal, nil), nil
			}, time.Millisecond)
	}()
	waitFor(t, func() bool { return sub.count() >= 3 }, "three collections")
	close(stop)
	<-done
	mu.Lock()
	defer mu.Unlock()
	if seen[0].HomeDirectories || !seen[1].HomeDirectories || ids[0] != "agent-1" {
		t.Fatalf("settings are not read per collection: %+v %v", seen, ids)
	}
}

// Stopped while collecting: the collection is cancelled and nothing is sent.
func TestHostCryptoLoop_StopCancelsAndSendsNothing(t *testing.T) {
	sub := &hcjSubmitter{}
	stop := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLocalHostCryptoLoop(sub, "a", newInterval(time.Hour), stop, hcjReady, func() hostcrypto.Options { return hostcrypto.Options{} },
			func(ctx context.Context, _ string, _ hostcrypto.Options) (*hostcrypto.Report, error) {
				close(started)
				<-ctx.Done()
				return hcjReport(hostinventory.ModeLocal, map[string]string{hostcrypto.SectionCertificates: hostcrypto.SectionPartial}), nil
			}, time.Millisecond)
	}()
	<-started
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop: the collection was not cancelled")
	}
	if sub.count() != 0 {
		t.Fatal("a cancelled collection was sent")
	}
}

// One collection at a time: a cycle that finds the slot taken is skipped.
func TestHostCryptoLoop_SkipsWhileAJobCollects(t *testing.T) {
	release, ok := devices.TryAcquireHostCrypto()
	if !ok {
		t.Fatal("slot held")
	}
	defer release()
	sub := &hcjSubmitter{}
	var calls atomic.Int32
	stop := make(chan struct{})
	close(stop)
	runLocalHostCryptoLoop(sub, "a", newInterval(time.Hour), stop, hcjReady, func() hostcrypto.Options { return hostcrypto.Options{} },
		func(context.Context, string, hostcrypto.Options) (*hostcrypto.Report, error) {
			calls.Add(1)
			return nil, nil
		}, time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("collected while another collection held the slot")
	}
}

// ---------------------------------------------------------------------------
// The wiring, end to end against a stub platform
// ---------------------------------------------------------------------------

// hcjPlatform is a protocol-1 stub that answers every heartbeat with values
// and records the host-crypto posts, held to host-crypto.submission.
type hcjPlatform struct {
	srv     *httptest.Server
	mu      sync.Mutex
	values  agentconfig.Values
	posts   [][]byte
	results [][]byte
}

func newHCJPlatform(t *testing.T, values agentconfig.Values) *hcjPlatform {
	p := &hcjPlatform{values: values}
	p.srv = httptest.NewServer(protocoltest.Speak1(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			p.mu.Lock()
			v := p.values
			p.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"config": agentconfig.ExchangePayload{
				Revision: agentconfig.Revision(agentconfig.RuntimeAgent, v), Values: v}})
		case strings.HasSuffix(r.URL.Path, "/host-crypto"):
			body, _ := io.ReadAll(r.Body)
			p.mu.Lock()
			p.posts = append(p.posts, body)
			p.mu.Unlock()
			_, _ = w.Write([]byte(`{"message":"accepted"}`))
		case strings.HasSuffix(r.URL.Path, "/results"):
			body, _ := io.ReadAll(r.Body)
			p.mu.Lock()
			p.results = append(p.results, body)
			p.mu.Unlock()
			_, _ = w.Write([]byte(`{"message":"accepted"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *hcjPlatform) postCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.posts)
}

func hcjAgent(t *testing.T, p *hcjPlatform, enabled bool, collect hostCryptoCollector) *DeviceAgent {
	hostCryptoReadyPoll = 10 * time.Millisecond
	t.Cleanup(func() { hostCryptoReadyPoll = time.Second })
	cfg := &config.Config{PlatformURL: p.srv.URL, AgentID: uuid.New().String(), DataPath: t.TempDir(),
		PollInterval: 30 * time.Minute, HeartbeatInterval: 30 * time.Minute, HostCryptoEnabled: enabled,
		HostCryptoInterval: 6 * time.Hour}
	return hcjAgentWith(t, cfg, collect)
}

func hcjAgentWith(t *testing.T, cfg *config.Config, collect hostCryptoCollector) *DeviceAgent {
	agent := newDeviceAgent(cfg, "", nil)
	agent.hostCryptoCollector = collect
	t.Cleanup(agent.Stop)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	return agent
}

// The platform turns host crypto on for an agent whose file says nothing; the
// agent collects with the pushed opt-ins and posts a submission that
// satisfies the published schema. Deleting registerHostCryptoSettings from
// newDeviceAgent, or the collector's wiring, fails this.
func TestHostCryptoWiring_PlatformTurnsItOn(t *testing.T) {
	p := newHCJPlatform(t, agentconfig.Effective(agentconfig.RuntimeAgent, nil, agentconfig.Values{
		agentconfig.KeyHostCryptoEnabled:         agentconfig.Bool(true),
		agentconfig.KeyHostCryptoHomeDirectories: agentconfig.Bool(true),
		agentconfig.KeyHostCryptoExcludePaths:    agentconfig.Text("/srv/never"),
	}))
	var got atomic.Pointer[hostcrypto.Options]
	agent := hcjAgent(t, p, false, func(_ context.Context, id string, o hostcrypto.Options) (*hostcrypto.Report, error) {
		got.Store(&o)
		r := hcjReport(hostinventory.ModeLocal, nil)
		r.AgentID = id
		return r, nil
	})
	waitFor(t, func() bool { return p.postCount() > 0 }, "a host crypto submission")
	if !agent.hostCrypto.isEnabled() {
		t.Fatal("the supervisor is not on")
	}
	o := got.Load()
	if o == nil || !o.HomeDirectories || len(o.ExcludePaths) != 1 || o.ExcludePaths[0] != "/srv/never" {
		t.Fatalf("collected with %+v", o)
	}
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	body := p.posts[0]
	p.mu.Unlock()
	if err := set.ValidateJSON("host-crypto.submission", body); err != nil {
		t.Fatalf("the submission does not satisfy its schema: %v\n%s", err, body)
	}
}

// Off by default: an agent whose file says nothing, answered with the
// built-in defaults, never collects.
func TestHostCryptoWiring_OffByDefault(t *testing.T) {
	p := newHCJPlatform(t, agentconfig.Effective(agentconfig.RuntimeAgent, nil, nil))
	var calls atomic.Int32
	agent := hcjAgent(t, p, false, func(context.Context, string, hostcrypto.Options) (*hostcrypto.Report, error) {
		calls.Add(1)
		return hcjReport(hostinventory.ModeLocal, nil), nil
	})
	waitFor(t, func() bool { return len(agent.applier.Current()) > 0 }, "the first answer to be applied")
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 0 || agent.hostCrypto.isEnabled() || p.postCount() != 0 {
		t.Fatalf("collected %d times with the setting off", calls.Load())
	}
}

// The file's setting is reported as the running position, so the platform
// can adopt it rather than turn it off.
func TestHostCryptoLocalValues(t *testing.T) {
	v := localValues(&config.Config{HostCryptoEnabled: true, HostCryptoInterval: 2 * time.Hour,
		HostCryptoExcludePaths: []string{"/b", "/a"}})
	if b := v[agentconfig.KeyHostCryptoEnabled]; b.B == nil || !*b.B {
		t.Fatalf("enabled not reported: %v", v)
	}
	if i := v[agentconfig.KeyHostCryptoInterval]; i.I == nil || *i.I != 7200 {
		t.Fatalf("interval not reported: %v", v)
	}
	if s := v[agentconfig.KeyHostCryptoExcludePaths]; s.S == nil || *s.S != "/a\n/b" {
		t.Fatalf("excludes not reported canonically: %v", v)
	}
	if _, ok := v[agentconfig.KeyHostCryptoHomeDirectories]; ok {
		t.Fatal("an opt-in the file does not turn on was reported")
	}
}

// ---------------------------------------------------------------------------
// Standalone
// ---------------------------------------------------------------------------

func hcjFakeCollector(rep *hostcrypto.Report, err error) func(context.Context, hostcrypto.Options) (*hostcrypto.Report, error) {
	return func(context.Context, hostcrypto.Options) (*hostcrypto.Report, error) { return rep, err }
}

// hcjReportOf returns the report of the one host_crypto record, after
// holding every record to the output schema and the report to the managed
// definition.
func hcjReportOf(t *testing.T, out []byte) (*hostcrypto.Report, []string) {
	t.Helper()
	kinds := outputschema.ValidateJSONL(t, out)
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	def, err := set.CompileDef("defs/host-crypto-report.json")
	if err != nil {
		t.Fatal(err)
	}
	var rep *hostcrypto.Report
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		var rec struct {
			Kind string `json:"kind"`
			Data struct {
				Report json.RawMessage `json:"report"`
			} `json:"data"`
		}
		_ = json.Unmarshal(line, &rec)
		if rec.Kind != string(agentoutput.KindHostCrypto) {
			continue
		}
		var inst any
		_ = json.Unmarshal(rec.Data.Report, &inst)
		if err := def.Validate(inst); err != nil {
			t.Fatalf("the record's report does not satisfy defs/host-crypto-report.json: %v", err)
		}
		rep = &hostcrypto.Report{}
		if err := json.Unmarshal(rec.Data.Report, rep); err != nil {
			t.Fatal(err)
		}
	}
	return rep, kinds
}

// The golden shape: run, one host_crypto record holding {"report"}, summary;
// exit 0 for a complete collection, 2 when a section failed, 1 when the
// collection failed outright (with an error record).
func TestStandaloneHostCrypto_Shape(t *testing.T) {
	res := runCmd(t, standaloneEnv{collectHostCrypto: hcjFakeCollector(hcjReport(hostinventory.ModeLocal, nil), nil)}, "host-crypto")
	if res.code != 0 {
		t.Fatalf("exit %d\n%s", res.code, res.stderr)
	}
	rep, kinds := hcjReportOf(t, []byte(res.stdout))
	if strings.Join(kinds, ",") != "run,host_crypto,summary" || rep == nil || rep.Mode != hostinventory.ModeLocal {
		t.Fatalf("kinds %v report %+v", kinds, rep)
	}

	failed := hcjReport(hostinventory.ModeLocal, map[string]string{hostcrypto.SectionPlatform: hostcrypto.SectionOK, hostcrypto.SectionKeystores: hostcrypto.SectionFailed})
	res = runCmd(t, standaloneEnv{collectHostCrypto: hcjFakeCollector(failed, nil)}, "host-crypto", "--format", "json")
	if res.code != 2 || !strings.Contains(res.stderr, "keystores failed") {
		t.Fatalf("a failed section: exit %d\n%s", res.code, res.stderr)
	}

	limited := hcjReport(hostinventory.ModeLocal, nil)
	limited.Limits = []hostcrypto.LimitHit{{Section: hostcrypto.SectionSweep, Limit: "max_files", Detail: "stopped after 10 files"}}
	if res = runCmd(t, standaloneEnv{collectHostCrypto: hcjFakeCollector(limited, nil)}, "host-crypto"); res.code != 2 {
		t.Fatalf("a bound that cut a section: exit %d", res.code)
	}

	res = runCmd(t, standaloneEnv{collectHostCrypto: hcjFakeCollector(nil, errors.New("no platform"))}, "host-crypto")
	if _, kinds := hcjReportOf(t, []byte(res.stdout)); res.code != 1 || countKind(kinds, agentoutput.KindError) != 1 {
		t.Fatalf("a failed collection: exit %d kinds %v", res.code, kinds)
	}

	// A key-shaped value is withheld; the report is still written.
	leaky := hcjReport(hostinventory.ModeLocal, nil)
	leaky.Configs = []hostcrypto.CryptoConfig{{Location: hostcrypto.Location{FoundBy: hostcrypto.FoundByConfig}, Product: "x",
		Settings: map[string]string{"k": "-----BEGIN PRIVATE KEY-----"}}}
	res = runCmd(t, standaloneEnv{collectHostCrypto: hcjFakeCollector(leaky, nil)}, "host-crypto")
	if res.code != 0 || strings.Contains(res.stdout, "BEGIN PRIVATE KEY") || !strings.Contains(res.stdout, "name withheld") {
		t.Fatalf("a key-shaped value: exit %d\n%s", res.code, res.stdout)
	}
}

// Flags reach the collector; bad invocations are refused before anything is
// collected.
func TestStandaloneHostCrypto_FlagsAndUsage(t *testing.T) {
	var got hostcrypto.Options
	collect := func(_ context.Context, o hostcrypto.Options) (*hostcrypto.Report, error) {
		got = o
		return hcjReport(hostinventory.ModeLocal, nil), nil
	}
	res := runCmd(t, standaloneEnv{collectHostCrypto: collect}, "host-crypto", "--home-directories", "--default-keystore-passwords",
		"--exclude", "/var/lib/docker", "--exclude", `C:\Windows`, "--root", "/opt", "--max-duration", "2m", "--quiet")
	if res.code != 0 || !got.HomeDirectories || !got.DefaultKeystorePasswords || len(got.ExcludePaths) != 2 ||
		got.SweepRoots[0] != "/opt" || got.MaxDuration != 2*time.Minute {
		t.Fatalf("exit %d options %+v", res.code, got)
	}
	for _, args := range [][]string{
		{"--exclude", "relative"},
		{"--root", "/a/../b"},
		{"--max-duration", "10s"},
		{"--max-duration", "2h"},
		{"--identity-file", "/x"},
		{"--ssh-host-key", "SHA256:x"},
		{"--remote", "nouser-host"},
		{"--remote", "u@"},
		{"--remote", "u@h", "--ssh-host-key", "MD5:aa"},
		{"--remote", "u@h"}, // no credential
		{"--remote", "u@h", "--port", "70000"},
		{"--format", "xml"},
		{"stray"},
	} {
		called := false
		res := runCmd(t, standaloneEnv{collectHostCrypto: func(context.Context, hostcrypto.Options) (*hostcrypto.Report, error) {
			called = true
			return nil, nil
		}, dialHostCrypto: func(hostinventory.SSHConfig) (hostCryptoDial, error) {
			called = true
			return hostCryptoDial{}, errors.New("no")
		}}, append([]string{"host-crypto"}, args...)...)
		if res.code != 1 || called || res.stdout != "" {
			t.Errorf("%q: exit %d, contacted %v, stdout %q", args, res.code, called, res.stdout)
		}
	}
	help := runCmd(t, standaloneEnv{}, "host-crypto", "--help")
	for _, want := range []string{"--remote", "-home-directories", "-default-keystore-passwords", "-exclude", "-root", "-identity-file", "never their contents", "Exit status"} {
		if help.code != 0 || !strings.Contains(help.stdout, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

// hcjLocalTransport stands in for SSH: commands run here, as the remote
// targets' own tests run them.
type hcjLocalTransport struct{ *hostinventory.LocalRunner }

func (hcjLocalTransport) ReadFile(context.Context, string) ([]byte, error) {
	return nil, errors.New("the remote targets never read a whole file")
}

func hcjIdentity(t *testing.T, mode os.FileMode) (string, string, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	pemText := string(pem.EncodeToMemory(block))
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path, pemText, key.Seed()
}

// --remote: the identity file reaches the dial as the credential and never
// the output; the host is read through the remote target (mode remote, no
// agent id); an unpinned host key is reported with the pin to use; and an
// identity file others can read is refused before any connection.
func TestStandaloneHostCrypto_Remote(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake transport runs POSIX commands locally")
	}
	keyPath, keyPEM, seed := hcjIdentity(t, 0o600)
	var dialed hostinventory.SSHConfig
	env := standaloneEnv{dialHostCrypto: func(cfg hostinventory.SSHConfig) (hostCryptoDial, error) {
		dialed = cfg
		return hostCryptoDial{runner: hcjLocalTransport{hostinventory.NewLocalRunner()}, hostKey: "SHA256:fakefakefake", verified: "first_use"}, nil
	}}
	out := filepath.Join(t.TempDir(), "remote.jsonl")
	res := runCmd(t, env, "host-crypto", "--remote", "collector@192.0.2.50", "--port", "2222", "--identity-file", keyPath,
		"--max-duration", "2m", "--out", out)
	if res.code == 1 {
		t.Fatalf("exit %d\n%s", res.code, res.stderr)
	}
	if dialed.User != "collector" || dialed.Host != "192.0.2.50" || dialed.Port != 2222 || dialed.PrivateKeyPEM != keyPEM {
		t.Fatalf("dialed %+v", dialed)
	}
	if !strings.Contains(res.stderr, "--ssh-host-key SHA256:fakefakefake") {
		t.Fatalf("the unpinned host key is not reported:\n%s", res.stderr)
	}
	b := []byte(readFile(t, out))
	rep, _ := hcjReportOf(t, b)
	if rep == nil || rep.Mode != hostinventory.ModeRemote || rep.AgentID != "" {
		t.Fatalf("report %+v", rep)
	}
	if where := hcjFindSecret(b, seed); where != "" || strings.Contains(string(b), "OPENSSH PRIVATE KEY") {
		t.Fatalf("the identity key is in the output (%s)", where)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode %v %v, want 0600", info.Mode().Perm(), err)
	}

	loose, _, _ := hcjIdentity(t, 0o644)
	called := false
	env.dialHostCrypto = func(hostinventory.SSHConfig) (hostCryptoDial, error) {
		called = true
		return hostCryptoDial{}, errors.New("no")
	}
	if res := runCmd(t, env, "host-crypto", "--remote", "u@192.0.2.50", "--identity-file", loose); res.code != 1 || called ||
		!strings.Contains(res.stderr, "chmod 600") {
		t.Fatalf("a group-readable identity file: exit %d dialed %v\n%s", res.code, called, res.stderr)
	}

	// A failed connection is a failed run with one error record.
	env.dialHostCrypto = func(hostinventory.SSHConfig) (hostCryptoDial, error) {
		return hostCryptoDial{}, errors.New("ssh: host key mismatch")
	}
	res = runCmd(t, env, "host-crypto", "--remote", "u@192.0.2.50", "--identity-file", keyPath)
	if _, kinds := hcjReportOf(t, []byte(res.stdout)); res.code != 1 || countKind(kinds, agentoutput.KindError) != 1 || !strings.Contains(res.stdout, "host key mismatch") {
		t.Fatalf("exit %d\n%s", res.code, res.stdout)
	}
}

// End to end through the real local collector: a directory of generated keys
// swept with --root; the output describes them and holds none of their
// private bytes.
func TestStandaloneHostCrypto_SecrecyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(filepath.Join(dir, "README"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, _ := key.Bytes()
	res := runCmd(t, standaloneEnv{}, "host-crypto", "--root", dir, "--max-duration", "2m")
	if res.code == 1 {
		t.Fatalf("exit %d\n%s", res.code, res.stderr)
	}
	rep, _ := hcjReportOf(t, []byte(res.stdout))
	found := false
	for _, k := range rep.PrivateKeys {
		found = found || k.Location.Path == filepath.Join(dir, "README")
	}
	if !found {
		t.Fatalf("the generated key was not found (sections %v)", rep.Sections)
	}
	if where := hcjFindSecret([]byte(res.stdout), priv); where != "" {
		t.Fatalf("the private key's bytes are in the output (%s)", where)
	}
	if hcjFindSecret([]byte(res.stdout+hex.EncodeToString(priv)), priv) == "" {
		t.Fatal("the secrecy check is inert")
	}
}

// The agent wires its excluded-paths setting into the job executor: a job
// run by the real agent excludes the setting's paths as well as its own.
// Deleting SetHostCryptoExcludes from newDeviceAgent fails this.
func TestHostCryptoWiring_SettingExcludesReachJobs(t *testing.T) {
	p := newHCJPlatform(t, nil)
	cfg := &config.Config{PlatformURL: p.srv.URL, AgentID: uuid.New().String(), DataPath: t.TempDir(),
		PollInterval: 30 * time.Minute, HeartbeatInterval: 30 * time.Minute,
		HostCryptoExcludePaths: []string{"/srv/operator-never"}}
	agent := newDeviceAgent(cfg, "", nil)
	t.Cleanup(agent.Stop)
	protocoltest.Open(agent.apiClient.Gate())
	params := map[string]interface{}{"mode": "local", "options": map[string]interface{}{
		"exclude_paths": []interface{}{"/job/own"}, "max_duration_seconds": float64(60)}}
	job := &models.Job{ID: uuid.New(), Type: devices.JobTypeHostCrypto, Parameters: params}
	if err := agent.jobExecutor.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.results) != 1 {
		t.Fatalf("%d results", len(p.results))
	}
	var res struct {
		HostCrypto hostcrypto.Report `json:"host_crypto"`
	}
	if err := json.Unmarshal(p.results[0], &res); err != nil {
		t.Fatal(err)
	}
	if ex := strings.Join(res.HostCrypto.Scope.ExcludedPaths, ","); ex != "/job/own,/srv/operator-never" {
		t.Fatalf("excluded %q, want the job's and the setting's", ex)
	}
}

// A consent is never the device's: a configuration file asking for both
// opt-ins (and for host crypto), answered by a platform that turns host
// crypto on and the opt-ins off, collects for the first time with both off.
// Driven through the real supervisor, file loader and heartbeat.
func TestHostCryptoConsentsNeverComeFromTheDevice(t *testing.T) {
	hostCryptoReadyPoll = 10 * time.Millisecond
	t.Cleanup(func() { hostCryptoReadyPoll = time.Second })
	for _, platformSays := range []bool{false, true} {
		p := newHCJPlatform(t, agentconfig.Effective(agentconfig.RuntimeAgent, nil, agentconfig.Values{
			agentconfig.KeyHostCryptoEnabled:                  agentconfig.Bool(true),
			agentconfig.KeyHostCryptoHomeDirectories:          agentconfig.Bool(platformSays),
			agentconfig.KeyHostCryptoDefaultKeystorePasswords: agentconfig.Bool(platformSays),
		}))
		path := filepath.Join(t.TempDir(), "agent.yaml")
		if err := os.WriteFile(path, []byte("platform_url: "+p.srv.URL+"\nagent_id: "+uuid.New().String()+
			"\nhost_crypto_enabled: true\nhost_crypto_home_directories: true\nhost_crypto_default_keystore_passwords: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.LoadFromFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg.DataPath, cfg.PollInterval, cfg.HeartbeatInterval = t.TempDir(), 30*time.Minute, 30*time.Minute
		var mu sync.Mutex
		var seen []hostcrypto.Options
		agent := hcjAgentWith(t, cfg, func(_ context.Context, id string, o hostcrypto.Options) (*hostcrypto.Report, error) {
			mu.Lock()
			seen = append(seen, o)
			mu.Unlock()
			r := hcjReport(hostinventory.ModeLocal, nil)
			r.AgentID = id
			return r, nil
		})
		if v := localValues(cfg); v[agentconfig.KeyHostCryptoHomeDirectories].B != nil || v[agentconfig.KeyHostCryptoDefaultKeystorePasswords].B != nil {
			t.Fatalf("the device reports consents as running: %v", v)
		}
		waitFor(t, func() bool { return p.postCount() > 0 }, "a submission")
		mu.Lock()
		first := seen[0]
		mu.Unlock()
		if first.HomeDirectories != platformSays || first.DefaultKeystorePasswords != platformSays {
			t.Fatalf("platform says %v: the first collection ran with home=%v defaults=%v", platformSays, first.HomeDirectories, first.DefaultKeystorePasswords)
		}
		agent.Stop()
	}
}

// No scheduled collection before the first desired state is applied.
func TestHostCryptoLoop_WaitsForTheFirstDesiredState(t *testing.T) {
	hostCryptoReadyPoll = 5 * time.Millisecond
	t.Cleanup(func() { hostCryptoReadyPoll = time.Second })
	var ready atomic.Bool
	var calls atomic.Int32
	sub := &hcjSubmitter{}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLocalHostCryptoLoop(sub, "a", newInterval(time.Hour), stop, ready.Load, func() hostcrypto.Options { return hostcrypto.Options{} },
			func(context.Context, string, hostcrypto.Options) (*hostcrypto.Report, error) {
				calls.Add(1)
				return hcjReport(hostinventory.ModeLocal, nil), nil
			}, time.Millisecond)
	}()
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("collected before any desired state was applied")
	}
	ready.Store(true)
	waitFor(t, func() bool { return calls.Load() == 1 }, "the collection once the desired state is in")
	close(stop)
	<-done
}
