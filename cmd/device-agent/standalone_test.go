package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/devices"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/outputschema"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory/kubetest"
)

// The standalone commands, driven through runStandalone (the same entry main
// calls) against fake appliances on loopback, through the REAL registry, so
// the projection and redaction a managed job gets are what these runs get.

// A password distinctive enough that finding it anywhere is a leak.
const leakCanary = "Zq9-standalone-CANARY-pw-7741"

type fakeFortiGate struct {
	srv           *httptest.Server
	requests      atomic.Int64
	refuseIfaces  bool
	wantUser      string
	wantPassword  string
	echoOnFailure bool
}

// newFakeFortiGate answers the FortiOS REST endpoints the collector reads,
// with HTTP basic auth checked against user/password. A wrong login gets 401;
// with echoOnFailure the body repeats the password it was offered, the way a
// careless appliance error might.
func newFakeFortiGate(t *testing.T, user, password string) *fakeFortiGate {
	t.Helper()
	f := &fakeFortiGate{wantUser: user, wantPassword: password}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		u, p, _ := r.BasicAuth()
		if u != f.wantUser || p != f.wantPassword {
			w.WriteHeader(http.StatusUnauthorized)
			if f.echoOnFailure {
				_, _ = w.Write([]byte(`{"http_status":401,"status":"error","error_message":"login failed for ` + u + ` with password ` + p + `"}`))
			}
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/monitor/system/status"):
			_, _ = w.Write([]byte(`{"status":"success","serial":"FGT60F0000000001","version":"v7.4.4",
				"results":{"hostname":"fw-branch-01","model_name":"FortiGate 60F","version":"v7.4.4"}}`))
		case strings.HasSuffix(r.URL.Path, "/cmdb/vpn.ssl/settings"):
			_, _ = w.Write([]byte(`{"status":"success","results":{"status":"enable","port":10443,
				"server_ip":"192.0.2.10","cipher":"TLS-AES-256-GCM-SHA384"}}`))
		case strings.HasSuffix(r.URL.Path, "/cmdb/system/interface") && f.refuseIfaces:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"http_status":403,"status":"error"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"success","results":[]}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	devicetest.AllowListener(t, f.srv.Listener.Addr().String())
	return f
}

type runOutcome struct {
	code   int
	stdout string
	stderr string
}

func runCmd(t *testing.T, env standaloneEnv, args ...string) runOutcome {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env.stdout, env.stderr = &stdout, &stderr
	if env.getenv == nil {
		env.getenv = func(string) string { return "" }
	}
	code, ok := runStandalone(args, env)
	if !ok {
		t.Fatalf("runStandalone(%q) did not recognise the subcommand", args)
	}
	return runOutcome{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func writeCredentials(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func countKind(kinds []string, kind agentoutput.Kind) int {
	n := 0
	for _, k := range kinds {
		if k == string(kind) {
			n++
		}
	}
	return n
}

func collectArgs(f *fakeFortiGate, extra ...string) []string {
	return append([]string{"collect", "--type", "fortigate", "--target", "192.0.2.10",
		"--management-url", f.srv.URL}, extra...)
}

func TestStandaloneCollect_EndToEndInEveryFormat(t *testing.T) {
	f := newFakeFortiGate(t, "readonly", leakCanary)
	creds := writeCredentials(t, "username: readonly\npassword: "+leakCanary+"\n", 0o600)
	dir := t.TempDir()

	jsonl := filepath.Join(dir, "out.jsonl")
	res := runCmd(t, standaloneEnv{}, collectArgs(f, "--credentials", creds, "--out", jsonl)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", res.code, res.stderr)
	}
	out := readFile(t, jsonl)
	kinds := outputschema.ValidateJSONL(t, []byte(out))
	if len(kinds) < 3 || kinds[0] != "run" || kinds[len(kinds)-1] != "summary" {
		t.Fatalf("record kinds = %v, want run first and summary last", kinds)
	}
	if n := countKind(kinds, agentoutput.KindDeviceInterrogation); n != 1 {
		t.Fatalf("device_interrogation records = %d, want 1 (kinds %v)", n, kinds)
	}
	if !strings.Contains(out, `"credentials: from the --credentials file"`) {
		t.Errorf("the run record does not say where the credentials came from:\n%s", out)
	}
	if !strings.Contains(out, `"assets":[`) || !strings.Contains(out, "TLS-AES-256-GCM-SHA384") {
		t.Errorf("the interrogation result is not in the output:\n%s", out)
	}
	if info, err := os.Stat(jsonl); err != nil || info.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("output file mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}
	if !strings.Contains(res.stderr, "fortigate device 192.0.2.10") {
		t.Errorf("the summary does not name the scope:\n%s", res.stderr)
	}

	csvPath := filepath.Join(dir, "out.csv")
	res = runCmd(t, standaloneEnv{}, collectArgs(f, "--credentials", creds, "--out", csvPath, "--format", "csv")...)
	if res.code != 0 {
		t.Fatalf("csv exit = %d; stderr:\n%s", res.code, res.stderr)
	}
	rows, err := csv.NewReader(strings.NewReader(readFile(t, csvPath))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("csv has no endpoint rows: %v", rows)
	}
	row := rows[1]
	if row[0] != "device_interrogation" || row[2] != "192.0.2.10" || row[3] != "10443" || row[7] != "TLS-AES-256-GCM-SHA384" || row[16] != "fortigate" {
		t.Errorf("endpoint row = %v; want the SSL VPN listener at 192.0.2.10:10443", row)
	}

	jsonPath := filepath.Join(dir, "out.json")
	res = runCmd(t, standaloneEnv{}, collectArgs(f, "--credentials", creds, "--out", jsonPath, "--format", "json")...)
	if res.code != 0 {
		t.Fatalf("json exit = %d; stderr:\n%s", res.code, res.stderr)
	}
	var doc struct {
		Run     json.RawMessage   `json:"run"`
		Records []json.RawMessage `json:"records"`
		Summary json.RawMessage   `json:"summary"`
	}
	if err := json.Unmarshal([]byte(readFile(t, jsonPath)), &doc); err != nil {
		t.Fatal(err)
	}
	schema := outputschema.Compile(t)
	for _, rec := range append([]json.RawMessage{doc.Run, doc.Summary}, doc.Records...) {
		if err := outputschema.Validate(schema, rec); err != nil {
			t.Fatalf("json record invalid: %v\n%s", err, rec)
		}
	}
	if len(doc.Records) != 1 {
		t.Errorf("json records = %d, want 1", len(doc.Records))
	}
}

// The password must appear in no output format and not on stderr, whether the
// login succeeds or fails, and including when the appliance echoes it back.
func TestStandaloneCollect_SecretsNeverLeak(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string // what the fake accepts
		wantCode int
	}{
		{"success", leakCanary, 0},
		{"failed login", "a-different-password", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeFortiGate(t, "readonly", tc.password)
			f.echoOnFailure = true
			creds := writeCredentials(t, `{"username":"readonly","password":"`+leakCanary+`","api_key":"`+leakCanary+`-key"}`, 0o600)
			for _, format := range []string{"jsonl", "json", "csv"} {
				path := filepath.Join(t.TempDir(), "out."+format)
				res := runCmd(t, standaloneEnv{}, collectArgs(f, "--credentials", creds, "--out", path, "--format", format)...)
				if res.code != tc.wantCode {
					t.Fatalf("%s: exit = %d, want %d; stderr:\n%s", format, res.code, tc.wantCode, res.stderr)
				}
				out := readFile(t, path)
				if strings.Contains(out, leakCanary) {
					t.Fatalf("%s output carries the password:\n%s", format, out)
				}
				if strings.Contains(res.stderr, leakCanary) {
					t.Fatalf("%s stderr carries the password:\n%s", format, res.stderr)
				}
				if tc.wantCode == 1 && format == "jsonl" {
					kinds := outputschema.ValidateJSONL(t, []byte(out))
					if countKind(kinds, agentoutput.KindError) != 1 {
						t.Fatalf("a failed login wrote no error record: %v\n%s", kinds, out)
					}
					// The reason still says what failed. (The Fortinet collector
					// does not quote the body; TestScrubSecrets_ReplacesLiteralValues
					// covers an error that does.)
					if !strings.Contains(out, "401") {
						t.Errorf("error reason lost its context:\n%s", out)
					}
				}
			}
		})
	}
}

// Mutation check for the scrub itself: without the literal-value pass, the
// echoed password survives redact.Text.
func TestScrubSecrets_ReplacesLiteralValues(t *testing.T) {
	creds := di.Credentials{Username: "readonly", Password: leakCanary, Custom: map[string]interface{}{"enable_secret": "en-" + leakCanary}}
	got := scrubSecrets("device said: bad password "+leakCanary+" and en-"+leakCanary+" for readonly", creds)
	if strings.Contains(got, leakCanary) {
		t.Fatalf("scrubSecrets left a secret: %q", got)
	}
	if !strings.Contains(got, "readonly") {
		t.Errorf("scrubSecrets removed the username: %q", got)
	}
}

func TestStandaloneCollect_CredentialsFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not describe access on Windows")
	}
	for _, tc := range []struct {
		mode     os.FileMode
		wantCode int
	}{
		{0o600, 0},
		{0o640, 1},
		{0o604, 1},
	} {
		t.Run(strconv.FormatUint(uint64(tc.mode), 8), func(t *testing.T) {
			f := newFakeFortiGate(t, "readonly", leakCanary)
			creds := writeCredentials(t, "username: readonly\npassword: "+leakCanary+"\n", tc.mode)
			out := filepath.Join(t.TempDir(), "out.jsonl")
			res := runCmd(t, standaloneEnv{}, collectArgs(f, "--credentials", creds, "--out", out)...)
			if res.code != tc.wantCode {
				t.Fatalf("exit = %d, want %d; stderr:\n%s", res.code, tc.wantCode, res.stderr)
			}
			if tc.wantCode == 1 {
				if !strings.Contains(res.stderr, "chmod 600") {
					t.Errorf("refusal does not give the fix:\n%s", res.stderr)
				}
				if n := f.requests.Load(); n != 0 {
					t.Errorf("the device was contacted %d time(s) with a refused credentials file", n)
				}
				if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("an output file was written for a refused run: %v", err)
				}
			}
		})
	}
}

func TestStandaloneCollect_EnvironmentCredentials(t *testing.T) {
	f := newFakeFortiGate(t, "env-user", leakCanary)
	env := standaloneEnv{getenv: func(k string) string {
		switch k {
		case envDeviceUsername:
			return "env-user"
		case envDevicePassword:
			return leakCanary
		}
		return ""
	}}
	res := runCmd(t, env, collectArgs(f)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", res.code, res.stderr)
	}
	kinds := outputschema.ValidateJSONL(t, []byte(res.stdout))
	if countKind(kinds, agentoutput.KindDeviceInterrogation) != 1 {
		t.Fatalf("kinds = %v", kinds)
	}
	if !strings.Contains(res.stdout, "from the environment (VISTA_DEVICE_USERNAME, VISTA_DEVICE_PASSWORD)") {
		t.Errorf("the run record does not say the environment was used:\n%s", res.stdout)
	}
	if strings.Contains(res.stdout+res.stderr, leakCanary) {
		t.Fatal("the environment password reached the output")
	}

	// A file wins over the environment.
	creds := writeCredentials(t, "username: env-user\npassword: "+leakCanary+"\n", 0o600)
	res = runCmd(t, env, collectArgs(f, "--credentials", creds)...)
	if res.code != 0 || !strings.Contains(res.stdout, "ignored because --credentials was given") {
		t.Errorf("exit = %d; the file did not win over the environment:\n%s", res.code, res.stdout)
	}
}

// Bad invocations exit 1 with a clear message and contact nothing.
func TestStandaloneCollect_UsageErrorsContactNothing(t *testing.T) {
	f := newFakeFortiGate(t, "readonly", leakCanary)
	good := writeCredentials(t, "username: readonly\npassword: x\n", 0o600)
	bad := writeCredentials(t, "username: [unclosed\npassword: "+leakCanary+"\n", 0o600)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown type", []string{"collect", "--type", "nope", "--target", "192.0.2.10", "--management-url", f.srv.URL, "--credentials", good}, `unknown device type "nope"`},
		{"missing target", []string{"collect", "--type", "fortigate", "--management-url", f.srv.URL, "--credentials", good}, "--target is required"},
		{"missing type", []string{"collect", "--target", "192.0.2.10", "--credentials", good}, "--type is required"},
		{"unparsable credentials", collectArgs(f, "--credentials", bad), "is not valid YAML or JSON"},
		{"url with a password", []string{"collect", "--type", "fortigate", "--target", "192.0.2.10", "--management-url", "https://u:p@192.0.2.10"}, "may not carry credentials"},
		{"bad host key", collectArgs(f, "--ssh-host-key", "MD5:aa"), "SHA256 fingerprint"},
		{"bad format", collectArgs(f, "--format", "xml"), "unknown output format"},
		{"unknown flag", []string{"collect", "--password", "x"}, "flag provided but not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runCmd(t, standaloneEnv{}, tc.args...)
			if res.code != 1 {
				t.Fatalf("exit = %d, want 1", res.code)
			}
			if !strings.Contains(res.stderr, tc.want) {
				t.Errorf("stderr does not say %q:\n%s", tc.want, res.stderr)
			}
			if strings.Contains(res.stderr, leakCanary) {
				t.Errorf("the message quotes the credentials file:\n%s", res.stderr)
			}
			if res.stdout != "" {
				t.Errorf("a refused run wrote output:\n%s", res.stdout)
			}
		})
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("the device was contacted %d time(s) by refused runs", n)
	}
}

func TestStandaloneCollect_HelpListsTypesAndFlags(t *testing.T) {
	res := runCmd(t, standaloneEnv{}, "collect", "--help")
	if res.code != 0 {
		t.Fatalf("exit = %d", res.code)
	}
	for _, want := range []string{"contacts no Vista Platform", "fortinet", "cisco", "-credentials", "-ssh-host-key",
		"-insecure-skip-verify", "-timeout", "-out", "-format", "-quiet", "-site", "-management-url", "-port"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("help does not mention %q:\n%s", want, res.stdout)
		}
	}
	res = runCmd(t, standaloneEnv{}, "host-inventory", "-h")
	if res.code != 0 || !strings.Contains(res.stdout, "contacts no") || !strings.Contains(res.stdout, "-format") {
		t.Errorf("host-inventory help: exit %d\n%s", res.code, res.stdout)
	}
}

func TestStandaloneCollect_WarningsArePartial(t *testing.T) {
	f := newFakeFortiGate(t, "readonly", leakCanary)
	f.refuseIfaces = true
	creds := writeCredentials(t, "username: readonly\npassword: "+leakCanary+"\n", 0o600)
	res := runCmd(t, standaloneEnv{}, collectArgs(f, "--credentials", creds, "--insecure-skip-verify")...)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 for a result with warnings; stderr:\n%s", res.code, res.stderr)
	}
	kinds := outputschema.ValidateJSONL(t, []byte(res.stdout))
	if countKind(kinds, agentoutput.KindDeviceInterrogation) != 1 {
		t.Fatalf("the partial result was not written: %v", kinds)
	}
	if !strings.Contains(res.stderr, "/api/v2/cmdb/system/interface") || !strings.Contains(res.stderr, "partial") {
		t.Errorf("the summary does not list the warning:\n%s", res.stderr)
	}
	if !strings.Contains(res.stdout, `"insecure-skip-verify":"true"`) {
		t.Errorf("--insecure-skip-verify is not in the run record's flags:\n%s", res.stdout)
	}
}

func TestEndpointsOf_MapsLeafCertificate(t *testing.T) {
	v, cs, kx := "TLSv1.3", "TLS_AES_128_GCM_SHA256", "X25519"
	res := &di.InterrogateResult{Assets: []di.CryptoAsset{{
		Hostname: "fw.example.test", IPAddress: "198.51.100.7", Port: 443, Protocol: "TLS",
		ProtocolVersion: &v, CipherSuite: &cs, KeyExchangeAlg: &kx,
		Certificates: []di.CertificateInfo{{SubjectDN: "CN=fw.example.test", IssuerDN: "CN=Example CA",
			KeyAlgorithm: "ECDSA", KeySize: 256, SignatureAlg: "ECDSA-SHA256", FingerprintSHA256: "abcd"}},
	}}}
	got := endpointsOf(res, "generic_http")
	if len(got) != 1 {
		t.Fatalf("endpoints = %d", len(got))
	}
	e := got[0]
	if e.Host != "fw.example.test" || e.Address != "198.51.100.7" || e.Port != 443 || e.ProtocolVersion != v ||
		e.CipherSuite != cs || e.KeyExchange != kx || e.CertificateSubject != "CN=fw.example.test" ||
		e.CertificateIssuer != "CN=Example CA" || e.CertificateKeySize != 256 || e.CertificateFingerprintSHA256 != "abcd" ||
		e.CertificateSignatureAlgorithm != "ECDSA-SHA256" || e.Source != "generic_http" {
		t.Errorf("endpoint = %+v", e)
	}
}

// fakeSSH is an SSH server that records whether any authentication method was
// offered to it, and refuses every login.
type fakeSSH struct {
	addr        string
	fingerprint string
	authTried   atomic.Bool
}

func newFakeSSH(t *testing.T) *fakeSSH {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSSH{fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			f.authTried.Store(true)
			return nil, errors.New("denied")
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			f.authTried.Store(true)
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	f.addr = ln.Addr().String()
	devicetest.AllowListener(t, f.addr)
	return f
}

// A pinned key that differs aborts during the key exchange, before any
// credential is offered. The matching-pin case proves the fake does see an
// authentication attempt, so the first assertion can fail.
func TestStandaloneCollect_SSHHostKeyPin(t *testing.T) {
	srv := newFakeSSH(t)
	_, port, _ := net.SplitHostPort(srv.addr)
	creds := writeCredentials(t, "username: admin\npassword: "+leakCanary+"\n", 0o600)
	args := func(pin string) []string {
		return []string{"collect", "--type", "cisco", "--target", "127.0.0.1", "--port", port,
			"--credentials", creds, "--ssh-host-key", pin, "--timeout", "20s"}
	}

	res := runCmd(t, standaloneEnv{}, args("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 on a host key mismatch; stderr:\n%s", res.code, res.stderr)
	}
	if srv.authTried.Load() {
		t.Fatal("a credential was offered to a server whose host key did not match the pin")
	}
	kinds := outputschema.ValidateJSONL(t, []byte(res.stdout))
	if countKind(kinds, agentoutput.KindError) != 1 || !strings.Contains(res.stdout, srv.fingerprint) {
		t.Errorf("the error record does not report the key that was seen (%s):\n%s", srv.fingerprint, res.stdout)
	}
	if strings.Contains(res.stdout+res.stderr, leakCanary) {
		t.Fatal("the password reached the output")
	}

	res = runCmd(t, standaloneEnv{}, args(srv.fingerprint)...)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (the fake refuses every login)", res.code)
	}
	if !srv.authTried.Load() {
		t.Fatal("with the matching pin no authentication was attempted; the fake cannot tell the cases apart")
	}
}

func TestSSHHostKeysSeen(t *testing.T) {
	res := &di.InterrogateResult{Assets: []di.CryptoAsset{
		{SSHInfo: &di.SSHInfo{HostKeyFingerprint: "SHA256:one"}},
		{SSHInfo: &di.SSHInfo{HostKeyFingerprint: "SHA256:one"}},
		{Protocol: "TLS"},
	}}
	if got := sshHostKeysSeen(res); len(got) != 1 || got[0] != "SHA256:one" {
		t.Errorf("sshHostKeysSeen = %v", got)
	}
}

func fakeHostCollector(failed bool) func(context.Context) (*hostinventory.Report, *di.InterrogateResult, error) {
	return func(context.Context) (*hostinventory.Report, *di.InterrogateResult, error) {
		report := &hostinventory.Report{Sections: map[string]string{
			hostinventory.SectionHost: hostinventory.SectionOK,
		}}
		if failed {
			report.Sections[hostinventory.SectionPackages] = hostinventory.SectionFailed
		}
		return report, &di.InterrogateResult{Assets: []di.CryptoAsset{}}, nil
	}
}

func TestStandaloneHostInventory(t *testing.T) {
	res := runCmd(t, standaloneEnv{collectHost: fakeHostCollector(false)}, "host-inventory")
	if res.code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", res.code, res.stderr)
	}
	kinds := outputschema.ValidateJSONL(t, []byte(res.stdout))
	if countKind(kinds, agentoutput.KindHostInventory) != 1 {
		t.Fatalf("kinds = %v", kinds)
	}
	if !strings.Contains(res.stdout, `"report":`) || !strings.Contains(res.stdout, `"observations":`) {
		t.Errorf("the record is not {report, observations}:\n%s", res.stdout)
	}

	res = runCmd(t, standaloneEnv{collectHost: fakeHostCollector(true)}, "host-inventory", "--format", "json")
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 when a section failed", res.code)
	}
	if !strings.Contains(res.stderr, "packages") {
		t.Errorf("the summary does not name the failed section:\n%s", res.stderr)
	}

	res = runCmd(t, standaloneEnv{collectHost: func(context.Context) (*hostinventory.Report, *di.InterrogateResult, error) {
		return nil, nil, errors.New("no package database")
	}}, "host-inventory")
	if res.code != 1 || countKind(outputschema.ValidateJSONL(t, []byte(res.stdout)), agentoutput.KindError) != 1 {
		t.Errorf("a failed collection: exit %d\n%s", res.code, res.stdout)
	}
}

// Anything that is not a standalone subcommand goes to the managed agent.
func TestRunStandalone_LeavesManagedInvocationsAlone(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--host-inventory-once"}, {"-version"}, {"--config", "x.yaml"}, {"register"}} {
		if _, ok := runStandalone(args, standaloneEnv{}); ok {
			t.Errorf("runStandalone(%q) claimed a managed invocation", args)
		}
	}
}

func kubeEnv(t *testing.T, getenv func(string) string) (standaloneEnv, *kubetest.Cluster) {
	t.Helper()
	cl := kubetest.New(t)
	cl.Load(filepath.Join("..", "..", "shared", "kubeinventory", "testdata", "full"))
	return standaloneEnv{getenv: getenv, kubeClient: func() (*kubeinventory.Client, error) {
		host, port := cl.HostPort()
		return kubeinventory.NewClient(host, port, cl.Dir)
	}}, cl
}

func TestStandaloneKubernetesInventory(t *testing.T) {
	env, cl := kubeEnv(t, nil)
	res := runCmd(t, env, "kubernetes-inventory", "--no-kubelet-probe", "--label-key", "team")
	if res.code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", res.code, res.stderr)
	}
	kinds := outputschema.ValidateJSONL(t, []byte(res.stdout))
	if countKind(kinds, agentoutput.KindKubernetesInventory) != 1 {
		t.Fatalf("kinds = %v", kinds)
	}
	for _, want := range []string{`"distribution":"kubeadm"`, `"workload":{"kind":"Deployment","name":"web"}`, `"team":"payments"`, `"tls_secrets":"not_enabled"`} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("the record lacks %s", want)
		}
	}
	if strings.Contains(res.stdout, "secret-value") || strings.Contains(res.stdout, "PRIVATE KEY") {
		t.Error("something the collector must leave in the cluster is in the output")
	}
	for _, r := range cl.Requests() {
		if strings.Contains(r.Path, "secrets") {
			t.Errorf("the Secrets API was called without the flag: %s", r.Path)
		}
	}

	// The flag, or the variable the manifest sets, turns on TLS Secrets.
	for _, tc := range []struct {
		env  func(string) string
		args []string
	}{
		{nil, []string{"kubernetes-inventory", "--no-kubelet-probe", "--read-tls-secrets", "--format", "json"}},
		{func(k string) string {
			if k == devices.EnvReadTLSSecrets {
				return "true"
			}
			return ""
		}, []string{"kubernetes-inventory", "--no-kubelet-probe", "--format", "json"}},
	} {
		env, _ := kubeEnv(t, tc.env)
		res := runCmd(t, env, tc.args...)
		if res.code != 0 || !strings.Contains(res.stdout, `"tls_secrets": "enabled"`) || !strings.Contains(res.stdout, `"web-tls"`) || strings.Contains(res.stdout, "PRIVATE KEY") {
			t.Errorf("%v: exit %d\n%s", tc.args, res.code, res.stderr)
		}
	}

	// A class the role does not grant: the run is partial and says which.
	env, cl = kubeEnv(t, nil)
	cl.SetStatus("/apis/apps/v1/deployments", 403)
	res = runCmd(t, env, "kubernetes-inventory", "--no-kubelet-probe")
	if res.code != 2 || !strings.Contains(res.stderr, "workloads (not_permitted)") {
		t.Errorf("exit = %d; stderr:\n%s", res.code, res.stderr)
	}

	// Without the cluster's id nothing but the error is written.
	env, cl = kubeEnv(t, nil)
	cl.SetStatus("/api/v1/namespaces", 403)
	res = runCmd(t, env, "kubernetes-inventory")
	kinds = outputschema.ValidateJSONL(t, []byte(res.stdout))
	if res.code != 1 || countKind(kinds, agentoutput.KindError) != 1 || countKind(kinds, agentoutput.KindKubernetesInventory) != 0 {
		t.Errorf("exit = %d, kinds = %v", res.code, kinds)
	}
}

// Outside a pod there is no cluster to describe, and no flag that names one.
func TestStandaloneKubernetesInventory_OnlyInACluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	out := filepath.Join(t.TempDir(), "out.jsonl")
	res := runCmd(t, standaloneEnv{}, "kubernetes-inventory", "--out", out)
	if res.code != 1 || !strings.Contains(res.stderr, "not running in a Kubernetes cluster") {
		t.Errorf("exit = %d; stderr:\n%s", res.code, res.stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an output file was written")
	}
	for _, flag := range []string{"--kubeconfig", "--server", "--token", "--context"} {
		if res := runCmd(t, standaloneEnv{}, "kubernetes-inventory", flag, "x"); res.code != 1 || !strings.Contains(res.stderr, "flag provided but not defined") {
			t.Errorf("%s: exit %d\n%s", flag, res.code, res.stderr)
		}
	}
	res = runCmd(t, standaloneEnv{}, "kubernetes-inventory", "--help")
	if res.code != 0 || !strings.Contains(res.stdout, "takes no kubeconfig") || strings.Contains(res.stdout, "-kubeconfig") {
		t.Errorf("help: exit %d\n%s", res.code, res.stdout)
	}
}
