package hostcrypto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A Windows host: the fake target with Windows paths.
// ---------------------------------------------------------------------------

// locWinFake is the fake target holding Windows paths. The fake's tree is
// slash-separated, so "C:\a\b" is stored as "/C:/a/b" and every path is
// translated on the way in and out; the collector sees only Windows paths.
type locWinFake struct{ *tgtFakeTarget }

func locW2S(p string) string { return "/" + strings.ReplaceAll(p, `\`, "/") }
func locS2W(p string) string { return strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", `\`) }

func newLocWinFake(local bool) *locWinFake { return &locWinFake{newTgtFakeTarget(local)} }

func (w *locWinFake) wfile(p string, b []byte) *locWinFake {
	w.file(locW2S(p), b)
	return w
}

func (w *locWinFake) winfo(fi FileInfo) FileInfo {
	fi.Path = locS2W(fi.Path)
	if strings.HasPrefix(fi.LinkTarget, "/") {
		fi.LinkTarget = locS2W(fi.LinkTarget)
	}
	return fi
}

func (w *locWinFake) Stat(ctx context.Context, p string) (FileInfo, error) {
	fi, err := w.tgtFakeTarget.Stat(ctx, locW2S(p))
	return w.winfo(fi), err
}

func (w *locWinFake) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	var ex []string
	for _, e := range opts.Exclude {
		ex = append(ex, locW2S(e))
	}
	opts.Exclude = ex
	files, err := w.tgtFakeTarget.List(ctx, locW2S(root), opts)
	for i := range files {
		files[i] = w.winfo(files[i])
	}
	return files, err
}

func (w *locWinFake) Identify(ctx context.Context, p string) (Identity, error) {
	return w.tgtFakeTarget.Identify(ctx, locW2S(p))
}

func (w *locWinFake) ReadFile(ctx context.Context, p string) ([]byte, error) {
	return w.tgtFakeTarget.ReadFile(ctx, locW2S(p))
}

func (w *locWinFake) ReadText(ctx context.Context, p string, keep []string) ([]byte, int, error) {
	return w.tgtFakeTarget.ReadText(ctx, locW2S(p), keep)
}

var _ Target = (*locWinFake)(nil)

const locWinHTTPD = "ServerRoot \"C:/Apache24\"\nListen 443\nInclude conf/extra/httpd-ssl.conf\n"
const locWinHTTPDSSL = "<VirtualHost _default_:443>\nServerName win.example\nSSLEngine on\nSSLProtocol -all +TLSv1.2\nSSLCertificateFile \"C:/Apache24/conf/ssl/server.crt\"\nSSLCertificateKeyFile \"C:/Apache24/conf/ssl/server.key\"\n</VirtualHost>\n"

func locWindowsTree(t *testing.T, local bool) *locWinFake {
	m := locTestMaterial(t)
	w := newLocWinFake(local)
	w.wfile(`C:\ProgramData\ssh\sshd_config`, []byte("HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key\nCiphers aes256-gcm@openssh.com\n")).
		wfile(`C:\ProgramData\ssh\ssh_host_ed25519_key`, m.edPEM).
		wfile(`C:\ProgramData\ssh\ssh_host_ed25519_key.pub`, m.edPub).
		wfile(`C:\ProgramData\ssh\administrators_authorized_keys`, m.edPub).
		wfile(`C:\Program Files\Java\jdk-21\lib\security\cacerts`, m.jks).
		wfile(`C:\Program Files\Java\jdk-21\conf\security\java.security`, []byte("jdk.tls.disabledAlgorithms=SSLv3, TLSv1\n")).
		wfile(`C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt`, m.caPEM).
		wfile(`C:\Apache24\conf\httpd.conf`, []byte(locWinHTTPD)).
		wfile(`C:\Apache24\conf\extra\httpd-ssl.conf`, []byte(locWinHTTPDSSL)).
		wfile(`C:\Apache24\conf\ssl\server.crt`, m.leafPEM).
		wfile(`C:\Apache24\conf\ssl\server.key`, m.ecPEM).
		wfile(`C:\Users\bob\.ssh\id_ed25519`, m.edPEM)
	return w
}

func TestLocWindowsLocalAndRemote(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(fmt.Sprintf("local=%v", local), func(t *testing.T) {
			w := locWindowsTree(t, local)
			rep := locCollect(t, w, Options{Platform: "windows", HomeDirectories: true})

			hk := locKeyAt(rep, `C:\ProgramData\ssh\ssh_host_ed25519_key`)
			if hk == nil || hk.Role != "ssh_host_key" || !locHasUsage(hk.Location, `C:\ProgramData\ssh\sshd_config`, "HostKey") ||
				hk.Location.FoundBy != FoundByConfig {
				t.Fatalf("Windows host key: %+v", hk)
			}
			if hk.Location.Mode != "" {
				t.Errorf("a Windows location carries Unix mode bits: %q", hk.Location.Mode)
			}
			if len(rep.SSH.AuthorizedKeys) != 1 || rep.SSH.AuthorizedKeys[0].Account != "Administrators" {
				t.Errorf("administrators_authorized_keys: %+v", rep.SSH.AuthorizedKeys)
			}
			if ks := locStoreAt(rep, `C:\Program Files\Java\jdk-21\lib\security\cacerts`); ks == nil || ks.Type != KeystoreJKS {
				t.Errorf("JDK cacerts: %+v", ks)
			}
			if locConfigOf(rep, `C:\Program Files\Java\jdk-21\conf\security\java.security`, "java") == nil {
				t.Error("no java.security")
			}
			if ca := locCertAt(rep, `C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt`); ca == nil || !ca.TrustAnchor {
				t.Errorf("Git bundle: %+v", ca)
			}
			// Apache: Include resolved against ServerRoot (conf\..), forward
			// slashes in the configuration turned into the host's.
			if !w.called("readtext", locW2S(`C:\Apache24\conf\extra\httpd-ssl.conf`)) {
				t.Errorf("Apache include not read: %v", w.recorded())
			}
			crt := locCertAt(rep, `C:\Apache24\conf\ssl\server.crt`)
			if crt == nil {
				t.Fatal("no Apache certificate")
			}
			if u := locUsage(crt.Location, `C:\Apache24\conf\extra\httpd-ssl.conf`, "SSLCertificateFile"); u == nil ||
				u.RootConfigPath != `C:\Apache24\conf\httpd.conf` || u.Product != "apache" {
				t.Fatalf("Apache certificate usage: %+v", crt.Location.UsedBy)
			}
			key := locKeyAt(rep, `C:\Apache24\conf\ssl\server.key`)
			if key == nil || key.Role != "tls" || !locHasUsage(key.Location, `C:\Apache24\conf\extra\httpd-ssl.conf`, "SSLCertificateKeyFile") {
				t.Fatalf("Apache key: %+v", key)
			}
			// No command answered for the roots: C:, with a note.
			if !locErrorsContain(rep, "assuming C:") {
				t.Errorf("the drive fallback was not noted: %+v", rep.Errors)
			}
			if uk := locKeyAt(rep, `C:\Users\bob\.ssh\id_ed25519`); uk == nil || uk.Role != "ssh_user_key" {
				t.Errorf("user key: %+v", uk)
			}
			if !local {
				priv := []string{
					`C:\ProgramData\ssh\ssh_host_ed25519_key`, `C:\Apache24\conf\ssl\server.key`,
					`C:\Users\bob\.ssh\id_ed25519`, `C:\Program Files\Java\jdk-21\lib\security\cacerts`,
				}
				for i := range priv {
					priv[i] = locW2S(priv[i])
				}
				if err := locPrivateReads(w.recorded(), priv); err != nil {
					t.Fatal(err)
				}
				if key.Unknown == "" || key.PublicKeySHA256 != "" {
					t.Errorf("remote Windows key: %+v", key)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

// TestLocDarwinHomebrewJDKThroughLink: Homebrew's opt/openjdk is a link into
// the Cellar, which a listing does not descend; the table's wildcard is
// followed through it, and the cacerts found once.
func TestLocDarwinHomebrewJDKThroughLink(t *testing.T) {
	m := locTestMaterial(t)
	for _, local := range []bool{true, false} {
		ft := newTgtFakeTarget(local).
			file("/etc/ssl/cert.pem", m.caPEM).
			file("/etc/ssh/sshd_config", []byte(locSSHDConf)).
			file("/etc/ssh/ssh_host_ed25519_key", m.edPEM).
			file("/opt/homebrew/etc/nginx/nginx.conf", []byte("http {\n server {\n listen 443 ssl;\n ssl_certificate /opt/homebrew/etc/nginx/ssl/a.crt;\n }\n}\n")).
			file("/opt/homebrew/etc/nginx/ssl/a.crt", m.leafPEM).
			file("/opt/homebrew/Cellar/openjdk/21.0.1/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts", m.jks).
			symlink("/opt/homebrew/opt/openjdk", "../Cellar/openjdk/21.0.1").
			file("/Library/Keychains/System.keychain", []byte("kych\x00\x01\x00\x00"))
		rep := locCollect(t, ft, Options{Platform: "darwin"})
		var jdk []Keystore
		for _, ks := range rep.Keystores {
			if strings.HasSuffix(ks.Location.Path, "/lib/security/cacerts") {
				jdk = append(jdk, ks)
			}
		}
		if len(jdk) != 1 || jdk[0].Type != KeystoreJKS {
			t.Fatalf("local=%v: Homebrew JDK cacerts: %+v", local, jdk)
		}
		if ks := locStoreAt(rep, "/Library/Keychains/System.keychain"); ks == nil || ks.Type != KeystoreKeychain {
			t.Errorf("local=%v: system keychain file: %+v", local, ks)
		}
		if c := locCertAt(rep, "/opt/homebrew/etc/nginx/ssl/a.crt"); c == nil || c.Location.FoundBy != FoundByConfig {
			t.Errorf("local=%v: Homebrew nginx certificate: %+v", local, c)
		}
		if ca := locCertAt(rep, "/etc/ssl/cert.pem"); ca == nil || !ca.TrustAnchor {
			t.Errorf("local=%v: system bundle: %+v", local, ca)
		}
	}
}

// ---------------------------------------------------------------------------
// Pass 2 specifics
// ---------------------------------------------------------------------------

// TestLocReferencesNotGuessed: a path with a variable, a % token or ~ is not
// followed, and the report says so; a referenced directory is listed.
func TestLocReferencesNotGuessed(t *testing.T) {
	m := locTestMaterial(t)
	ft := newTgtFakeTarget(true).
		file("/etc/nginx/nginx.conf", []byte("http {\n server {\n listen 443 ssl;\n ssl_certificate /etc/nginx/$host.crt;\n ssl_certificate_key /etc/ssl/private/k.pem;\n }\n}\n")).
		file("/etc/ssh/ssh_config", []byte("IdentityFile ~/.ssh/id_rsa\n")).
		file("/etc/haproxy/haproxy.cfg", []byte("frontend f\n bind :443 ssl crt /etc/haproxy/live\n")).
		file("/etc/haproxy/live/a.pem", append(append([]byte(nil), m.leafPEM...), m.ecPEM...))
	rep := locCollect(t, ft, Options{Platform: "linux"})
	for _, c := range []struct{ d, p, want string }{
		{"ssl_certificate", "/etc/nginx/$host.crt", RefNotFollowed},
		{"IdentityFile", "~/.ssh/id_rsa", RefNotFollowed},
		{"ssl_certificate_key", "/etc/ssl/private/k.pem", RefMissing},
		{"bind crt", "/etc/haproxy/live", RefFound},
	} {
		if got := locRefStatus(rep, c.d, c.p); got != c.want {
			t.Errorf("%s %s: status %q, want %q", c.d, c.p, got, c.want)
		}
	}
	if len(rep.Errors) != 0 {
		t.Errorf("missing and unfollowed references are not errors: %+v", rep.Errors)
	}
	k := locKeyAt(rep, "/etc/haproxy/live/a.pem")
	if k == nil || k.Role != "tls" || !locHasUsage(k.Location, "/etc/haproxy/haproxy.cfg", "bind crt") {
		t.Errorf("a key in a directory HAProxy names: %+v", k)
	}
}

// TestLocIncludeOnce: a file read as an include is part of its root's
// record, not a second root, even when a table also lists it; and an include
// cycle ends.
func TestLocIncludeOnce(t *testing.T) {
	ft := newTgtFakeTarget(false).
		file("/etc/ssl/openssl.cnf", []byte("openssl_conf = init\n.include /usr/lib/ssl/openssl.cnf\n[init]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nMinProtocol = TLSv1.2\n")).
		file("/usr/lib/ssl/openssl.cnf", []byte(".include /etc/ssl/openssl.cnf\nCipherString = DEFAULT@SECLEVEL=2\n"))
	rep := locCollect(t, ft, Options{Platform: "linux"})
	n := 0
	for _, c := range rep.Configs {
		if c.Product == "openssl" {
			n++
			if c.Location.Path != "/etc/ssl/openssl.cnf" {
				t.Errorf("the include was recorded as a root: %s", c.Location.Path)
			}
		}
	}
	if n == 0 {
		t.Fatal("no openssl record")
	}
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

// locReadTextCall finds a direct call of a Target's ReadText in Go source.
var locReadTextCall = regexp.MustCompile(`\.ReadText\(`)

// TestLocConfigOnlyThroughReadConfig: passes 1 and 2 and the tables read
// configuration through collection.readConfig only. Both ways: the files
// pass; a line calling ReadText fails.
func TestLocConfigOnlyThroughReadConfig(t *testing.T) {
	for _, f := range []string{"pass_known.go", "pass_config.go", "oslinux.go", "osdarwin.go", "oswindows.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if locReadTextCall.Match(b) {
			t.Errorf("%s calls ReadText directly; use c.readConfig", f)
		}
	}
	if !locReadTextCall.MatchString("text, _, err := c.target.ReadText(ctx, p, keep)") {
		t.Fatal("the guard cannot see a direct ReadText call")
	}
	// And at run time: every ReadText of a collection asked for exactly a
	// product's keep words.
	ft := locLinuxTree(t, false)
	locCollect(t, ft, Options{Platform: "linux"})
	if len(ft.keeps) == 0 {
		t.Fatal("no configuration was read; the check proves nothing")
	}
	known := map[string]bool{}
	for k := range configKeepWords {
		known[strings.Join(ConfigKeepWords(k), ",")] = true
	}
	for _, keep := range ft.keeps {
		if !known[strings.Join(keep, ",")] {
			t.Errorf("ReadText with keep words that are no product's: %v", keep)
		}
	}
}

// TestLocTablesWellFormed: every row is absolute in its platform's style,
// every configuration row names a product with a parser, and no row is a
// home directory in the system table.
func TestLocTablesWellFormed(t *testing.T) {
	for _, pl := range []string{"linux", "darwin", "windows"} {
		sys, home := locTables(pl, "", locWinRoots{})
		w := locStyle(pl == "windows")
		if len(sys) == 0 || len(home) == 0 {
			t.Fatalf("%s: empty table", pl)
		}
		for _, e := range append(append([]locEntry(nil), sys...), home...) {
			if !w.isAbs(e.Path) || (pl != "windows" && strings.Contains(e.Path, `\`)) || (pl == "windows" && strings.Contains(e.Path, "/")) {
				t.Errorf("%s: %q is not an absolute path in the host's style", pl, e.Path)
			}
			if e.Kind == locConfig && e.Product != locBackendProduct && ConfigParserFor(e.Product) == nil {
				t.Errorf("%s: %q names product %q, which has no parser", pl, e.Path, e.Product)
			}
		}
		for _, e := range sys {
			for _, h := range []string{"/home/", "/Users/", `\Users\`, "/root", "/var/root"} {
				if strings.Contains(e.Path, h) {
					t.Errorf("%s: system row %q is in a home directory", pl, e.Path)
				}
			}
		}
	}
	// Every product with a parser has a row somewhere (java-options and
	// gnutls included), so ConfigProducts is covered.
	seen := map[string]bool{}
	for _, pl := range []string{"linux", "darwin", "windows"} {
		sys, _ := locTables(pl, "", locWinRoots{})
		for _, e := range sys {
			seen[e.Product] = true
		}
	}
	for _, p := range ConfigProducts() {
		if !seen[p] {
			t.Errorf("product %q has a parser but no table row", p)
		}
	}
}

func TestLocStyle(t *testing.T) {
	w, u := locStyle(true), locStyle(false)
	for _, c := range []struct {
		got, want string
	}{
		{w.dir(`C:\a\b\c.conf`), `C:\a\b`},
		{w.up(`C:\Apache24\conf`, 1), `C:\Apache24`},
		{w.resolve(`C:\Apache24`, "conf/extra/x.conf"), `C:\Apache24\conf\extra\x.conf`},
		{w.resolve(`C:\x`, "D:/y/z"), `D:\y\z`},
		{u.resolve("/etc/nginx", "../ssl/a.pem"), "/etc/ssl/a.pem"},
		{u.dir("/etc"), "/"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if !w.matchComp("JDK-*", "jdk-21") || u.matchComp("JDK-*", "jdk-21") {
		t.Error("Windows matches without case, Unix with it")
	}
	if !w.under(`c:\programdata\ssh\x`, `C:\ProgramData\ssh`) || u.under("/etc/sshx", "/etc/ssh") {
		t.Error("under")
	}
}

// ---------------------------------------------------------------------------
// The real filesystem, local target, Linux
// ---------------------------------------------------------------------------

// TestLocRealFilesystemLinux builds a small host under a temporary root (nginx
// with an include, sshd, a JDK whose cacerts is a link to the system's, an
// Elasticsearch jvm.options) and runs passes 1 and 2 with the LOCAL target,
// end to end: real Stat, List, Identify, ReadText, links resolved by the
// filesystem.
func TestLocRealFilesystemLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fake root is laid out as Linux")
	}
	m := locTestMaterial(t)
	root := t.TempDir()
	write := func(p string, b []byte, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	link := func(p, target string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/ssl/certs/ca-certificates.crt", m.caPEM, 0o644)
	write("/etc/ssl/private/server.key", m.ecPEM, 0o600)
	write("/etc/nginx/nginx.conf", []byte(locNginxConf), 0o644)
	write("/etc/nginx/sites/site.conf", []byte(locNginxSite), 0o644)
	link("/etc/nginx/conf.d/site.conf", "../sites/site.conf")
	write("/etc/nginx/ssl/site.crt", m.leafPEM, 0o644)
	write("/etc/ssh/sshd_config", []byte(locSSHDConf), 0o644)
	write("/etc/ssh/ssh_host_ed25519_key", m.edPEM, 0o600)
	write("/etc/ssh/ssh_host_ed25519_key.pub", m.edPub, 0o644)
	write("/etc/ssl/certs/java/cacerts", m.jks, 0o644)
	link("/usr/lib/jvm/java-17/lib/security/cacerts", "../../../../../etc/ssl/certs/java/cacerts")
	write("/usr/lib/jvm/java-17/conf/security/java.security", []byte("jdk.tls.disabledAlgorithms=SSLv3, TLSv1\n"), 0o644)
	write("/etc/elasticsearch/jvm.options", []byte("-Djavax.net.ssl.trustStore=/etc/es/ts.jks\n"), 0o644)
	write("/etc/es/ts.jks", m.jks, 0o640)

	opts := Options{Platform: "linux", Now: tgtNow, MaxDuration: time.Minute}
	lt := NewLocalTarget()
	c := tgtCollection(lt, opts)
	c.opts.Platform = "linux"
	c.registry.resolve = localRealPath
	c.loc = newLocState(root, "linux")
	ctx := context.Background()
	passKnownLocations(ctx, c)
	passFollowConfiguration(ctx, c)
	c.registry.finish(c.report)
	rep := c.report

	at := func(p string) string { return filepath.Join(root, p) }
	leaf := locCertAt(rep, at("/etc/nginx/ssl/site.crt"))
	if leaf == nil || leaf.Location.FoundBy != FoundByConfig || locUsage(leaf.Location, at("/etc/nginx/conf.d/site.conf"), "ssl_certificate") == nil ||
		locUsage(leaf.Location, at("/etc/nginx/conf.d/site.conf"), "ssl_certificate").RootConfigPath != at("/etc/nginx/nginx.conf") {
		t.Fatalf("nginx certificate: %+v\nerrors: %+v", leaf, rep.Errors)
	}
	key := locKeyAt(rep, at("/etc/ssl/private/server.key"))
	if key == nil || key.Location.Mode != "0600" || key.Role != "tls" || key.PublicKeySHA256 != leaf.PublicKeySHA256 ||
		!locHasUsage(key.Location, at("/etc/nginx/conf.d/site.conf"), "ssl_certificate_key") {
		t.Fatalf("nginx key: %+v", key)
	}
	hk := locKeyAt(rep, at("/etc/ssh/ssh_host_ed25519_key"))
	if hk == nil || !locHasUsage(hk.Location, at("/etc/ssh/sshd_config"), "HostKey") || len(rep.SSH.HostPublicKeys) != 1 {
		t.Fatalf("host key: %+v", hk)
	}
	// The JDK's cacerts and the system's are one file: one keystore.
	n := 0
	for _, ks := range rep.Keystores {
		if strings.HasSuffix(ks.Location.Path, "cacerts") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("cacerts reached through a link became %d keystores", n)
	}
	ts := locStoreAt(rep, at("/etc/es/ts.jks"))
	if ts == nil || !locHasUsage(ts.Location, at("/etc/elasticsearch/jvm.options"), "-Djavax.net.ssl.trustStore") ||
		ts.Location.GroupReadable == nil || !*ts.Location.GroupReadable {
		t.Errorf("trust store: %+v", ts)
	}
	if locConfigOf(rep, at("/usr/lib/jvm/java-17/conf/security/java.security"), "java") == nil {
		t.Error("no java.security record")
	}
	for _, s := range locSections {
		if rep.Sections[s] != SectionOK {
			t.Errorf("section %s = %q (%+v)", s, rep.Sections[s], rep.Errors)
		}
	}
	keyAssertNoLeak(t, "real filesystem report", rep, m.secrets...)
}

// TestLocWindowsRootsFromHost: the drive and the program directories come
// from the host; a bad answer falls back field by field, no answer to C:.
func TestLocWindowsRootsFromHost(t *testing.T) {
	m := locTestMaterial(t)
	w := newLocWinFake(false)
	w.script(locWinRootsArgv, tgtResult{stdout: `D:|D:\Data|D:\Apps|D:\Apps (x86)` + "\r\n"})
	w.wfile(`D:\Data\ssh\sshd_config`, []byte("HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key\n")).
		wfile(`D:\Data\ssh\ssh_host_ed25519_key`, m.edPEM).
		wfile(`D:\Apps\Java\jdk-21\lib\security\cacerts`, m.jks).
		wfile(`C:\ProgramData\ssh\sshd_config`, []byte("HostKey C:/elsewhere\n"))
	rep := locCollect(t, w, Options{Platform: "windows"})
	hk := locKeyAt(rep, `D:\Data\ssh\ssh_host_ed25519_key`)
	if hk == nil || !locHasUsage(hk.Location, `D:\Data\ssh\sshd_config`, "HostKey") {
		t.Fatalf("host key under the host's ProgramData: %+v", hk)
	}
	if locStoreAt(rep, `D:\Apps\Java\jdk-21\lib\security\cacerts`) == nil {
		t.Error("JDK under the host's Program Files not found")
	}
	if locConfigOf(rep, `C:\ProgramData\ssh\sshd_config`, "sshd") != nil || locErrorsContain(rep, "assuming C:") {
		t.Error("C: was assumed although the host answered")
	}
	runs := 0
	for _, call := range w.recorded() {
		if strings.HasPrefix(call, "run powershell") {
			runs++
		}
	}
	if runs != 1 {
		t.Errorf("the roots were asked for %d times, want once", runs)
	}

	c := tgtCollection(w, Options{Platform: "windows"})
	for _, tc := range []struct {
		in   []string
		want locWinRoots
	}{
		{[]string{"e:", `E:\PD`, "relative", ""}, locWinRoots{"E:", `E:\PD`, `E:\Program Files`, `E:\Program Files (x86)`}},
		{[]string{"", "", "", ""}, locDefaultWinRoots("C:")},
		{[]string{"C:\\x", "", "", ""}, locDefaultWinRoots("C:")},
		{nil, locDefaultWinRoots("C:")},
	} {
		if got := c.locParseWinRoots(tc.in); got != tc.want {
			t.Errorf("%q: got %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

// TestLocLegacySSH1Key: a legacy SSH-1 key file is a key of its own format,
// in both modes, and its bytes never cross.
func TestLocLegacySSH1Key(t *testing.T) {
	body := append([]byte("SSH PRIVATE KEY FILE FORMAT 1.1\n\x00"), make([]byte, 64)...)
	for _, local := range []bool{true, false} {
		ft := newTgtFakeTarget(local).file("/etc/ssh/ssh_host_key", body).file("/etc/ssh/sshd_config", []byte("HostKey /etc/ssh/ssh_host_key\n"))
		rep := locCollect(t, ft, Options{Platform: "linux"})
		k := locKeyAt(rep, "/etc/ssh/ssh_host_key")
		if k == nil || k.Format != KeyFormatSSH1 || k.Algorithm != "RSA" || k.Unknown == "" {
			t.Errorf("local=%v: %+v", local, k)
		}
		if !local {
			if err := locPrivateReads(ft.recorded(), []string{"/etc/ssh/ssh_host_key"}); err != nil {
				t.Error(err)
			}
		}
	}
}
