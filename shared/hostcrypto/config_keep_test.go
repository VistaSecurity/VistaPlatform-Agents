package hostcrypto

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The keep words are safe only if a parser reading the filtered text reports
// exactly what it reports from the whole file. These tests hold that over
// every configuration fixture of the package, hold the hand-written word
// slices to the parsers' source, and check that the secrets the parsers drop
// do not cross the filter either.

// keepFixture is one configuration a parser test parsed.
type keepFixture struct {
	where   string // test name and ordinal, for messages
	product string // a cfgParsers name, or "" for a back-end
	backend string // a ParseCryptoPolicyBackend name
	in      []byte
}

var (
	keepMu      sync.Mutex
	keepTest    string
	keepRecords []keepFixture
)

// keepRecord is called by cfgT and keepCPBackend. It records only while
// keepCollect runs the fixture tests.
func keepRecord(p ConfigParser, backend string, b []byte) {
	keepMu.Lock()
	defer keepMu.Unlock()
	if keepTest == "" {
		return
	}
	product := ""
	if p != nil {
		ptr := reflect.ValueOf(p).Pointer()
		for name, q := range cfgParsers {
			if reflect.ValueOf(q).Pointer() == ptr {
				product = name
			}
		}
		if product == "" {
			return // a parser that is not a product (none today)
		}
	}
	keepRecords = append(keepRecords, keepFixture{
		where:   keepTest + "#" + strconv.Itoa(len(keepRecords)),
		product: product, backend: backend, in: append([]byte(nil), b...),
	})
}

// keepCPBackend is ParseCryptoPolicyBackend, recorded.
func keepCPBackend(name string, b []byte) []CryptoConfig {
	keepRecord(nil, name, b)
	return ParseCryptoPolicyBackend(name, b)
}

// keepFixtureTests are the tests whose fixtures go through cfgT or
// keepCPBackend. TestKeepFixtureTestsAreAllListed fails when a test that
// parses a fixture is missing here. The Fuzz targets are not run: their
// seeds are hostile inputs, and the hostile tests below cover those.
var keepFixtureTests = map[string]func(*testing.T){
	"TestApacheGnuTLSAndFIPSAndKeyURIs":                    TestApacheGnuTLSAndFIPSAndKeyURIs,
	"TestApacheHostileSyntax":                              TestApacheHostileSyntax,
	"TestApacheMozillaIntermediate":                        TestApacheMozillaIntermediate,
	"TestApacheSecretsAreDropped":                          TestApacheSecretsAreDropped,
	"TestApacheSkippedSections":                            TestApacheSkippedSections,
	"TestCryptoPoliciesConfig":                             TestCryptoPoliciesConfig,
	"TestCryptoPolicyBackends":                             TestCryptoPolicyBackends,
	"TestHAProxyHostile":                                   TestHAProxyHostile,
	"TestHAProxyListenAndDefaultServer":                    TestHAProxyListenAndDefaultServer,
	"TestHAProxySecretsAreDropped":                         TestHAProxySecretsAreDropped,
	"TestHAProxyStock":                                     TestHAProxyStock,
	"TestJavaHostile":                                      TestJavaHostile,
	"TestJavaOptions":                                      TestJavaOptions,
	"TestJavaPropertiesLastWinsAndFIPS":                    TestJavaPropertiesLastWinsAndFIPS,
	"TestJDK17SecurityProperties":                          TestJDK17SecurityProperties,
	"TestKrb5Hostile":                                      TestKrb5Hostile,
	"TestKrb5Libdefaults":                                  TestKrb5Libdefaults,
	"TestKrb5PKINITForms":                                  TestKrb5PKINITForms,
	"TestGnuTLSSystemConfig":                               TestGnuTLSSystemConfig,
	"TestPostfixHostile":                                   TestPostfixHostile,
	"TestPostfixMainCF":                                    TestPostfixMainCF,
	"TestNginxHostileSyntax":                               TestNginxHostileSyntax,
	"TestNginxKeySources":                                  TestNginxKeySources,
	"TestNginxSecretsAreDropped":                           TestNginxSecretsAreDropped,
	"TestNginxServerInheritsHTTP":                          TestNginxServerInheritsHTTP,
	"TestNginxStockMain":                                   TestNginxStockMain,
	"TestNginxStreamMailAndProxy":                          TestNginxStreamMailAndProxy,
	"TestNginxTLSSite":                                     TestNginxTLSSite,
	"TestOpenSSL3WithProviders":                            TestOpenSSL3WithProviders,
	"TestOpenSSLFIPSOnlyByRequirement":                     TestOpenSSLFIPSOnlyByRequirement,
	"TestOpenSSLHostile":                                   TestOpenSSLHostile,
	"TestOpenSSLIncludeForms":                              TestOpenSSLIncludeForms,
	"TestOpenSSLRHELBackendFragment":                       TestOpenSSLRHELBackendFragment,
	"TestOpenSSLSecretsAreDropped":                         TestOpenSSLSecretsAreDropped,
	"TestOpenSSLVariablesAndFragment":                      TestOpenSSLVariablesAndFragment,
	"TestApacheDepthPastLimitIsCountedNotPushed":           TestApacheDepthPastLimitIsCountedNotPushed,
	"TestHAProxyHasNoBackslashContinuation":                TestHAProxyHasNoBackslashContinuation,
	"TestHAProxyKeysAndDirectivesNeverComeFromFileText":    TestHAProxyKeysAndDirectivesNeverComeFromFileText,
	"TestHAProxyProtocolFlagsBesideABoundAreIgnored":       TestHAProxyProtocolFlagsBesideABoundAreIgnored,
	"TestJavaIncludeIsFollowed":                            TestJavaIncludeIsFollowed,
	"TestJavaLoneCarriageReturnEndsALine":                  TestJavaLoneCarriageReturnEndsALine,
	"TestLoneCarriageReturnNeverLeaks":                     TestLoneCarriageReturnNeverLeaks,
	"TestNginxRepeatedProtocolsAreUnited":                  TestNginxRepeatedProtocolsAreUnited,
	"TestOpenSSLExplicitDefaultSection":                    TestOpenSSLExplicitDefaultSection,
	"TestOpenSSLFIPSBackendNeverSetsFIPS":                  TestOpenSSLFIPSBackendNeverSetsFIPS,
	"TestPostfixBlankAndCommentLinesDoNotEndAContinuation": TestPostfixBlankAndCommentLinesDoNotEndAContinuation,
	"TestSSHDMatchKeywordsAreRestricted":                   TestSSHDMatchKeywordsAreRestricted,
	"TestContextIsBoundedAndSanitised":                     TestContextIsBoundedAndSanitised,
	"TestGnuTLSLayouts":                                    TestGnuTLSLayouts,
	"TestJavaOnlyTLSListIsDisabled":                        TestJavaOnlyTLSListIsDisabled,
	"TestKrb5RealmSubsectionAndDuplicates":                 TestKrb5RealmSubsectionAndDuplicates,
	"TestNginxConfCommandReplacesInherited":                TestNginxConfCommandReplacesInherited,
	"TestNoPrefixAdmission":                                TestNoPrefixAdmission,
	"TestOpenSSLOnlySystemDefaultIsHostWide":               TestOpenSSLOnlySystemDefaultIsHostWide,
	"TestProtocolsAreNeverInvented":                        TestProtocolsAreNeverInvented,
	"TestReviewLeaks":                                      TestReviewLeaks,
	"TestSSHMatchCriteriaAllowlist":                        TestSSHMatchCriteriaAllowlist,
	"TestSSHClientConfig":                                  TestSSHClientConfig,
	"TestSSHDIgnoresHostBlocks":                            TestSSHDIgnoresHostBlocks,
	"TestSSHDRHEL9":                                        TestSSHDRHEL9,
	"TestSSHHostile":                                       TestSSHHostile,
}

var (
	keepOnce      sync.Once
	keepCollected []keepFixture
)

// keepCollect runs the fixture tests once with recording on and returns what
// they parsed.
func keepCollect(t *testing.T) []keepFixture {
	t.Helper()
	keepOnce.Do(func() {
		names := make([]string, 0, len(keepFixtureTests))
		for n := range keepFixtureTests {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			keepMu.Lock()
			keepTest = n
			keepMu.Unlock()
			t.Run("collect/"+n, keepFixtureTests[n])
		}
		keepMu.Lock()
		keepTest = ""
		keepCollected = keepRecords
		keepRecords = nil
		keepMu.Unlock()
	})
	if len(keepCollected) < 100 {
		t.Fatalf("only %d fixtures recorded", len(keepCollected))
	}
	return keepCollected
}

func (f keepFixture) keep() []string {
	if f.backend != "" {
		return ConfigBackendKeepWords(f.backend)
	}
	return ConfigKeepWords(f.product)
}

func (f keepFixture) parse(b []byte) []CryptoConfig {
	if f.backend != "" {
		return ParseCryptoPolicyBackend(f.backend, b)
	}
	return cfgParsers[f.product](b, nil)
}

func (f keepFixture) name() string {
	if f.backend != "" {
		return "back-end " + f.backend
	}
	return f.product
}

// keepFilter is FilterConfigText for a test: the text, and whether the
// parity comparison applies (the file was accepted and nothing redacted: a
// redaction changes a value on purpose).
func keepFilter(t *testing.T, b []byte, keep []string) ([]byte, bool) {
	t.Helper()
	if len(keep) == 0 {
		t.Fatalf("no keep words")
	}
	out, red, ok := FilterConfigText(b, keep)
	return out, ok && red == 0
}

// keepExpectedDiff are the fixtures whose parse the filter changes because
// the rule cannot express what the parser reads (see the comment at the top
// of config_keep.go). Each entry names a product ("" for any) and a test of
// the fixture; a fixture it matches may differ, any other may not, and every
// entry must be met by a fixture that does differ, so the list cannot go
// stale.
var keepExpectedDiff = []struct {
	product string
	match   func(in []byte) bool
	why     string
}{
	// Unsupported, by design: a shell line's words are whatever the script
	// says, so only jvm.options (one option per line) is read through
	// ReadText.
	{"java-options", keepOptionAfterFirstWord, "an option after a first word that is not an option (JAVA_OPTS=\"..., a quote): the line is not kept"},
	// A lone CR cuts its line (FilterConfigText rule 2), so what follows it
	// never crosses. These two parsers read such a line WHOLE and reject it
	// for what follows the CR, so the whole file reports nothing while the
	// cut line reports the directive before the CR. Closing it needs the
	// parser to cut there too; every other line-mode parser already reads
	// the line as the filter does.
	{"apache", keepLoneCR, "a lone CR: the filter cuts the line, the Apache parser rejects the whole line"},
	{"crypto-policies", keepLoneCR, "a lone CR: the filter cuts the line, the crypto-policies parser rejects the whole line"},
}

// keepLoneCR is a "\r" not followed by "\n".
func keepLoneCR(in []byte) bool {
	for i, c := range in {
		if c == '\r' && (i+1 == len(in) || in[i+1] != '\n') {
			return true
		}
	}
	return false
}

// keepOptionAfterFirstWord is a line holding "-D" whose first word is not an
// option.
func keepOptionAfterFirstWord(in []byte) bool {
	for _, l := range configLines(in) {
		t := strings.TrimLeft(l, " \t")
		if strings.Contains(t, "-D") && !strings.HasPrefix(t, "-D") {
			return true
		}
	}
	return false
}

func TestKeepWordsParity(t *testing.T) {
	met := map[int]bool{}
	checked, skipped := 0, 0
	for _, f := range keepCollect(t) {
		filtered, ok := keepFilter(t, f.in, f.keep())
		if !ok {
			skipped++
			continue
		}
		want, got := f.parse(f.in), f.parse(filtered)
		same := reflect.DeepEqual(want, got)
		expected := -1
		for i, e := range keepExpectedDiff {
			if (e.product == "" || e.product == f.product) && e.match(f.in) {
				expected = i
			}
		}
		switch {
		case expected >= 0 && !same:
			met[expected] = true
		case !same:
			t.Errorf("%s (%s): the filter changes the result\ninput:\n%s\nfiltered:\n%s\nwhole: %s\nfiltered: %s",
				f.where, f.name(), f.in, filtered, cfgJSON(t, want), cfgJSON(t, got))
		}
		checked++
	}
	for i, e := range keepExpectedDiff {
		if !met[i] {
			t.Errorf("expected difference %q (%s) met no fixture", e.why, e.product)
		}
	}
	t.Logf("%d fixtures compared, %d refused or redacted by the filter", checked, skipped)
	if checked < 100 {
		t.Errorf("only %d fixtures compared", checked)
	}
}

// keepTree is one tree of the own fixtures, parsed as the collector would:
// the root through ReadText's rule, and every included file too.
type keepTree struct {
	product, root, base string
	files               map[string][]byte
}

func keepTrees(t *testing.T) []keepTree {
	rocky := cfgFixtureTree(t, "rocky9", "/")
	for k, v := range cfgFixtureTree(t, "rocky", "/") {
		rocky[k] = v
	}
	deb := cfgFixtureTree(t, "debian", "/")
	deb["/etc/nginx/sites-enabled/default"] = deb["/etc/nginx/sites-available/default"]
	deb["/etc/apache2/mods-enabled/ssl.conf"] = deb["/etc/apache2/mods-available/ssl.conf"]
	deb["/etc/apache2/sites-enabled/default-ssl.conf"] = deb["/etc/apache2/sites-available/default-ssl.conf"]
	return []keepTree{
		{"sshd", "/etc/ssh/sshd_config", "/etc/ssh", rocky},
		{"krb5", "/etc/krb5.conf", "/etc", rocky},
		{"openssl", "/etc/pki/tls/openssl.cnf", "/etc/pki/tls", rocky},
		{"nginx", "/etc/nginx/nginx.conf", "/etc/nginx", deb},
		{"nginx", "/etc/nginx/nginx.conf", "/etc/nginx", cfgFixtureTree(t, "nginx", "/etc")},
		{"apache", "/usr/local/apache2/conf/httpd.conf", "/usr/local/apache2", cfgFixtureTree(t, "httpd", "/usr/local/apache2")},
	}
}

// keepOwnProduct says which parser reads an own fixture file, by its path.
func keepOwnProduct(rel string) (product, backend string) {
	switch {
	case strings.HasPrefix(rel, "etc/crypto-policies/back-ends/"):
		return "", path.Base(rel)
	case strings.HasPrefix(rel, "etc/ssh/sshd_config"):
		return "sshd", ""
	case strings.HasPrefix(rel, "etc/krb5.conf"):
		return "krb5", ""
	case rel == "etc/pki/tls/openssl.cnf":
		return "openssl", ""
	case strings.Contains(rel, "nginx/"):
		return "nginx", ""
	case strings.HasPrefix(rel, "etc/apache2/") || strings.HasPrefix(rel, "conf/"):
		return "apache", ""
	case rel == "etc/haproxy/haproxy.cfg":
		return "haproxy", ""
	case rel == "etc/postfix/main.cf":
		return "postfix", ""
	case rel == "java.security":
		return "java", ""
	}
	return "", ""
}

// keepOwnFixtures is every own fixture file, as a keepFixture.
func keepOwnFixtures(t *testing.T) []keepFixture {
	var out []keepFixture
	for dir, files := range cfgOwn {
		for rel, text := range files {
			product, backend := keepOwnProduct(rel)
			if product == "" && backend == "" {
				t.Errorf("own fixture %s/%s: no product for it; add it to keepOwnProduct", dir, rel)
				continue
			}
			out = append(out, keepFixture{where: dir + "/" + rel, product: product, backend: backend, in: []byte(text)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].where < out[j].where })
	return out
}

func TestKeepWordsParityOwnFixtures(t *testing.T) {
	for _, f := range keepOwnFixtures(t) {
		filtered, ok := keepFilter(t, f.in, f.keep())
		if !ok {
			t.Errorf("%s: the filter refused or redacted an own fixture", f.where)
			continue
		}
		if want, got := f.parse(f.in), f.parse(filtered); !reflect.DeepEqual(want, got) {
			t.Errorf("%s (%s): the filter changes the result\nfiltered:\n%s\nwhole: %s\nfiltered: %s",
				f.where, f.name(), filtered, cfgJSON(t, want), cfgJSON(t, got))
		}
	}
	// Through includes: every included file is filtered with the root's
	// product's words, as the collector's resolver reads it.
	for _, tr := range keepTrees(t) {
		keep := ConfigKeepWords(tr.product)
		filtered := map[string][]byte{}
		for k, v := range tr.files {
			out, ok := keepFilter(t, v, keep)
			if !ok {
				t.Fatalf("%s: refused or redacted", k)
			}
			filtered[k] = out
		}
		p := cfgParsers[tr.product]
		want := p(tr.files[tr.root], cfgMapResolver(tr.files, tr.base))
		got := p(filtered[tr.root], cfgMapResolver(filtered, tr.base))
		if len(want) == 0 {
			t.Errorf("%s %s: the tree reports nothing; the comparison would prove nothing", tr.product, tr.root)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s %s through includes: whole %s\nfiltered %s", tr.product, tr.root, cfgJSON(t, want), cfgJSON(t, got))
		}
	}
}

// keepSecrets are secret-bearing lines of each syntax that the parser does
// not read, the forms the parsers' own secret tests use. Every value holds
// "KEEPSECRET".
var keepSecrets = map[string][]string{
	"openssl": {"input_password = KEEPSECRET1", "output_password = KEEPSECRET2", "PIN = KEEPSECRET3",
		"pw = KEEPSECRET4", "module-mac = KEEPSECRET5"},
	"java": {"javax.net.ssl.keyStorePassword=KEEPSECRET1", "fips.keystore.password=KEEPSECRET2",
		"javax.net.ssl.trustStorePassword=KEEPSECRET3", "fips.provider.1000=KEEPSECRET4",
		"security.providerX=KEEPSECRET5"},
	"java-options": {"-Djavax.net.ssl.keyStorePassword=KEEPSECRET1", "-Djavax.net.ssl.trustStorePassword=KEEPSECRET2",
		"-Dcom.example.token=KEEPSECRET3"},
	"sshd": {"AuthorizedKeysCommand /usr/bin/fetch --token KEEPSECRET1", "SetEnv TOKEN=KEEPSECRET2",
		"Banner /etc/KEEPSECRET3", "Subsystem x /bin/x KEEPSECRET4"},
	"ssh": {"ProxyCommand curl -H 'Authorization: Bearer KEEPSECRET1' x", "LocalCommand echo KEEPSECRET2",
		"SetEnv TOKEN=KEEPSECRET3", "RemoteCommand KEEPSECRET4"},
	"nginx": {"ssl_password_file /etc/nginx/KEEPSECRET1;", "ssl_session_ticket_key /etc/KEEPSECRET2;",
		"proxy_set_header Authorization \"Bearer KEEPSECRET3\";", "auth_basic_user_file /KEEPSECRET4;",
		"proxy_ssl_password_file /KEEPSECRET5;"},
	"apache": {"SSLPassPhraseDialog exec:/bin/echo KEEPSECRET1", "GnuTLSP12Password KEEPSECRET2",
		"RequestHeader set Authorization \"Bearer KEEPSECRET3\"", "ProxyRemote * http://u:KEEPSECRET4@h",
		"SSLProxyMachineCertificatePassword KEEPSECRET5"},
	"haproxy": {"stats auth admin:KEEPSECRET1", "user admin insecure-password KEEPSECRET2",
		"http-request set-header Authorization \"Bearer KEEPSECRET3\"", "ca-sign-pass KEEPSECRET4"},
	"crypto-policies": {"password=KEEPSECRET1"},
	"krb5":            {"pkinit_pin = KEEPSECRET1", "password = KEEPSECRET2", "admin_password = KEEPSECRET3"},
	"gnutls":          {"SECRET = KEEPSECRET1", "token = KEEPSECRET2"},
	"postfix": {"smtp_sasl_password_maps = hash:/etc/postfix/KEEPSECRET1", "smtpd_sasl_password = KEEPSECRET2",
		"relay_password = KEEPSECRET3"},
}

// keepBackendSyntax is the syntax of each back-end, for its secrets.
var keepBackendSyntax = map[string]string{
	"opensslcnf.config": "openssl", "openssl_fips.config": "openssl", "openssl.config": "openssl",
	"openssh.config": "ssh", "libssh.config": "ssh", "opensshserver.config": "sshd",
	"gnutls.config": "gnutls", "java.config": "java", "javasystem.config": "java",
	"nss.config": "crypto-policies", "krb5.config": "krb5",
}

// keepInsertPoints are the line boundaries of text where a new line is a
// line of its own: the start, the boundary after the first line past the
// middle that ends a statement (not a "\" continuation, and for nginx a line
// ending in ";", "{" or "}"), and the end when the last line ends one.
func keepInsertPoints(lines []string, nginx bool) []int {
	ends := func(i int) bool {
		s := strings.TrimRight(lines[i], " \t")
		if strings.HasSuffix(s, `\`) {
			return false
		}
		return !nginx || strings.HasSuffix(s, ";") || strings.HasSuffix(s, "{") || strings.HasSuffix(s, "}")
	}
	pts := []int{0}
	for i := len(lines) / 2; i < len(lines)-1; i++ {
		if ends(i) {
			pts = append(pts, i+1)
			break
		}
	}
	if len(lines) > 0 && ends(len(lines)-1) {
		pts = append(pts, len(lines))
	}
	return pts
}

func TestKeepWordsDropSecrets(t *testing.T) {
	fixtures := append(keepOwnFixtures(t), keepCollect(t)...)
	byProduct := map[string]int{}
	for _, f := range fixtures {
		syntax := f.product
		if f.backend != "" {
			syntax = keepBackendSyntax[path.Base(f.backend)]
			if syntax == "" {
				syntax = keepBackendSyntax[path.Base(f.backend)+".config"]
			}
		}
		secrets := keepSecrets[syntax]
		if len(secrets) == 0 {
			t.Errorf("%s: no secret lines for syntax %q", f.where, syntax)
			continue
		}
		if _, _, ok := FilterConfigText(f.in, f.keep()); !ok {
			continue
		}
		lines := configLines(f.in)
		for _, at := range keepInsertPoints(lines, f.product == "nginx") {
			var b strings.Builder
			for i, l := range lines {
				if i == at {
					b.WriteString(strings.Join(secrets, "\n") + "\n")
				}
				b.WriteString(l + "\n")
			}
			if at == len(lines) {
				b.WriteString(strings.Join(secrets, "\n") + "\n")
			}
			out, _, ok := FilterConfigText([]byte(b.String()), f.keep())
			if !ok {
				t.Errorf("%s: refused after injection", f.where)
				continue
			}
			if bytes.Contains(out, []byte("KEEPSECRET")) {
				t.Errorf("%s (%s): an injected secret crossed the filter at line %d:\n%s", f.where, f.name(), at, out)
			}
		}
		byProduct[syntax]++
	}
	for syntax := range keepSecrets {
		if byProduct[syntax] == 0 {
			t.Errorf("no fixture of syntax %s carried injected secrets", syntax)
		}
	}
}

// keepBackendNames are the names ParseCryptoPolicyBackend's switch accepts,
// read from its source.
func keepBackendNames(t *testing.T) []string {
	return keepSwitchCases(t, "ParseCryptoPolicyBackend", "base")
}

func TestKeepWordsGuard(t *testing.T) {
	for key, words := range configKeepWords {
		for i := 0; i < len(key); i++ {
			if c := key[i]; c > 0x7e || c <= ' ' || (c >= 'A' && c <= 'Z') {
				t.Errorf("key %q: not lower-case printable ASCII without a blank", key)
				break
			}
		}
		if len(words) == 0 {
			t.Errorf("key %q: no words", key)
		}
		// Every word must be sendable to a remote host as it is.
		if _, err := keepArg(words); err != nil {
			t.Errorf("key %q: %v", key, err)
		}
		for _, w := range words {
			if w != asciiLower(w) || strings.ContainsAny(w, " \t") {
				t.Errorf("key %q: word %q is not lower-case or holds a blank", key, w)
			}
		}
	}
	for _, p := range ConfigProducts() {
		if len(ConfigKeepWords(p)) == 0 {
			t.Errorf("product %s has no keep words", p)
		}
	}
	names := keepBackendNames(t)
	if len(names) < 10 {
		t.Fatalf("read %d back-end names from the source", len(names))
	}
	for _, n := range names {
		for _, spelling := range []string{n, n + ".config", "/etc/crypto-policies/back-ends/" + n + ".config"} {
			if len(ConfigBackendKeepWords(spelling)) == 0 {
				t.Errorf("back-end %q has no keep words", spelling)
			}
		}
	}
	// No other keys than the products and the back-ends.
	if want := len(ConfigProducts()) + len(names); len(configKeepWords) != want {
		t.Errorf("%d keys, want %d", len(configKeepWords), want)
	}
	if ConfigKeepWords("nosuch") != nil {
		t.Errorf("an unknown product has keep words")
	}
	// The result is a copy.
	w := ConfigKeepWords("sshd")
	w[0] = "x"
	if ConfigKeepWords("sshd")[0] == "x" {
		t.Errorf("ConfigKeepWords returns the table itself")
	}
}

// keepContains reports whether the product's list holds word (with or
// without ";").
func keepContains(product, word string) bool {
	word = asciiLower(word)
	for _, w := range ConfigKeepWords(product) {
		if strings.TrimSuffix(w, ";") == word {
			return true
		}
	}
	return false
}

// keepSecretDirectives must never be on a list: the parsers' own secret
// tests name them.
var keepSecretDirectives = map[string][]string{
	"openssl":      {"input_password", "output_password", "pin", "pass"},
	"java":         {"javax.net.ssl.keyStorePassword", "javax.net.ssl.trustStorePassword", "fips.keystore.password"},
	"java-options": {"javax.net.ssl.keyStorePassword", "javax.net.ssl.trustStorePassword"},
	"sshd":         {"authorizedkeyscommand", "setenv", "banner", "subsystem"},
	"ssh":          {"proxycommand", "localcommand", "remotecommand", "setenv"},
	"nginx":        {"ssl_password_file", "ssl_session_ticket_key", "proxy_ssl_password_file", "proxy_set_header"},
	"apache":       {"sslpassphrasedialog", "gnutlsp12password", "requestheader"},
	"haproxy":      {"stats", "user", "http-request", "ca-sign-pass", "tls-ticket-keys"},
	"postfix":      {"smtp_sasl_password_maps", "smtpd_sasl_password_maps", "relayhost"},
}

func TestKeepWordsNeverListASecretDirective(t *testing.T) {
	for product, names := range keepSecretDirectives {
		for _, n := range names {
			if keepContains(product, n) {
				t.Errorf("%s lists %q", product, n)
			}
		}
	}
}

// The parsers' source, read once.
var (
	keepSrcOnce  sync.Once
	keepSrcFuncs map[string]*ast.FuncDecl
	keepSrcErr   error
)

func keepFunc(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	keepSrcOnce.Do(func() {
		keepSrcFuncs = map[string]*ast.FuncDecl{}
		paths, err := filepath.Glob("*.go")
		if err != nil {
			keepSrcErr = err
			return
		}
		fset := token.NewFileSet()
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				keepSrcErr = err
				return
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				n := fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) == 1 {
					rt := fd.Recv.List[0].Type
					if st, ok := rt.(*ast.StarExpr); ok {
						rt = st.X
					}
					n = types.ExprString(rt) + "." + n
				}
				keepSrcFuncs[n] = fd
			}
		}
	})
	if keepSrcErr != nil {
		t.Fatal(keepSrcErr)
	}
	fd := keepSrcFuncs[name]
	if fd == nil {
		t.Fatalf("no function %s in the package source", name)
	}
	return fd
}

func keepLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

// keepSwitchCases returns the string cases of the switches on tag in fn.
func keepSwitchCases(t *testing.T, fn, tag string) []string {
	var out []string
	ast.Inspect(keepFunc(t, fn), func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil || types.ExprString(sw.Tag) != tag {
			return true
		}
		for _, st := range sw.Body.List {
			for _, e := range st.(*ast.CaseClause).List {
				if s, ok := keepLit(e); ok {
					out = append(out, s)
				}
			}
		}
		return true
	})
	return out
}

// keepCallArgs returns the string literal arguments of calls in fn to a
// function or method named callee.
func keepCallArgs(t *testing.T, fn, callee string) []string {
	var out []string
	ast.Inspect(keepFunc(t, fn), func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch f := c.Fun.(type) {
		case *ast.Ident:
			name = f.Name
		case *ast.SelectorExpr:
			name = f.Sel.Name
		}
		if name != callee {
			return true
		}
		for _, a := range c.Args {
			if s, ok := keepLit(a); ok {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// keepIndexKeys returns the string literal keys of index expressions in fn
// whose operand prints as x, or ends in "."+x.
func keepIndexKeys(t *testing.T, fn, x string) []string {
	var out []string
	ast.Inspect(keepFunc(t, fn), func(n ast.Node) bool {
		ix, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}
		if xs := types.ExprString(ix.X); xs == x || strings.HasSuffix(xs, "."+x) {
			if s, ok := keepLit(ix.Index); ok {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// keepCompared returns the string literals compared (== or !=) with lhs in fn.
func keepCompared(t *testing.T, fn, lhs string) []string {
	var out []string
	ast.Inspect(keepFunc(t, fn), func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || (be.Op != token.EQL && be.Op != token.NEQ) || types.ExprString(be.X) != lhs {
			return true
		}
		if s, ok := keepLit(be.Y); ok && s != "" {
			out = append(out, s)
		}
		return true
	})
	return out
}

// keepMinus is a without the words of b.
func keepMinus(a, b []string) []string {
	var out []string
	for _, w := range a {
		if !slices.Contains(b, w) {
			out = append(out, w)
		}
	}
	return out
}

func keepUnion(groups ...[]string) []string {
	m := map[string]bool{}
	for _, g := range groups {
		for _, w := range g {
			m[asciiLower(w)] = true
		}
	}
	out := make([]string, 0, len(m))
	for w := range m {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// TestKeepSlicesMatchTheParsers holds every hand-written keep* slice to the
// switch, comparison or lookup it stands for: a case added to a parser and
// not here (or the reverse) fails.
func TestKeepSlicesMatchTheParsers(t *testing.T) {
	var crypto []string
	for _, p := range keepCallArgs(t, "cfgCPOpenSSHOptions", "CutPrefix") {
		if strings.HasSuffix(p, "=") {
			crypto = append(crypto, strings.TrimSuffix(p, "="))
		}
	}
	for _, c := range []struct {
		name       string
		have, want []string
	}{
		{"keepOpenSSLSSLKeys", keepOpenSSLSSLKeys, keepCallArgs(t, "cfgOSSLApplySSL", "val")},
		{"keepOpenSSLChain", keepOpenSSLChain, keepUnion(
			keepCallArgs(t, "cfgOSSLFile.init", "ci"), keepCallArgs(t, "cfgParseOpenSSL", "ci"),
			keepIndexKeys(t, "cfgParseOpenSSL", "vals"), keepCallArgs(t, "cfgOSSLProvidersAndEngines", "ci"))},
		{"keepOpenSSLFragment", keepOpenSSLFragment, keepCallArgs(t, "cfgOSSLFragment", "ci")},
		{"keepJavaProps", keepJavaProps, keepUnion(keepIndexKeys(t, "cfgParseJava", "props"), keepIndexKeys(t, "cfgJavaExpandIncludes", "props"))},
		{"keepJavaStructure", keepJavaStructure, keepCompared(t, "cfgParseJava", "k")},
		{"keepJavaOptions", keepJavaOptions, keepSwitchCases(t, "cfgJavaOption", "name")},
		{"keepSSHKeywords", keepSSHKeywords, keepSwitchCases(t, "cfgSSHKeyword", "kw")},
		{"keepSSHBlocks", keepSSHBlocks, keepMinus(keepCompared(t, "cfgParseSSH", "kw"), keepSSHKeywords)},
		{"keepCPOpenSSHOptions", keepCPOpenSSHOptions, crypto},
		{"keepNginxDirectives", keepNginxDirectives, keepSwitchCases(t, "cfgNgxApply", "n.name")},
		{"keepNginxBlocks", keepNginxBlocks, keepSwitchCases(t, "cfgParseNginx", "n.name")},
		{"keepApacheDirectives", keepApacheDirectives, keepSwitchCases(t, "cfgApacheDirective", "d")},
		{"keepApacheSections", keepApacheSections, keepCompared(t, "cfgParseApache", "name")},
		{"keepHAProxyGlobal", keepHAProxyGlobal, keepSwitchCases(t, "cfgParseHAProxy", "f[0]")},
		{"keepHAProxyServers", keepHAProxyServers, keepSwitchCases(t, "cfgHAServers", "f[0]")},
		{"keepHAProxyBind", keepHAProxyBind, keepUnion(keepCompared(t, "cfgParseHAProxy", "f[0]"), keepCompared(t, "cfgHAServerDefaults.add", "f[0]"))},
		{"keepKrb5Relations", keepKrb5Relations, keepSwitchCases(t, "cfgKrb5Relation", "k")},
		{"keepKrb5Includes", keepKrb5Includes, keepCallArgs(t, "cfgParseKrb5", "EqualFold")},
		{"keepGnuTLSSystem", keepGnuTLSSystem, keepCompared(t, "cfgParseGnuTLS", "k")},
		{"keepNSSPolicy", keepNSSPolicy, keepCallArgs(t, "cfgParseNSSPolicy", "EqualFold")},
	} {
		have, want := keepUnion(c.have), keepUnion(c.want)
		if len(want) == 0 {
			t.Errorf("%s: nothing read from the source; the check would prove nothing", c.name)
		}
		if !reflect.DeepEqual(have, want) {
			t.Errorf("%s = %v\nthe parser reads %v", c.name, have, want)
		}
	}
	// The numbered Java families: listed from the prefixes the parser uses.
	if !keepContains("java", cfgJavaProviderPrefix+"1") || !keepContains("java", cfgJavaFIPSProviderPrefix+"99") ||
		keepContains("java", cfgJavaProviderPrefix+"100") || keepContains("java", cfgJavaProviderPrefix+"01") {
		t.Errorf("numbered provider words are not 1 to 99")
	}
}

// TestKeepFixtureTestsAreAllListed reads the package's test files and fails
// when a test that parses through cfgT or keepCPBackend is not run by
// keepCollect, so a new fixture cannot escape the parity test.
func TestKeepFixtureTestsAreAllListed(t *testing.T) {
	paths, err := filepath.Glob("config_*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, p := range paths {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !strings.HasPrefix(fd.Name.Name, "Test") || strings.HasPrefix(fd.Name.Name, "TestKeep") {
				continue
			}
			uses := false
			ast.Inspect(fd, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && (id.Name == "cfgT" || id.Name == "keepCPBackend") {
					uses = true
				}
				return true
			})
			if !uses {
				continue
			}
			found++
			if keepFixtureTests[fd.Name.Name] == nil {
				t.Errorf("%s (%s) parses fixtures but is not in keepFixtureTests", fd.Name.Name, p)
			}
		}
	}
	if found != len(keepFixtureTests) {
		t.Errorf("found %d fixture tests, keepFixtureTests lists %d: it lists one that parses no fixture", found, len(keepFixtureTests))
	}
}

// TestKeepOptionsPerProduct: each product declares exactly the options of
// its syntax (see the comment at the top of config_keep.go).
func TestKeepOptionsPerProduct(t *testing.T) {
	want := map[string]string{
		"nginx": "@statements", "java": "@backslash @cr", "java-options": "@backslash @cr", "apache": "@backslash",
		"openssl": "@backslash", "postfix": "@indent", "sshd": "", "ssh": "", "haproxy": "", "krb5": "", "gnutls": "", "crypto-policies": "",
		"crypto-policies/opensslcnf.config": "@backslash", "crypto-policies/openssl_fips.config": "@backslash",
		"crypto-policies/openssl.config": "", "crypto-policies/openssh.config": "@backslash", "crypto-policies/libssh.config": "@backslash",
		"crypto-policies/opensshserver.config": "@backslash", "crypto-policies/gnutls.config": "", "crypto-policies/java.config": "@backslash @cr",
		"crypto-policies/javasystem.config": "@backslash @cr", "crypto-policies/nss.config": "", "crypto-policies/krb5.config": "",
	}
	if len(want) != len(configKeepWords) {
		t.Errorf("%d keys listed here, %d in the table", len(want), len(configKeepWords))
	}
	for key, w := range want {
		var opts []string
		for _, e := range configKeepWords[key] {
			if strings.HasPrefix(e, "@") {
				opts = append(opts, e)
			}
		}
		sort.Strings(opts)
		if got := strings.Join(opts, " "); got != w {
			t.Errorf("%s: options %q, want %q", key, got, w)
		}
		if !newKeepSet(configKeepWords[key]).usable() {
			t.Errorf("%s: the list is not usable", key)
		}
	}
	// The opener-only words are gone: a dropped block drops itself now.
	for _, w := range []string{"location", "events", "upstream"} {
		if keepContains("nginx", w) {
			t.Errorf("nginx lists %q", w)
		}
	}
	for _, w := range []string{"directory", "location", "files"} {
		if keepContains("apache", w) {
			t.Errorf("apache lists %q", w)
		}
	}
}
