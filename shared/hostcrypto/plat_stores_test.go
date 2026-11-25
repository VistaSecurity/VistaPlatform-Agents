package hostcrypto

import (
	"crypto/sha1" // #nosec G505 -- test: the thumbprint the store would print
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

func platThumb(der []byte) string {
	s := sha1.Sum(der) // #nosec G401 -- test
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

// platStoresAnswer builds a stores answer: a My store with one certificate
// whose key is in the TPM provider, a Root store with one anchor, a store
// the account was refused, and (users) CurrentUser\My.
func platStoresAnswer(t *testing.T, my, root platKey, users bool) string {
	stores := []map[string]any{
		{"Store": `Cert:\LocalMachine\My`, "Error": "", "Truncated": false, "Certs": []map[string]any{{
			"Der": base64.StdEncoding.EncodeToString(my.certDER), "HasKey": true,
			"Key": map[string]any{"Provider": "Microsoft Platform Crypto Provider", "Algorithm": "ECDSA_P256", "Size": 256, "Export": "None", "Hardware": nil, "Error": ""},
		}}},
		// A single certificate arrives as an object, not an array (PowerShell
		// 5.1 unrolls); psArray reads both.
		{"Store": `Cert:\LocalMachine\Root`, "Error": "", "Truncated": true, "Certs": map[string]any{
			"Der": base64.StdEncoding.EncodeToString(root.certDER), "HasKey": false, "Key": nil,
		}},
		{"Store": `Cert:\LocalMachine\Remote Desktop`, "Error": "denied", "Truncated": false, "Certs": []any{}},
	}
	if users {
		stores = append(stores, map[string]any{"Store": `Cert:\CurrentUser\My`, "Error": "", "Truncated": false, "Certs": []map[string]any{{
			"Der": base64.StdEncoding.EncodeToString(root.certDER), "HasKey": true,
			"Key": map[string]any{"Provider": "Microsoft Software Key Storage Provider", "Algorithm": "ECDSA_P256", "Size": 256, "Export": "AllowExport, AllowPlaintextExport", "Error": ""},
		}}})
	}
	return platJSON(t, map[string]any{"Elevated": false, "Stores": stores})
}

func TestPlatParseWindowsStores(t *testing.T) {
	my, root := platNewKey(t, "my"), platNewKey(t, "root")
	res, err := platParseWindowsStores([]byte(platStoresAnswer(t, my, root, true)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Elevated == nil || *res.Elevated {
		t.Fatalf("elevated: %v", res.Elevated)
	}
	if len(res.Certs) != 3 || len(res.Keys) != 2 {
		t.Fatalf("certs %d keys %d", len(res.Certs), len(res.Keys))
	}
	c0 := res.Certs[0]
	if c0.Location.Store != `Cert:\LocalMachine\My` || c0.Location.FoundBy != FoundByPlatformStore || c0.HasPrivateKey == nil || !*c0.HasPrivateKey || c0.TrustAnchor || c0.CertificatePEM == "" {
		t.Fatalf("my certificate: %+v", c0)
	}
	if c1 := res.Certs[1]; !c1.TrustAnchor || c1.CertificatePEM != "" || *c1.HasPrivateKey {
		t.Fatalf("root anchor: %+v", c1)
	}
	if c2 := res.Certs[2]; c2.TrustAnchor || c2.Location.Store != `Cert:\CurrentUser\My` {
		t.Fatalf("a user's store is not an anchor store: %+v", c2)
	}
	k := res.Keys[0]
	if k.Format != KeyFormatPlatformStore || k.Protection != KeyProtectionTPM || k.Provider != "Microsoft Platform Crypto Provider" || k.ProviderKind != ProviderKindTPM ||
		k.Location.Store != `Cert:\LocalMachine\My` || k.Location.Container != "" || k.Location.Alias != "" || k.Algorithm != "ECDSA" || k.SizeBits != 256 ||
		k.Curve != "P-256" || k.PublicKeySHA256 != c0.PublicKeySHA256 || k.Exportable == nil || *k.Exportable {
		t.Fatalf("tpm key: %+v", k)
	}
	if k := res.Keys[1]; k.Protection != KeyProtectionSoftware || k.ProviderKind != ProviderKindSoftware || k.Exportable == nil || !*k.Exportable {
		t.Fatalf("software key: %+v", k)
	}
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0].Error(), "Remote Desktop") || len(res.Truncated) != 1 || !res.UserStores {
		t.Fatalf("problems %v truncated %v", res.Problems, res.Truncated)
	}
}

// TestPlatWindowsStoresSecrecy: what the host sends is projected, never
// passed through. A key blob in an unexpected field is not decoded, a "Der"
// that is a private key is not a certificate and is dropped, and a
// container name is not a field.
func TestPlatWindowsStoresSecrecy(t *testing.T) {
	k := platNewKey(t, "leak")
	ans := platJSON(t, map[string]any{"Elevated": true, "Stores": []map[string]any{{
		"Store": `Cert:\LocalMachine\My`, "Error": "", "Truncated": false, "Certs": []map[string]any{
			{"Der": base64.StdEncoding.EncodeToString(k.keyDER), "HasKey": true, "Key": nil},
			{"Der": base64.StdEncoding.EncodeToString(k.certDER), "HasKey": true,
				"PrivateKeyBlob": base64.StdEncoding.EncodeToString(k.keyDER),
				"Key": map[string]any{"Provider": "Microsoft Software Key Storage Provider", "UniqueName": hex.EncodeToString(k.secret()),
					"Blob": base64.StdEncoding.EncodeToString(k.secret()), "Size": 256, "Export": "None"}},
		}}}})
	res, err := platParseWindowsStores([]byte(ans))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Certs) != 1 || len(res.Keys) != 1 {
		t.Fatalf("certs %d keys %d", len(res.Certs), len(res.Keys))
	}
	keyAssertNoLeak(t, "stores", res, k.secret()) // the scalar: the PKCS#8 DER also holds the public key the certificate carries

	// The detector sees a leak when there is one.
	leaky := res
	leaky.Keys = append([]PrivateKey(nil), res.Keys...)
	leaky.Keys[0].Unknown = base64.StdEncoding.EncodeToString(k.secret())
	if keyLeakIn([]byte(platJSON(t, leaky.Keys)), k.secret()) == "" {
		t.Fatal("the leak check passes a record holding the key")
	}
}

func TestPlatWinProviderKind(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		provider string
		hw       *bool
		want     string
	}{
		{"Microsoft Platform Crypto Provider", nil, ProviderKindTPM},
		{"Microsoft Smart Card Key Storage Provider", nil, ProviderKindSmartCard},
		{"Microsoft Base Smart Card Crypto Provider", nil, ProviderKindSmartCard},
		{"Vendor CSP", &yes, ProviderKindSmartCard},
		{"Microsoft Enhanced Cryptographic Provider v1.0", &no, ProviderKindSoftware},
		{"Microsoft Software Key Storage Provider", nil, ProviderKindSoftware},
		{"", nil, ProviderKindUnknown},
	} {
		if got := platWinProviderKind(tc.provider, tc.hw); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.provider, got, tc.want)
		}
	}
}

// A key the account cannot open still has its certificate's algorithm, and
// says why the rest is missing.
func TestPlatWindowsKeyRefused(t *testing.T) {
	k := platNewKey(t, "refused")
	cert, err := ParseCertificateDER(k.certDER)
	if err != nil {
		t.Fatal(err)
	}
	pk := platWinPrivateKey(`Cert:\LocalMachine\My`, cert, &platWinKey{Error: "denied"})
	if pk.Algorithm != "ECDSA" || pk.Unknown == "" || pk.Provider != "" || pk.ProviderKind != ProviderKindUnknown || pk.Location.Store != `Cert:\LocalMachine\My` || pk.Exportable != nil {
		t.Fatalf("%+v", pk)
	}
}

func TestPlatWindowsStoresThroughCollect(t *testing.T) {
	my, root := platNewKey(t, "my"), platNewKey(t, "root")
	for _, local := range []bool{true, false} {
		for _, users := range []bool{false, true} {
			ft := newPlatFakeWin(t, local)
			ft.answers["stores"] = platStoresAnswer(t, my, root, users)
			rep := platCollect(t, ft, Options{Platform: hostinventory.PlatformWindows, HomeDirectories: users})
			if rep.Sections[SectionCertificates] != SectionPartial || rep.Sections[SectionPrivateKeys] != SectionPartial {
				t.Fatalf("local=%v: sections %v", local, rep.Sections)
			}
			if !platErrorsContain(rep, SectionCertificates, "Remote Desktop") {
				t.Fatalf("the refused store is not named: %+v", rep.Errors)
			}
			if rep.Access.Elevated == nil || *rep.Access.Elevated {
				t.Fatalf("elevated: %v", rep.Access.Elevated)
			}
			if users && rep.Sections[SectionHomeDirectories] != SectionPartial {
				t.Fatalf("home directories: %v", rep.Sections)
			}
			if !users && rep.Sections[SectionHomeDirectories] != "" {
				t.Fatalf("home directories claimed without the opt-in: %v", rep.Sections)
			}
			wantCerts := 2
			if users {
				wantCerts = 3
			}
			if len(rep.Certificates) != wantCerts {
				t.Fatalf("certificates: %d", len(rep.Certificates))
			}
			if ft.args[0]["Users"] != users {
				t.Fatalf("the opt-in did not reach the host: %v", ft.args[0])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

func TestPlatKeychainCertificates(t *testing.T) {
	a, b := platNewKey(t, "a"), platNewKey(t, "b")
	// A key block in the answer (none is expected from find-certificate)
	// is dropped unread.
	out := append(append(append([]byte(nil), a.certPEM...), b.keyPEM...), b.certPEM...)
	certs, trunc := platParseKeychainCertificates(out, platSystemKeychain, false)
	if len(certs) != 2 || trunc {
		t.Fatalf("certs %d", len(certs))
	}
	if certs[0].Location.Store != platSystemKeychain || certs[0].TrustAnchor || certs[0].CertificatePEM == "" {
		t.Fatalf("%+v", certs[0].Location)
	}
	keyAssertNoLeak(t, "keychain", certs, b.secret())
	anchors, _ := platParseKeychainCertificates(a.certPEM, platRootsKeychain, true)
	if len(anchors) != 1 || !anchors[0].TrustAnchor || anchors[0].CertificatePEM != "" {
		t.Fatalf("anchors: %+v", anchors)
	}
}

func TestPlatKeychainIdentities(t *testing.T) {
	a, b := platNewKey(t, "a"), platNewKey(t, "b")
	ha, hb := platThumb(a.certDER), platThumb(b.certDER)
	out := "Policy: X.509 Basic\n  Matching identities\n  1) " + ha + " \"Some Name\"\n  2) " + strings.ToLower(hb) +
		" \"Other\" (CSSMERR_TP_CERT_EXPIRED)\n     2 identities found\n\n  Valid identities only\n  1) " + ha + " \"Some Name\"\n     1 valid identities found\n"
	ids := platParseKeychainIdentities([]byte(out))
	if strings.Join(ids, ",") != ha+","+hb {
		t.Fatalf("identities: %v", ids)
	}
	if strings.Contains(strings.Join(ids, ""), "Name") {
		t.Fatal("a name was kept")
	}
	certs, _ := platParseKeychainCertificates(a.certPEM, "/k", false)
	keys, unmatched := platKeychainKeys("/k", certs, []string{ha, "0000000000000000000000000000000000000000"})
	if len(keys) != 1 || unmatched != 1 || *certs[0].HasPrivateKey != true || keys[0].Algorithm != "ECDSA" || keys[0].PublicKeySHA256 != certs[0].PublicKeySHA256 ||
		keys[0].Location.Store != "/k" || keys[0].Location.Alias != "" || keys[0].Provider != "macOS keychain" || keys[0].ProviderKind != ProviderKindSoftware {
		t.Fatalf("keys: %+v", keys)
	}
	if got := platParseKeychainIdentities([]byte("  Matching identities\n     0 identities found\n")); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
}

// platDarwinFake scripts the keychain commands on a fake macOS host.
func platDarwinFake(t *testing.T, local bool, sys, roots platKey, userKeychainDenied bool) *tgtFakeTarget {
	ft := newTgtFakeTarget(local)
	ft.script(platSh(platDarwinFDA), tgtResult{stdout: "no\n"})
	ft.script(platKeychainCertsArgv(platSystemKeychain), tgtResult{stdout: string(sys.certPEM)})
	ft.script(platKeychainIdentitiesArgv(platSystemKeychain), tgtResult{stdout: "  Matching identities\n  1) " + platThumb(sys.certDER) + " \"n\"\n"})
	ft.script(platKeychainCertsArgv(platRootsKeychain), tgtResult{stdout: string(roots.certPEM)})
	ft.script(platSh(platDarwinUserKeychains), tgtResult{stdout: "/Users/u1/Library/Keychains/login.keychain-db\n/etc/not-a-user\n"})
	user := "/Users/u1/Library/Keychains/login.keychain-db"
	if userKeychainDenied {
		ft.script(platKeychainCertsArgv(user), tgtResult{stderr: "security: SecKeychainSearchCopyNext: Operation not permitted", exit: 1})
	} else {
		ft.script(platKeychainCertsArgv(user), tgtResult{stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.", exit: 44})
		ft.script(platKeychainIdentitiesArgv(user), tgtResult{stdout: "  Matching identities\n     0 identities found\n"})
	}
	return ft
}

func TestPlatDarwinKeychains(t *testing.T) {
	sys, roots := platNewKey(t, "sys"), platNewKey(t, "root")
	for _, local := range []bool{true, false} {
		ft := platDarwinFake(t, local, sys, roots, true)
		c := tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin, HomeDirectories: true})
		platDarwinKeychains(t.Context(), c)
		c.registry.finish(c.report)
		rep := c.report
		if rep.Access.FullDiskAccess == nil || *rep.Access.FullDiskAccess {
			t.Fatalf("full disk access: %v", rep.Access.FullDiskAccess)
		}
		if rep.Sections[SectionCertificates] != SectionOK || rep.Sections[SectionHomeDirectories] != SectionPartial {
			t.Fatalf("sections %v", rep.Sections)
		}
		if !platErrorsContain(rep, SectionHomeDirectories, "Full Disk Access") {
			t.Fatalf("the reason does not name Full Disk Access: %+v", rep.Errors)
		}
		if len(rep.Certificates) != 2 || len(rep.PrivateKeys) != 1 || rep.PrivateKeys[0].Location.Store != platSystemKeychain {
			t.Fatalf("certs %d keys %+v", len(rep.Certificates), rep.PrivateKeys)
		}
		for _, call := range ft.recorded() {
			if strings.Contains(call, "/etc/not-a-user") {
				t.Fatal("a listed path outside /Users was used")
			}
		}

		// An empty login keychain is an answer, not a refusal.
		ft = platDarwinFake(t, local, sys, roots, false)
		c = tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin, HomeDirectories: true})
		platDarwinKeychains(t.Context(), c)
		if c.report.Sections[SectionHomeDirectories] != SectionOK {
			t.Fatalf("empty keychain: %v %+v", c.report.Sections, c.report.Errors)
		}

		// Without the opt-in no login keychain is listed.
		ft = platDarwinFake(t, local, sys, roots, false)
		c = tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
		platDarwinKeychains(t.Context(), c)
		if ft.called("run", strings.Join(platSh(platDarwinUserKeychains), " ")) {
			t.Fatal("login keychains listed without the opt-in")
		}
	}
}

func TestPlatDarwinNoSecurityTool(t *testing.T) {
	ft := newTgtFakeTarget(false) // nothing scripted: every command is missing
	c := tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
	platDarwinKeychains(t.Context(), c)
	if c.report.Sections[SectionCertificates] != SectionUnsupported {
		t.Fatalf("%v", c.report.Sections)
	}
}
