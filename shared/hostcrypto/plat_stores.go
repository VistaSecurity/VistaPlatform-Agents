package hostcrypto

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- a certificate thumbprint, as the keychain names it; not a security decision
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Platform certificate stores: the Windows certificate stores with the CNG
// and CAPI keys behind them, and the macOS keychains.
//
// What crosses: a certificate (public) and, for a certificate the store holds
// a key for, the key's METADATA: provider, algorithm, size, export policy. No
// program here opens a key for use, exports one, or reads a key container's
// name; a key is only ever described.

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

// platStoreMaxPerStore bounds the certificates read from one store.
const platStoreMaxPerStore = 2000

// platPSStores lists the certificate stores of LocalMachine and, with the
// home-directories opt-in, the collecting account's own "My" store (the
// other CurrentUser stores are views over the machine's, and AddressBook is
// other people's certificates). Per certificate: its thumbprint, its DER
// (RawData, the certificate alone) and HasPrivateKey; for a certificate
// with a key, stKey describes the key through the certificate's
// Get*PrivateKey handle: the provider's name, the algorithm, the size and
// the export POLICY. The handle is disposed unused: nothing is signed,
// decrypted or exported, and the container's name is never read.
const platPSStores = `$stRes = New-Object 'System.Collections.Generic.List[object]'
function stKey($skC) {
  $skR = [pscustomobject]@{ Provider = ''; Algorithm = ''; Size = 0; Export = ''; Hardware = $null; Error = '' }
  $skK = $null
  try {
    $skK = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($skC)
    if ($null -eq $skK) { $skK = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($skC) }
    if ($null -eq $skK) { $skK = [System.Security.Cryptography.X509Certificates.DSACertificateExtensions]::GetDSAPrivateKey($skC) }
    if ($null -eq $skK) { $skR.Error = 'other'; return $skR }
    $skT = [string]$skK.GetType().Name
    if ($skT.EndsWith('Cng', [StringComparison]::Ordinal)) {
      $skN = $skK.Key
      $skR.Provider = [string]$skN.Provider.Provider
      $skR.Algorithm = [string]$skN.Algorithm.Algorithm
      $skR.Size = [int]$skN.KeySize
      $skR.Export = [string]$skN.ExportPolicy
    } else {
      $skI = $skK.CspKeyContainerInfo
      $skR.Provider = [string]$skI.ProviderName
      $skR.Algorithm = $skT
      $skR.Size = [int]$skK.KeySize
      if ($skI.Exportable) { $skR.Export = 'AllowExport' } else { $skR.Export = 'None' }
      $skR.Hardware = [bool]$skI.HardwareDevice
    }
  } catch { $skR.Error = (plErr $_.Exception) }
  finally { if ($null -ne $skK) { try { $skK.Dispose() } catch { $skT = '' } } }
  return $skR
}
$stLocs = New-Object 'System.Collections.Generic.List[string]'
[void]$stLocs.Add('LocalMachine')
if ($a.Users) { [void]$stLocs.Add('CurrentUser') }
foreach ($stLoc in $stLocs) {
  $stNames = New-Object 'System.Collections.Generic.List[string]'
  if ($stLoc -ceq 'CurrentUser') { [void]$stNames.Add('My') } else {
    try { foreach ($stS in @(Get-ChildItem -LiteralPath ('Cert:\' + $stLoc))) { [void]$stNames.Add([string]$stS.Name) } }
    catch { $stE = (plErr $_.Exception); [void]$stRes.Add([pscustomobject]@{ Store = ('Cert:\' + $stLoc); Error = $stE; Truncated = $false; Certs = @() }); continue }
  }
  foreach ($stName in $stNames) {
    $stCerts = New-Object 'System.Collections.Generic.List[object]'
    $stE = ''
    $stTrunc = $false
    $stStore = $null
    try {
      $stStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($stName, [System.Security.Cryptography.X509Certificates.StoreLocation]$stLoc)
      $stStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
      foreach ($stC in $stStore.Certificates) {
        if ($stCerts.Count -ge [int]$a.Max) { $stTrunc = $true; break }
        $stKey = $null
        if ($stC.HasPrivateKey) { $stKey = stKey $stC }
        [void]$stCerts.Add([pscustomobject]@{ Der = [Convert]::ToBase64String($stC.RawData); HasKey = [bool]$stC.HasPrivateKey; Key = $stKey })
      }
    } catch { $stE = (plErr $_.Exception) }
    finally { if ($null -ne $stStore) { $stStore.Close() } }
    [void]$stRes.Add([pscustomobject]@{ Store = ('Cert:\' + $stLoc + '\' + $stName); Error = $stE; Truncated = $stTrunc; Certs = $stCerts.ToArray() })
  }
}
plOut ([pscustomobject]@{ Elevated = (plElevated); Stores = $stRes.ToArray() })
`

type platStoreArgs struct {
	Users bool `json:"Users"`
	Max   int  `json:"Max"`
}

// platWinKey is the key metadata stKey answers. Only these fields are
// decoded; anything else in the answer is dropped by the decoder.
type platWinKey struct {
	Provider  string `json:"Provider"`
	Algorithm string `json:"Algorithm"`
	Size      int    `json:"Size"`
	Export    string `json:"Export"`
	Hardware  *bool  `json:"Hardware"`
	Error     string `json:"Error"`
}

type platWinCert struct {
	Der    string      `json:"Der"`
	HasKey bool        `json:"HasKey"`
	Key    *platWinKey `json:"Key"`
}

type platWinStore struct {
	Store     string          `json:"Store"`
	Error     string          `json:"Error"`
	Truncated bool            `json:"Truncated"`
	Certs     json.RawMessage `json:"Certs"`
}

type platWinStoresAnswer struct {
	Elevated *bool           `json:"Elevated"`
	Stores   json.RawMessage `json:"Stores"`
}

// platWinStoreResult is what one stores answer amounts to.
type platWinStoreResult struct {
	Elevated *bool
	Certs    []Certificate
	Keys     []PrivateKey
	// Problems are stores that could not be read (or were cut short), by
	// name, with why.
	Problems []error
	// Truncated names the stores cut at the per-store bound.
	Truncated []string
	// UserStores is true when a CurrentUser store was read.
	UserStores bool
}

// platWinAnchorStores are the stores whose members are trust anchors.
var platWinAnchorStores = map[string]bool{
	"Root": true, "AuthRoot": true, "SmartCardRoot": true, "TrustedAppRoot": true,
	"FlightRoot": true, "TestSignRoot": true, "PasspointTrustedRoots": true,
}

// platParseWindowsStores parses the stores program's answer. Each certificate is
// re-parsed from its DER with [ParseCertificateDER], so what is kept is a
// certificate's description and its re-encoding, never the bytes as they
// arrived: a "Der" that is not a certificate is dropped. Each key is
// described from named fields only.
func platParseWindowsStores(b []byte) (platWinStoreResult, error) {
	var res platWinStoreResult
	var ans platWinStoresAnswer
	if err := json.Unmarshal(b, &ans); err != nil {
		return res, errors.New("hostcrypto: unreadable certificate store answer")
	}
	res.Elevated = ans.Elevated
	stores, err := psArray[platWinStore](ans.Stores)
	if err != nil {
		return res, errors.New("hostcrypto: unreadable certificate store answer")
	}
	for _, st := range stores {
		if !strings.HasPrefix(st.Store, `Cert:\`) || len(st.Store) > 256 {
			continue
		}
		user := strings.HasPrefix(st.Store, `Cert:\CurrentUser\`)
		if err := platPSError(st.Store, st.Error); err != nil {
			res.Problems = append(res.Problems, err)
			continue
		}
		if st.Truncated {
			res.Truncated = append(res.Truncated, st.Store)
		}
		if user {
			res.UserStores = true
		}
		certs, err := psArray[platWinCert](st.Certs)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Errorf("%s: unreadable answer", st.Store))
			continue
		}
		name := st.Store[strings.LastIndexByte(st.Store, '\\')+1:]
		anchor := platWinAnchorStores[name] && !user
		for _, wc := range certs {
			der, err := base64.StdEncoding.DecodeString(wc.Der)
			if err != nil {
				continue
			}
			cert, err := ParseCertificateDER(der)
			if err != nil {
				continue
			}
			cert.Location = Location{Store: st.Store, FoundBy: FoundByPlatformStore}
			cert.TrustAnchor = anchor
			if anchor {
				cert.CertificatePEM = ""
			}
			has := wc.HasKey
			cert.HasPrivateKey = &has
			res.Certs = append(res.Certs, cert)
			if !has {
				continue
			}
			res.Keys = append(res.Keys, platWinPrivateKey(st.Store, cert, wc.Key))
		}
	}
	return res, nil
}

// platWinPrivateKey describes the key behind a store certificate. It sits in
// the certificate's store and pairs with the certificate by
// PublicKeySHA256; the algorithm and curve are the certificate's (the key is
// its pair), the size the provider's where it said one.
func platWinPrivateKey(store string, cert Certificate, k *platWinKey) PrivateKey {
	pk := PrivateKey{
		Location:        Location{Store: store, FoundBy: FoundByPlatformStore},
		Format:          KeyFormatPlatformStore,
		Algorithm:       cert.KeyAlgorithm,
		SizeBits:        cert.KeySize,
		Curve:           cert.Curve,
		PublicKeySHA256: cert.PublicKeySHA256,
		ProviderKind:    ProviderKindUnknown,
	}
	if k == nil || k.Error != "" || k.Provider == "" {
		pk.Unknown = "the key's provider could not be read"
		if k != nil && k.Error == "denied" {
			pk.Unknown = "the key's provider could not be read by this account"
		}
		return pk
	}
	pk.Provider = platCap(k.Provider, 128)
	pk.ProviderKind = platWinProviderKind(k.Provider, k.Hardware)
	pk.Protection = map[string]string{ProviderKindTPM: KeyProtectionTPM, ProviderKindSmartCard: KeyProtectionHSM, ProviderKindSoftware: KeyProtectionSoftware}[pk.ProviderKind]
	if k.Size > 0 && k.Size <= 65536 {
		pk.SizeBits = k.Size
	}
	if k.Export != "" {
		e := strings.Contains(k.Export, "AllowExport") || strings.Contains(k.Export, "AllowPlaintextExport")
		pk.Exportable = &e
	}
	return pk
}

// platWinProviderKind says what a provider keeps its keys in.
func platWinProviderKind(provider string, hardware *bool) string {
	p := strings.ToLower(provider)
	switch {
	case p == "microsoft platform crypto provider":
		return ProviderKindTPM
	case strings.Contains(p, "smart card"), hardware != nil && *hardware:
		return ProviderKindSmartCard
	case p == "":
		return ProviderKindUnknown
	}
	return ProviderKindSoftware
}

func platCap(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// platWindowsStores runs pass 1's Windows store part.
func platWindowsStores(ctx context.Context, c *collection) {
	b, err := platPS(ctx, c.target, platPSStores, platStoreArgs{Users: c.opts.HomeDirectories, Max: platStoreMaxPerStore})
	if err != nil {
		c.partial(SectionCertificates, fmt.Errorf("certificate stores: %w", err))
		c.partial(SectionPrivateKeys, fmt.Errorf("certificate stores: %w", err))
		return
	}
	res, err := platParseWindowsStores(b)
	if err != nil {
		c.partial(SectionCertificates, err)
		c.partial(SectionPrivateKeys, err)
		return
	}
	platSetElevated(c, res.Elevated)
	platRecordStores(c, res.Certs, res.Keys, res.Problems, res.Truncated)
	if c.opts.HomeDirectories {
		// Only the collecting account's own store can be opened; another
		// user's needs that user's profile loaded.
		c.partial(SectionHomeDirectories, errors.New("certificate stores: only the collecting account's own CurrentUser\\My store is read"))
	}
}

// platRecordStores adds store certificates and keys to the registry and
// marks the two sections.
func platRecordStores(c *collection, certs []Certificate, keys []PrivateKey, problems []error, truncated []string) {
	for _, cert := range certs {
		c.registry.addCertificate(cert)
	}
	for _, k := range keys {
		c.registry.addPrivateKey(k)
	}
	for _, p := range problems {
		c.partial(SectionCertificates, p)
		c.mark(SectionPrivateKeys, SectionPartial)
	}
	for _, s := range truncated {
		c.limit(SectionCertificates, "max_records", fmt.Sprintf("%s: kept the first %d certificates", s, platStoreMaxPerStore))
	}
	c.mark(SectionCertificates, SectionOK)
	c.mark(SectionPrivateKeys, SectionOK)
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

const (
	platSystemKeychain = "/Library/Keychains/System.keychain"
	platRootsKeychain  = "/System/Library/Keychains/SystemRootCertificates.keychain"
)

// platDarwinUserKeychains lists the login keychains, one path per line. A
// path is printed, never a keychain's contents.
const platDarwinUserKeychains = `for f in /Users/*/Library/Keychains/login.keychain-db /Users/*/Library/Keychains/login.keychain; do [ -f "$f" ] && printf '%s\n' "$f"; done; exit 0`

// platDarwinFDA answers whether the collector has Full Disk Access: it reads
// one byte of the system TCC database, which TCC guards, to /dev/null. Only
// the answer is printed.
const platDarwinFDA = `if head -c 1 "/Library/Application Support/com.apple.TCC/TCC.db" >/dev/null 2>&1; then echo yes; else echo no; fi`

// platKeychainCertsArgv lists a keychain's certificates as PEM. Certificates
// are not encrypted in a keychain: this needs no unlock and never prompts.
func platKeychainCertsArgv(keychain string) []string {
	return []string{"security", "find-certificate", "-a", "-p", keychain}
}

// platKeychainIdentitiesArgv lists the identities (a certificate with its
// private key) a keychain holds, by the certificate's SHA-1 hash and name.
// It reads no key and never prompts.
func platKeychainIdentitiesArgv(keychain string) []string {
	return []string{"security", "find-identity", keychain}
}

// platParseKeychainCertificates parses `security find-certificate -a -p`. Only
// certificate blocks are kept; any other block (none is expected) is
// dropped unread.
func platParseKeychainCertificates(out []byte, keychain string, anchors bool) (certs []Certificate, truncated bool) {
	pc := ParsePEMFile(out, PEMLimits{})
	for _, cert := range pc.Certificates {
		cert.Location = Location{Store: keychain, FoundBy: FoundByPlatformStore}
		cert.TrustAnchor = anchors
		if anchors {
			cert.CertificatePEM = ""
		}
		certs = append(certs, cert)
	}
	return certs, pc.Truncated
}

var platIdentityRE = regexp.MustCompile(`^\s*\d+\)\s+([0-9A-Fa-f]{40})(\s|$)`)

// platParseKeychainIdentities parses `security find-identity`: the SHA-1 hashes
// of the certificates in its "Matching identities" section. Names are not
// kept.
func platParseKeychainIdentities(out []byte) []string {
	var hashes []string
	seen := map[string]bool{}
	in := false
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Matching identities"):
			in = true
			continue
		case strings.HasPrefix(t, "Valid identities only"), strings.HasPrefix(t, "Policy:"):
			in = false
			continue
		}
		if !in {
			continue
		}
		if m := platIdentityRE.FindStringSubmatch(line); m != nil {
			h := strings.ToUpper(m[1])
			if !seen[h] && len(hashes) < platStoreMaxPerStore {
				seen[h] = true
				hashes = append(hashes, h)
			}
		}
	}
	return hashes
}

// platKeychainKeys pairs identity hashes with the keychain's certificates:
// each pair is a certificate with HasPrivateKey and a platform-store key in
// the keychain, paired with the certificate by PublicKeySHA256. It also
// returns how many identities named a certificate the keychain did not list
// (they are counted, not recorded: without the certificate nothing would
// tell one such key from another).
func platKeychainKeys(keychain string, certs []Certificate, identities []string) ([]PrivateKey, int) {
	have := map[string]bool{}
	for _, h := range identities {
		have[h] = true
	}
	var keys []PrivateKey
	matched := map[string]bool{}
	for i := range certs {
		h := platCertSHA1(certs[i])
		has := have[h]
		certs[i].HasPrivateKey = &has
		if !has || matched[h] {
			continue
		}
		matched[h] = true
		keys = append(keys, PrivateKey{
			Location:        Location{Store: keychain, FoundBy: FoundByPlatformStore},
			Format:          KeyFormatPlatformStore,
			Algorithm:       certs[i].KeyAlgorithm,
			SizeBits:        certs[i].KeySize,
			Curve:           certs[i].Curve,
			Protection:      KeyProtectionSoftware,
			Provider:        "macOS keychain",
			ProviderKind:    ProviderKindSoftware,
			PublicKeySHA256: certs[i].PublicKeySHA256,
		})
	}
	unmatched := 0
	for _, h := range identities {
		if !matched[h] {
			unmatched++
		}
	}
	return keys, unmatched
}

// platCertSHA1 is a certificate's SHA-1 hash, from its re-encoding, as the
// keychain names identities.
func platCertSHA1(c Certificate) string {
	der := platCertDER(c)
	if der == nil {
		return ""
	}
	sum := sha1.Sum(der) // #nosec G401 -- an identifier, as the keychain prints it
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// platCertDER is the DER inside a Certificate's PEM, or nil.
func platCertDER(c Certificate) []byte {
	block, _ := pem.Decode([]byte(c.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return block.Bytes
}

// platDarwinKeychains runs pass 1's keychain part.
func platDarwinKeychains(ctx context.Context, c *collection) {
	// Full Disk Access first: it decides how a refused read is explained.
	if out, _, exit, err := platRun(ctx, c.target, platSh(platDarwinFDA)); err == nil && exit == 0 {
		v := strings.TrimSpace(string(out)) == "yes"
		c.mu.Lock()
		c.report.Access.FullDiskAccess = &v
		c.mu.Unlock()
	}

	type kc struct {
		path    string
		anchors bool
		user    bool
	}
	list := []kc{{platSystemKeychain, false, false}, {platRootsKeychain, true, false}}
	if c.opts.HomeDirectories {
		out, stderr, exit, err := platRun(ctx, c.target, platSh(platDarwinUserKeychains))
		switch {
		case err != nil:
			c.partial(SectionHomeDirectories, fmt.Errorf("login keychains: %w", err))
		case exit != 0:
			c.partial(SectionHomeDirectories, platStderr("login keychains", stderr, exit))
		default:
			for _, p := range strings.Split(string(out), "\n") {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "/Users/") && len(list) < 512 {
					list = append(list, kc{p, false, true})
				}
			}
		}
	}

	var problems []error
	var truncated []string
	var certs []Certificate
	var keys []PrivateKey
	userProblem := false
	for _, k := range list {
		if c.timeUp(ctx, SectionCertificates) {
			break
		}
		out, stderr, exit, err := platRun(ctx, c.target, platKeychainCertsArgv(k.path))
		if err == nil && exit != 0 && !platKeychainEmpty(stderr) {
			err = platStderr("security find-certificate "+k.path, stderr, exit)
		}
		if err != nil {
			if errors.Is(err, errPlatNoTool) {
				c.mark(SectionCertificates, SectionUnsupported)
				c.note(SectionCertificates, fmt.Errorf("keychains: %w", err))
				return
			}
			if k.user {
				userProblem = true
				c.note(SectionHomeDirectories, platDarwinReason(c, err))
				continue
			}
			problems = append(problems, platDarwinReason(c, err))
			continue
		}
		kcCerts, trunc := platParseKeychainCertificates(out, k.path, k.anchors)
		if trunc {
			truncated = append(truncated, k.path)
		}
		if !k.anchors {
			idOut, idErr, idExit, err := platRun(ctx, c.target, platKeychainIdentitiesArgv(k.path))
			if err == nil && idExit == 0 {
				kk, unmatched := platKeychainKeys(k.path, kcCerts, platParseKeychainIdentities(idOut))
				keys = append(keys, kk...)
				if unmatched > 0 {
					c.partial(SectionPrivateKeys, fmt.Errorf("%s: %d identities name a certificate the keychain did not list; their keys are not described", k.path, unmatched))
				}
			} else if err == nil {
				problems = append(problems, platStderr("security find-identity "+k.path, idErr, idExit))
			} else {
				problems = append(problems, err)
			}
		}
		certs = append(certs, kcCerts...)
	}
	platRecordStores(c, certs, keys, problems, truncated)
	if c.opts.HomeDirectories {
		if userProblem {
			c.mark(SectionHomeDirectories, SectionPartial)
		} else {
			c.mark(SectionHomeDirectories, SectionOK)
		}
	}
}

// platKeychainEmpty: find-certificate exits non-zero on a keychain with no
// certificate, saying so; that is an answer, not a failure.
func platKeychainEmpty(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("could not be found"))
}

// platDarwinReason says why a keychain was refused, naming Full Disk Access
// when the collector lacks it.
func platDarwinReason(c *collection, err error) error {
	c.mu.Lock()
	fda := c.report.Access.FullDiskAccess
	c.mu.Unlock()
	if fda != nil && !*fda {
		return fmt.Errorf("%w (the collector has no Full Disk Access)", err)
	}
	return err
}
