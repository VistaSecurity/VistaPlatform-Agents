// Package hostcrypto finds the cryptographic material and configuration on a
// host and describes it: certificates, private keys, keystores, SSH material,
// configured protocol and cipher policy, cryptographic libraries, and the
// platform protection the host relies on (disk encryption, TPM, Secure Boot).
//
// It is the on-host counterpart of what the sensor learns from the network:
// the sensor sees what an endpoint negotiates, this package sees what sits on
// disk behind it, including what nothing serves yet. Design:
// docs/design/host-crypto.md.
//
// One collector, two modes, through a [Target]. LOCAL mode runs on the host as
// the agent. REMOTE mode reaches a host over SSH with stored credentials and
// is deliberately weaker: see "What never leaves the host" below.
//
// # What never leaves the host
//
// Posture, never key material. A [Report] carries what an item IS (its
// algorithm, size, whether it is encrypted, who can read it, what refers to
// it) and a hash of its PUBLIC half. It never carries a private key, a
// passphrase, a keystore password, a shared secret or the contents of a
// keytab entry. Concretely, and enforced by tests:
//
//   - In local mode a private key file is parsed in the agent's memory and
//     only the fields of [PrivateKey] are kept.
//   - In remote mode NO BYTE of a private key file crosses the connection.
//     The collector learns what a file is from [Target.Identify] (a file's
//     magic number and its PEM labels) and, where the host has the tool,
//     from a command that runs there and prints only a public key. The
//     [Target] wrapper refuses a read of anything not identified as public.
//   - A configuration file is projected onto an allowlist of directives per
//     product. Nothing is kept because it "looked crypto-related".
//   - No command transcript is stored. A step that fails records its name and
//     a bounded message.
//
// # Honest sections
//
// Every section is independently fallible and says which it was: read, read in
// part, failed, not possible on this platform, or switched off. Consumers MUST
// read [Report.Sections] before treating an empty list as an answer.
//
// # This package must stay pure Go and CGO-free
//
// It is compiled into the device agent for Linux, Windows and macOS. It must
// not import anything platform-internal.
package hostcrypto

import (
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Section outcomes. The first four are host inventory's, with the same
// meaning; Skipped is this package's.
const (
	SectionOK          = hostinventory.SectionOK
	SectionFailed      = hostinventory.SectionFailed
	SectionPartial     = hostinventory.SectionPartial
	SectionUnsupported = hostinventory.SectionUnsupported
	// SectionSkipped: the operator has not turned this on (home directories,
	// default keystore passwords) or the mode cannot do it (the content sweep
	// in remote mode). Not a failure, and no basis for retiring anything.
	SectionSkipped = "skipped"
)

// Section names: the keys of [Report.Sections] and the Step of a [StepError].
const (
	SectionPlatform       = "platform"
	SectionCertificates   = "certificates"
	SectionPrivateKeys    = "private_keys"
	SectionKeystores      = "keystores"
	SectionSSH            = "ssh"
	SectionConfigs        = "configs"
	SectionLibraries      = "libraries"
	SectionDiskEncryption = "disk_encryption"
	SectionTPM            = "tpm"
	SectionSecureBoot     = "secure_boot"
	SectionTokens         = "tokens"
	// SectionFIPSMode is the operating system's FIPS switch
	// ([Protection.FIPSMode]): unsupported where the platform has none.
	SectionFIPSMode = "fips_mode"
	// SectionProcesses is pass 3: which running process holds which library,
	// keystore or key file open, and which socket it listens on.
	SectionProcesses = "processes"
	// SectionSweep is pass 4: the bounded sweep that identifies files by
	// content rather than by name.
	SectionSweep = "sweep"
	// SectionHomeDirectories is the per-user part of every pass. Off unless
	// the operator opts in.
	SectionHomeDirectories = "home_directories"
)

// How an item was found. One item may be found more than once; the strongest
// (earliest in this list) is recorded.
const (
	FoundByProcess       = "process"        // a running process holds it open
	FoundByConfig        = "config"         // a configuration file names it
	FoundByKnownLocation = "known_location" // a place this platform keeps such things
	FoundBySweep         = "sweep"          // identified by content in the sweep
	FoundByPlatformStore = "platform_store" // a Windows store, a macOS keychain
	// FoundByNeighbour: in the directory of a file a configuration or a
	// process named, found when that directory was covered (see Coverage).
	FoundByNeighbour = "neighbour"
)

// Report is one host crypto collection.
type Report struct {
	// Collected is when the collection finished, in UTC.
	Collected time.Time `json:"collected"`
	// Mode is local or remote.
	Mode hostinventory.Mode `json:"mode"`
	// Platform is "linux", "darwin" or "windows".
	Platform string `json:"platform"`
	// AgentID is the reporting agent's id, in LOCAL mode only.
	AgentID string `json:"agent_id,omitempty"`
	// Access says how much the collector was allowed to see.
	Access Access `json:"access"`
	// Scope records what the operator asked for, so a reader can tell "not
	// found" from "not looked for".
	Scope Scope `json:"scope"`

	Certificates []Certificate   `json:"certificates,omitempty"`
	PrivateKeys  []PrivateKey    `json:"private_keys,omitempty"`
	Keystores    []Keystore      `json:"keystores,omitempty"`
	SSH          SSH             `json:"ssh"`
	Configs      []CryptoConfig  `json:"configs,omitempty"`
	Libraries    []CryptoLibrary `json:"libraries,omitempty"`
	// Protection is absent when no protection fact was read (omitzero):
	// an empty object never stands for "nothing to report".
	Protection Protection `json:"protection,omitzero"`

	// Sections is the outcome of every section, by name. See the Section
	// constants.
	Sections map[string]string `json:"sections"`
	// Errors lists the steps that failed or saw only part of the answer.
	Errors []StepError `json:"errors,omitempty"`
	// Limits lists every bound that cut a section short, so a truncated list
	// never reads as a complete one.
	Limits []LimitHit `json:"limits,omitempty"`

	// Coverage names the directories this collection saw completely. It is
	// what allows a reader to retire a file-based item that is no longer
	// there, whatever its section says. Absent when nothing was covered.
	Coverage Coverage `json:"coverage,omitzero"`
}

// Access is what the collecting account could reach.
type Access struct {
	// Elevated is true when the collector ran as root, SYSTEM or an
	// administrator with an elevated token. Nil when it could not tell.
	Elevated *bool `json:"elevated,omitempty"`
	// FullDiskAccess is macOS only: whether the collector could read the
	// protected locations (TCC). Nil elsewhere and when it could not tell.
	FullDiskAccess *bool `json:"full_disk_access,omitempty"`
}

// Scope is what one collection was asked to cover.
type Scope struct {
	HomeDirectories          bool     `json:"home_directories"`
	DefaultKeystorePasswords bool     `json:"default_keystore_passwords"`
	ExcludedPaths            []string `json:"excluded_paths,omitempty"`
	SweepRoots               []string `json:"sweep_roots,omitempty"`
}

// Location is where an item is and who can reach it. Every on-disk item has
// one.
type Location struct {
	// Path is the file's absolute path. For an item inside a platform store it
	// is empty and Store is set.
	Path string `json:"path,omitempty"`
	// Store names a platform store: `Cert:\LocalMachine\My`, a macOS keychain
	// path. A store key's provider is in [PrivateKey.Provider].
	Store string `json:"store,omitempty"`
	// Container is the keystore file an entry lives in, with Alias its name
	// there. Empty for a file that is the item itself.
	Container string `json:"container,omitempty"`
	Alias     string `json:"alias,omitempty"`

	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
	// Mode is the Unix permission bits in octal ("0600"). Empty on Windows.
	Mode string `json:"mode,omitempty"`
	// WorldReadable and GroupReadable are the answer the finding rules need,
	// worked out per platform (mode bits on Unix; the ACL granting read to
	// Everyone, Users or Authenticated Users on Windows). Nil when the
	// permissions could not be read.
	WorldReadable *bool `json:"world_readable,omitempty"`
	GroupReadable *bool `json:"group_readable,omitempty"`

	SizeBytes  int64  `json:"size_bytes,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"` // RFC 3339, UTC

	// FoundBy is one of the FoundBy constants.
	FoundBy string `json:"found_by"`
	// UsedBy lists what refers to the item. Empty means nothing the collector
	// looked at refers to it NOW; it saw one moment, not the item's life.
	UsedBy []Usage `json:"used_by,omitempty"`
}

// Usage is one thing that refers to an item.
type Usage struct {
	// Kind is "config" (a configuration file names it), "process" (a running
	// process holds it open) or "listener" (that process listens on a port).
	Kind string `json:"kind"`
	// ConfigPath and Directive are set for kind "config". ConfigPath is the
	// file that holds the directive: an included file when the directive is
	// in one, with RootConfigPath then naming the configuration that
	// includes it (empty when ConfigPath is itself the root).
	ConfigPath     string `json:"config_path,omitempty"`
	RootConfigPath string `json:"root_config_path,omitempty"`
	Directive      string `json:"directive,omitempty"`
	// Product and Context are the configuration's (CryptoConfig.Product and
	// .Context): what reads it, and the server block, Match block or section
	// whose directive names the item.
	Product string `json:"product,omitempty"`
	Context string `json:"context,omitempty"`
	// Process is the executable's name, set for "process" and "listener".
	Process string `json:"process,omitempty"`
	// Address, Port and Transport are set for kind "listener".
	Address   string `json:"address,omitempty"`
	Port      int    `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
}

// Certificate is one certificate found on the host. The fields follow the
// managed protocol's certificate entry, so the platform reads it as it reads a
// certificate from any other collector.
type Certificate struct {
	Location Location `json:"location"`

	SubjectDN         string   `json:"subject_dn,omitempty"`
	IssuerDN          string   `json:"issuer_dn,omitempty"`
	SerialNumber      string   `json:"serial_number,omitempty"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	NotBefore         string   `json:"not_before,omitempty"`
	NotAfter          string   `json:"not_after,omitempty"`
	KeyAlgorithm      string   `json:"key_algorithm,omitempty"`
	KeySize           int      `json:"key_size,omitempty"`
	Curve             string   `json:"curve,omitempty"`
	SignatureAlg      string   `json:"signature_alg,omitempty"`
	IsCA              bool     `json:"is_ca"`
	SelfSigned        bool     `json:"self_signed"`
	DNSNames          []string `json:"dns_names,omitempty"`
	IPAddresses       []string `json:"ip_addresses,omitempty"`
	// PublicKeySHA256 is the SHA-256 of the certificate's
	// SubjectPublicKeyInfo, in hex. It is what pairs a certificate with a
	// private key ([PrivateKey.PublicKeySHA256]) and with a certificate the
	// sensor saw served.
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	// TrustAnchor is true for a member of a system or application trust
	// store. Trust anchors carry no CertificatePEM: there are hundreds per
	// host and the fingerprint identifies them.
	TrustAnchor bool `json:"trust_anchor"`
	// CertificatePEM is the certificate itself. A certificate is public.
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// HasPrivateKey is set for a platform-store certificate: whether the store
	// holds its private key. Nil for a file.
	HasPrivateKey *bool `json:"has_private_key,omitempty"`
}

// Private key formats.
const (
	KeyFormatPKCS1         = "pkcs1"          // PEM "RSA PRIVATE KEY"
	KeyFormatSEC1          = "sec1"           // PEM "EC PRIVATE KEY"
	KeyFormatPKCS8         = "pkcs8"          // PEM "PRIVATE KEY" / "ENCRYPTED PRIVATE KEY", or DER
	KeyFormatDSA           = "dsa"            // PEM "DSA PRIVATE KEY"
	KeyFormatOpenSSH       = "openssh"        // PEM "OPENSSH PRIVATE KEY"
	KeyFormatPuTTY         = "putty"          // PuTTY-User-Key-File-2/3
	KeyFormatPGP           = "pgp"            // an OpenPGP secret key
	KeyFormatSSH1          = "ssh1"           // "SSH PRIVATE KEY FILE FORMAT 1.1", legacy SSH-1 (RSA only)
	KeyFormatPlatformStore = "platform_store" // CNG, CAPI, keychain
)

// Where a private key's bytes live.
const (
	KeyProtectionFile     = "file"     // a file; see Encrypted
	KeyProtectionSoftware = "software" // an OS key store, software-backed
	KeyProtectionTPM      = "tpm"
	KeyProtectionHSM      = "hsm"     // a PKCS#11 token or network HSM
	KeyProtectionEnclave  = "enclave" // Secure Enclave
)

// What a platform-store key's provider keeps it in.
const (
	ProviderKindSoftware      = "software"
	ProviderKindTPM           = "tpm"
	ProviderKindSmartCard     = "smartcard"
	ProviderKindSecureEnclave = "secure-enclave"
	ProviderKindUnknown       = "unknown" // the provider could not be read
)

// PrivateKey describes one private key. It never holds the key.
type PrivateKey struct {
	Location Location `json:"location"`

	// Role is what the key is for where that is certain: "ssh_host_key",
	// "ssh_user_key", "tls", "pgp". Empty otherwise.
	Role   string `json:"role,omitempty"`
	Format string `json:"format"`
	// Algorithm is the catalogue's name for the key type: "RSA", "ECDSA",
	// "Ed25519", "DSA", "ML-DSA-65"... Empty when the key is encrypted in a
	// format that hides it (encrypted PKCS#8) and Unknown says why.
	Algorithm string `json:"algorithm,omitempty"`
	SizeBits  int    `json:"size_bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
	// Encrypted says whether the key is protected by a passphrase. Nil when
	// the collector could not tell.
	Encrypted *bool `json:"encrypted,omitempty"`
	// Encryption names how, where the format says: "aes-256-cbc",
	// "bcrypt+aes256-ctr", "PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC)".
	Encryption string `json:"encryption,omitempty"`
	// Protection is one of the KeyProtection constants.
	Protection string `json:"protection"`
	// Exportable is Windows and keychain only: whether the store lets the key
	// be exported. Nil elsewhere.
	Exportable *bool `json:"exportable,omitempty"`
	// Provider is a platform-store key's provider, as the platform names it:
	// "Microsoft Software Key Storage Provider", "Microsoft Platform Crypto
	// Provider", "Microsoft Enhanced Cryptographic Provider v1.0", "macOS
	// keychain". Empty for a file.
	Provider string `json:"provider,omitempty"`
	// ProviderKind is one of the ProviderKind constants. Empty for a file.
	ProviderKind string `json:"provider_kind,omitempty"`
	// PublicKeySHA256 is the SHA-256 of the key's SubjectPublicKeyInfo, in
	// hex: the same value a matching [Certificate] carries. Empty when the
	// public half could not be derived without the passphrase.
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	// SSHFingerprint is the OpenSSH "SHA256:..." fingerprint, for SSH keys.
	SSHFingerprint string `json:"ssh_fingerprint,omitempty"`
	// Unknown explains, in a few words, a field left empty: "encrypted;
	// algorithm not readable without the passphrase", "openssl not installed
	// on the remote host".
	Unknown string `json:"unknown,omitempty"`
}

// Keystore types.
const (
	KeystoreJKS      = "jks"
	KeystoreJCEKS    = "jceks"
	KeystorePKCS12   = "pkcs12"
	KeystoreBCFKS    = "bcfks"
	KeystoreBKS      = "bks"
	KeystoreNSS      = "nss"      // cert9.db + key4.db, or the legacy cert8/key3
	KeystoreGnuPG    = "gnupg"    // a GnuPG home
	KeystoreKeytab   = "keytab"   // a Kerberos keytab
	KeystoreKeychain = "keychain" // a macOS keychain file
	KeystoreUBER     = "uber"     // Bouncy Castle UBER
)

// How a keystore was opened.
const (
	OpenedNot             = "not_opened"       // its protection needs a password the collector does not have (what it states in clear may still be listed)
	OpenedWithoutPassword = "no_password"      // it needs none: the empty password opens its protection, or nothing in it is protected (a keytab)
	OpenedDefaultPassword = "default_password" // a well-known default opened it (opt-in)
)

// Keystore is one container of keys and certificates.
type Keystore struct {
	Location Location `json:"location"`
	Type     string   `json:"type"`
	// Opened is one of the Opened constants.
	Opened string `json:"opened"`
	// DefaultPassword is the answer to "does a well-known default password
	// open this?". Nil unless the operator opted in to trying. The password
	// itself is never recorded, only that one worked.
	DefaultPassword *bool `json:"default_password,omitempty"`
	// Protection describes how the container protects its contents, where the
	// format says without a password: "PBES2 (PBKDF2-HMAC-SHA256, 10000
	// iterations, AES-256-CBC), MAC HMAC-SHA256", "JKS proprietary (SHA-1)".
	Protection string `json:"protection,omitempty"`
	// EntryCount is how many entries the container has, when it could be
	// counted. Nil when it could not.
	EntryCount *int            `json:"entry_count,omitempty"`
	Entries    []KeystoreEntry `json:"entries,omitempty"`
	// Unknown explains, in a few words, why the contents are empty or
	// incomplete: "remote: entries are not read", "a platform store; its
	// contents are read from the store".
	Unknown string `json:"unknown,omitempty"`
}

// KeystoreEntry is one entry of a keystore.
type KeystoreEntry struct {
	Alias string `json:"alias,omitempty"`
	// Kind is "private_key", "certificate", "secret_key"; for a keytab
	// "kerberos_key"; for an OpenPGP keyring "pgp_public_key" or
	// "pgp_public_subkey".
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm,omitempty"`
	SizeBits  int    `json:"size_bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
	// CertificateFingerprint is the SHA-256 of the entry's (leaf) certificate.
	// The certificate itself is in [Report.Certificates] with this keystore
	// as its Location.Container.
	CertificateFingerprint string `json:"certificate_fingerprint,omitempty"`
	PublicKeySHA256        string `json:"public_key_sha256,omitempty"`
	// Principal, KVNO and EncryptionType are keytab fields. The key is not
	// read.
	Principal      string `json:"principal,omitempty"`
	KVNO           int    `json:"kvno,omitempty"`
	EncryptionType string `json:"encryption_type,omitempty"`
}

// SSH is the host's SSH material beyond its private keys, which are in
// [Report.PrivateKeys] with Role "ssh_host_key" or "ssh_user_key", and its
// server and client configuration, which are in [Report.Configs].
type SSH struct {
	AuthorizedKeys []AuthorizedKeysFile `json:"authorized_keys,omitempty"`
	KnownHosts     []KnownHostsFile     `json:"known_hosts,omitempty"`
	// HostPublicKeys are the host keys' public halves, which is what a client
	// sees and what pairs this host with the sensor's SSH observation.
	HostPublicKeys []SSHPublicKey `json:"host_public_keys,omitempty"`
}

// AuthorizedKeysFile is one authorized_keys file: who may log in as whom.
type AuthorizedKeysFile struct {
	Location Location `json:"location"`
	// Account is the account the file grants access to.
	Account string         `json:"account,omitempty"`
	Keys    []SSHPublicKey `json:"keys,omitempty"`
}

// SSHPublicKey is one SSH public key. Comments are not kept: they are usually
// a person's name or address.
type SSHPublicKey struct {
	Algorithm   string `json:"algorithm"` // "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com"
	SizeBits    int    `json:"size_bits,omitempty"`
	Fingerprint string `json:"fingerprint"` // "SHA256:..."
	// Restricted is true when the entry carries options that limit it (from=,
	// command=, restrict). Authorized keys only.
	Restricted *bool `json:"restricted,omitempty"`
	// CertificateAuthority is whether an authorized_keys entry carries the
	// cert-authority option. Nil when it could not be known (a remote
	// collection: options do not cross) and for keys that are not
	// authorized_keys entries.
	CertificateAuthority *bool `json:"certificate_authority,omitempty"`
}

// KnownHostsFile is summarised, never listed: its entries are other people's
// hosts.
type KnownHostsFile struct {
	Location Location `json:"location"`
	// Entries and Hashed are nil when the file could not be read in this
	// mode (a known_hosts file is not public, so a remote collection records
	// only that it exists and who can read it).
	Entries *int  `json:"entries,omitempty"`
	Hashed  *bool `json:"hashed,omitempty"`
}

// CryptoConfig is the cryptographic policy one configuration file sets, for
// one product. It is a projection onto named fields; nothing else of the file
// is kept.
type CryptoConfig struct {
	Location Location `json:"location"`
	// Product is what reads the file: "openssl", "java", "sshd", "ssh",
	// "nginx", "apache", "haproxy", "crypto-policies", "schannel", "gnutls",
	// "krb5", "postfix"...
	Product string `json:"product"`
	// Context narrows it where one file holds several: an nginx server block's
	// server_name and listen, an OpenSSL section name.
	Context string `json:"context,omitempty"`

	// Protocols are the protocol versions the configuration allows, in the
	// catalogue's spelling: "TLSv1.2", "TLSv1.3", "SSHv2".
	Protocols   []string `json:"protocols,omitempty"`
	MinProtocol string   `json:"min_protocol,omitempty"`
	MaxProtocol string   `json:"max_protocol,omitempty"`
	// CipherString is the configured cipher expression as written, for the
	// products that take one ("HIGH:!aNULL:!MD5"). CipherSuites is the
	// explicit list where the product takes a list.
	CipherString        string   `json:"cipher_string,omitempty"`
	CipherSuites        []string `json:"cipher_suites,omitempty"`
	KeyExchanges        []string `json:"key_exchanges,omitempty"`
	Groups              []string `json:"groups,omitempty"`
	MACs                []string `json:"macs,omitempty"`
	SignatureAlgorithms []string `json:"signature_algorithms,omitempty"`
	HostKeyAlgorithms   []string `json:"host_key_algorithms,omitempty"`
	// DisabledProtocols are protocol versions the file switches off when it
	// does not state the allowed set (HAProxy "no-tlsv10" alone). The allowed
	// set then depends on the product's and library's defaults, which the
	// file does not say and this record does not guess.
	DisabledProtocols []string `json:"disabled_protocols,omitempty"`
	// DisabledAlgorithms is a deny list (java.security
	// jdk.tls.disabledAlgorithms, a crypto-policies back end).
	DisabledAlgorithms []string `json:"disabled_algorithms,omitempty"`
	// Policy is a named policy: crypto-policies "DEFAULT:SHA1", an OpenSSL
	// security level "SECLEVEL=2".
	Policy string `json:"policy,omitempty"`
	// FIPS is whether the configuration turns FIPS mode on. Nil when it says
	// nothing.
	FIPS *bool `json:"fips,omitempty"`
	// Settings holds further allowlisted directives of this product, by name.
	// The allowlist is per product and tested; a directive not on it is not
	// kept.
	Settings map[string]string `json:"settings,omitempty"`
	// References are the files this configuration names. They drive pass 2
	// and become the UsedBy of the items they point at.
	References []ConfigReference `json:"references,omitempty"`
}

// ConfigReference is one file a configuration names.
type ConfigReference struct {
	// Kind is "certificate", "private_key", "keystore", "trust_store",
	// "dh_params", "crl" or "include".
	Kind      string `json:"kind"`
	Directive string `json:"directive"`
	Path      string `json:"path"`
	// Status is what the collector found at Path: one of the Ref
	// constants. Empty when no collector followed it (a parser alone).
	Status string `json:"status,omitempty"`
}

// What a collector found at a ConfigReference's path.
const (
	RefFound       = "found"        // the file (or directory) exists and was visited
	RefMissing     = "missing"      // nothing at the path (a glob that matched nothing)
	RefUnreadable  = "unreadable"   // it exists and could not be read; Errors says why
	RefNotFollowed = "not_followed" // the path holds a variable, a % token or ~, and names no one file
)

// CryptoLibrary is one cryptographic library or provider present on the host.
type CryptoLibrary struct {
	// Name is the catalogue's name: "openssl", "libressl", "boringssl",
	// "gnutls", "nss", "libgcrypt", "wolfssl", "mbedtls", "bouncycastle",
	// "schannel", "corecrypto".
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// Path is the library file. Empty for one known only from the package
	// database.
	Path string `json:"path,omitempty"`
	// Source is "package", "file" or "process".
	Source  string `json:"source"`
	Package string `json:"package,omitempty"`
	// FIPSProvider is whether a FIPS provider or module is installed for it.
	// Nil when not applicable or not known.
	FIPSProvider *bool `json:"fips_provider,omitempty"`
	// LoadedBy names the running processes that have it loaded (pass 3).
	LoadedBy []string `json:"loaded_by,omitempty"`
}

// Protection is what the platform itself provides.
type Protection struct {
	Volumes []VolumeEncryption `json:"volumes,omitempty"`
	TPM     *TPM               `json:"tpm,omitempty"`
	// SecureEnclave is Apple's Secure Enclave, macOS only. It is not a TPM
	// and is not reported as one. Nil where it was not read.
	SecureEnclave *SecureEnclave `json:"secure_enclave,omitempty"`
	SecureBoot    *bool          `json:"secure_boot,omitempty"`
	// FIPSMode is the operating system's FIPS switch. Nil when the platform
	// has none or it could not be read.
	FIPSMode *bool `json:"fips_mode,omitempty"`
	// Tokens are the PKCS#11 modules and smart-card providers configured.
	Tokens []Token `json:"tokens,omitempty"`
}

// VolumeEncryption is one mounted volume and whether it is encrypted at rest.
type VolumeEncryption struct {
	Device     string `json:"device,omitempty"`
	MountPoint string `json:"mount_point,omitempty"`
	// Encrypted is nil when the collector could not tell.
	Encrypted *bool `json:"encrypted,omitempty"`
	// Method is "luks1", "luks2", "bitlocker", "filevault", "dm-crypt-plain".
	Method      string `json:"method,omitempty"`
	Cipher      string `json:"cipher,omitempty"` // "aes-xts-plain64", "XTS-AES 256"
	KeySizeBits int    `json:"key_size_bits,omitempty"`
	// Protectors are how the volume key is unlocked: "tpm", "tpm+pin",
	// "passphrase", "recovery_key", "key_file". Names only.
	Protectors []string `json:"protectors,omitempty"`
	// Status is the platform's own word where it has one: "FullyEncrypted",
	// "EncryptionInProgress".
	Status string `json:"status,omitempty"`
}

// SecureEnclave describes a Mac's Secure Enclave.
type SecureEnclave struct {
	// Present is nil when it could not be told.
	Present *bool `json:"present,omitempty"`
	// Kind is "apple-silicon" or "t2".
	Kind string `json:"kind,omitempty"`
}

// TPM describes the host's Trusted Platform Module.
type TPM struct {
	Present      bool   `json:"present"`
	Version      string `json:"version,omitempty"` // "2.0", "1.2"
	Manufacturer string `json:"manufacturer,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty"`
}

// Token is one PKCS#11 module or smart-card provider.
type Token struct {
	Name string `json:"name,omitempty"`
	// Path is the module library.
	Path string `json:"path,omitempty"`
	// ConfiguredIn is the file that names it.
	ConfiguredIn string `json:"configured_in,omitempty"`
}

// Coverage is what one collection saw completely, directory by directory.
//
// A directory is listed in Directories if and only if the collector listed
// its direct entries completely (no permission error, no bound, no deadline,
// not excluded, not a home directory without the opt-in), and every regular
// file directly in it was identified and, when it is something the Report
// records, is in the Report, or is in SkippedFiles with the reason it was
// not read. Its subdirectories are covered separately or not at all.
//
// So for a covered directory, a file-based item (Location.Path directly in
// it) that a previous collection reported and this one does not is gone. A
// false "covered" would retire an item that still exists, so the collector
// leaves a directory uncovered whenever it is not certain. Items in
// platform stores (Windows certificate stores, macOS keychains) are not
// covered by this; their sections decide.
type Coverage struct {
	Directories  []string      `json:"directories,omitempty"`
	SkippedFiles []SkippedFile `json:"skipped_files,omitempty"`
}

// SkippedFile is a file in a covered directory that was not read, and why
// ("larger than the read bound", "permission denied"). An item at its path
// is not gone.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// StepError records a step that did not complete. Message is a bounded
// description, never the output that produced it.
type StepError struct {
	Step    string `json:"step"`
	Message string `json:"message"`
}

// LimitHit records a bound that stopped a section early.
type LimitHit struct {
	Section string `json:"section"`
	// Limit names the bound: "max_files", "max_duration", "max_records",
	// "max_file_bytes".
	Limit string `json:"limit"`
	// Detail is a short human sentence: "stopped after 200000 files".
	Detail string `json:"detail,omitempty"`
}
