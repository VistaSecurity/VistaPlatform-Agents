package hostcrypto

import (
	"context"
	"errors"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Target is how the collector reaches a host. It is host inventory's
// [hostinventory.Runner] plus the three things a file hunt needs and a command
// transport does not give safely: listing a tree within bounds, reading a
// file's permissions, and learning what a file IS without reading it.
//
// The parsers take bytes and nothing else, exactly as host inventory's do.
// What differs between the modes is which bytes the collector may ask for.
// On a remote target [Target.ReadFile] does not return a file: it returns the
// certificates in it, each re-encoded by a certificate parser on the host
// (openssl, or .NET on Windows), and its SSH public key lines, and nothing
// around them, decided and printed on the host from one read of the file. A
// file with no such content is refused with ErrNotPublic. Configuration is read
// through [Target.ReadText], which narrows on the host to the lines a parser
// asked for.
type Target interface {
	hostinventory.Runner

	// Local reports whether file bytes stay on the host they came from: true
	// when the collector runs on the host itself. Only a local target may
	// hand a private key file to a parser.
	Local() bool

	// Stat describes one path. A missing path is ErrNotExist; a path the
	// account may not stat is ErrPermission. Neither is ever an empty result.
	Stat(ctx context.Context, path string) (FileInfo, error)

	// List walks root and returns the regular files under it, within the
	// bounds in opts. It never follows a symbolic link out of root, never
	// crosses onto another filesystem unless opts says so, and never descends
	// into an excluded path. When a bound stops it early it returns what it
	// has and ErrListTruncated.
	List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error)

	// Identify says what a file is from its first bytes and, for PEM, its
	// "-----BEGIN ...-----" labels. On a remote target the command that
	// answers it runs on the host and returns only those markers: at most
	// [MagicBytes] bytes from the start of the file and the label lines.
	Identify(ctx context.Context, path string) (Identity, error)

	// ReadText returns the parts of a configuration file that a parser has
	// asked for, and nothing else. It is the only way configuration text is
	// read, in both modes, and the narrowing happens ON THE HOST before any
	// byte leaves it ([FilterConfigText] is the rule, word for word):
	//
	//   1. keep holds the parser's directive names ([ConfigKeepWords]) and
	//      its syntax OPTIONS, entries beginning with "@": "@statements"
	//      (brace-and-semicolon syntax read as statements), "@backslash"
	//      (a kept line ending in an odd number of backslashes continues),
	//      "@indent" (a line beginning with a blank continues the previous
	//      one) and "@cr" (a lone carriage return ends a line), and the structure it
	//      has: "@sections" and "@anysections" ("[name]" headers) and "@tags"
	//      (closing tags). There is no continuation without an option, and a
	//      line holding a lone carriage return is dropped whole.
	//   2. A line (or statement) is kept only when its first word is in keep
	//      (compared without regard to ASCII case), when it is strict
	//      structure (a section header, a lone brace, a closing tag), or
	//      when it continues a kept line under an option. Every other line
	//      is dropped, and a dropped block opener drops its whole block, so
	//      a line such as "password = ..." never crosses, whatever its
	//      length or alphabet.
	//   3. Of what is kept, every PEM block is dropped and every run of
	//      [RedactRunLength] or more base64 or hexadecimal characters is
	//      replaced by [RedactedMarker]. redactions counts those.
	//
	// A keep with no directive name, or with an unknown option, is refused
	// with ErrNotPublic, and so is a file that is not text. Local and remote
	// targets apply the SAME rule, so a parser sees the same bytes in both
	// modes.
	ReadText(ctx context.Context, path string, keep []string) (text []byte, redactions int, err error)
}

// PublicReader is implemented by the remote targets: [Target.ReadFile] with
// the number of certificate blocks in the file that could not be read (the
// host's certificate parser refused them, or Go's recheck dropped a block
// crypto/x509 does not parse). Those blocks never cross; the rest of the
// file does, and the Report says how many were left out.
type PublicReader interface {
	ReadPublic(ctx context.Context, path string) (b []byte, unreadable int, err error)
}

// BatchTarget is implemented by targets that can Stat and Identify many
// paths in one host program (the remote targets: one command instead of two
// per path, which on Windows is a PowerShell start of about 0.75 s each). It
// is optional; a collector falls back to [Target.Stat] and
// [Target.Identify] on a target without it.
//
// StatIdentifyMany answers for every path, in order, with exactly what the
// single calls would answer for it: the FileInfo or Stat's error, and the
// Identity or Identify's error. Nothing else crosses: an Identity holds at
// most [MagicBytes] bytes of the file and its PEM labels, as Identify's does.
// The error is for the batch as a whole (the context ended); a path the host
// did not answer for in a batch is asked for with the single calls.
type BatchTarget interface {
	StatIdentifyMany(ctx context.Context, paths []string) ([]PathInfo, error)
}

// PathInfo is one path's answer from [BatchTarget.StatIdentifyMany].
type PathInfo struct {
	Path string
	// Info is Stat's answer when StatErr is nil.
	Info    FileInfo
	StatErr error
	// Identity is Identify's answer when IdentifyErr is nil.
	Identity    Identity
	IdentifyErr error
}

// maxBatchPaths and maxBatchPathBytes bound one host program of a batch.
const (
	maxBatchPaths     = 64
	maxBatchPathBytes = 16 << 10
)

// batchChunks splits paths into the batches one host program answers.
func batchChunks(paths []string) [][]string {
	var out [][]string
	start, n := 0, 0
	for i, p := range paths {
		if i > start && (i-start >= maxBatchPaths || n+len(p) > maxBatchPathBytes) {
			out = append(out, paths[start:i])
			start, n = i, 0
		}
		n += len(p)
	}
	if start < len(paths) {
		out = append(out, paths[start:])
	}
	return out
}

// statIdentifySingle answers for one path with the single calls.
func statIdentifySingle(ctx context.Context, t Target, p string) PathInfo {
	r := PathInfo{Path: p}
	r.Info, r.StatErr = t.Stat(ctx, p)
	r.Identity, r.IdentifyErr = t.Identify(ctx, p)
	return r
}

// RedactRunLength is the length of an unbroken run of base64 or hexadecimal
// characters at which [Target.ReadText] redacts. Forty is below the shortest
// encoded secret worth the name (a 32-byte key is 43 base64 or 64 hex
// characters) and above every cipher, group and algorithm name: those are
// broken by '-', ':', '_' or '@' long before forty.
const RedactRunLength = 40

// RedactedMarker replaces a redacted run.
const RedactedMarker = "[redacted]"

// MagicBytes is how much of a file's start [Target.Identify] may return. Eight
// bytes name every format this package recognises (JKS FEEDFEED, JCEKS
// CECECECE, a keytab's 0x0502, BCFKS and PKCS#12's ASN.1 SEQUENCE header,
// "PuTTY-Us", "SQLite f") and are not key material in any of them.
const MagicBytes = 8

// Errors a Target returns. They are distinct because the Report must say
// which happened.
var (
	ErrNotExist      = errors.New("hostcrypto: no such file or directory")
	ErrPermission    = errors.New("hostcrypto: permission denied")
	ErrListTruncated = errors.New("hostcrypto: the listing stopped at a bound")
	// ErrFileTooLarge is returned by a read of a file over the size bound.
	// Nothing of the file is returned.
	ErrFileTooLarge = errors.New("hostcrypto: the file is larger than the read bound")
	// ErrNotPublic is returned by a remote target's ReadFile for a path whose
	// Identity is not public. It is a programming error for a collector to
	// reach it: the read was refused, and nothing crossed the connection.
	ErrNotPublic = errors.New("hostcrypto: refusing to read a file not identified as public over a remote connection")
)

// FileInfo is one file as a Target sees it.
type FileInfo struct {
	Path string
	// Size in bytes.
	Size int64
	// Mode is the Unix permission bits, or 0 on Windows.
	Mode uint32
	// Owner and Group are names where the host resolves them, else numeric
	// ids as text.
	Owner string
	Group string
	// WorldReadable and GroupReadable are nil when the permissions could not
	// be read (see [Location]).
	WorldReadable *bool
	GroupReadable *bool
	// ModifiedAt is RFC 3339, UTC.
	ModifiedAt string
	// IsDir and IsSymlink describe the path itself, not what a link points
	// at.
	IsDir     bool
	IsSymlink bool
	// LinkTarget is where a symbolic link points, when IsSymlink.
	LinkTarget string
}

// ListOptions bound one walk.
type ListOptions struct {
	// MaxDepth is how far below root to descend. 0 means root's own entries.
	MaxDepth int
	// MaxFiles stops the walk after this many files. 0 means the package
	// default.
	MaxFiles int
	// MaxSizeBytes skips files larger than this. 0 means the package default.
	MaxSizeBytes int64
	// Exclude are path prefixes never entered. The collector always adds the
	// platform's pseudo-filesystems and network mounts.
	Exclude []string
	// CrossFilesystems lets the walk leave root's filesystem. Off by default.
	CrossFilesystems bool
	// Names, when set, keeps only files whose base name matches one of these
	// glob patterns. The sweep leaves it empty and identifies by content.
	Names []string
}

// Class is what a file is, as far as its markers say.
type Class string

const (
	ClassUnknown     Class = ""
	ClassCertificate Class = "certificate" // PEM CERTIFICATE / TRUSTED CERTIFICATE, or DER by parse
	ClassPrivateKey  Class = "private_key" // any PEM private key label, PuTTY, OpenSSH
	ClassPublicKey   Class = "public_key"  // PEM PUBLIC KEY, an OpenSSH .pub line
	ClassCSR         Class = "csr"         // PEM CERTIFICATE REQUEST
	ClassCRL         Class = "crl"         // PEM X509 CRL
	ClassDHParams    Class = "dh_params"   // PEM DH PARAMETERS
	ClassKeystore    Class = "keystore"    // JKS, JCEKS, PKCS#12, BCFKS, keytab, NSS, keychain
	ClassPGP         Class = "pgp"         // an OpenPGP keyring or armoured block
	ClassMixed       Class = "mixed"       // PEM with a certificate AND a private key
	ClassText        Class = "text"        // printable, none of the above: a candidate configuration file
)

// Identity is what [Target.Identify] learned about one file.
type Identity struct {
	// Magic is the file's first bytes, at most [MagicBytes].
	Magic []byte
	// PEMLabels are the labels of the file's PEM blocks, in order, without
	// the dashes: "CERTIFICATE", "ENCRYPTED PRIVATE KEY". Bounded.
	PEMLabels []string
	// Class is what Magic and PEMLabels amount to.
	Class Class
	// KeystoreType is one of the Keystore constants when Class is
	// ClassKeystore and the magic number says which.
	KeystoreType string
}

// Public reports whether a file of this identity may be read over a remote
// connection with [Target.ReadFile]: a certificate file, or an OpenSSH
// public key file (key lines, no PEM label). Even then what crosses is not
// the file: each certificate crosses only as a host parser's re-encoding of
// it, and each key line as "type blob". A public key, request, revocation
// list or parameters file is harmless but not readable remotely (no record
// of the Report needs it from a remote host); a private key in any form, a
// keystore, a PGP keyring, anything unidentified, and plain text are not
// public at all. Text is not public because a secret needs no marker: a
// WireGuard key, a kubeconfig and a Tor service key are all printable. A
// configuration file is read with [Target.ReadText] instead. A local target
// reads every file whole and does not consult Public.
func (i Identity) Public() bool {
	switch i.Class {
	case ClassCertificate:
		return true
	case ClassPublicKey:
		return len(i.PEMLabels) == 0
	default:
		return false
	}
}
