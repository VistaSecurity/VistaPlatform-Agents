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
// What differs between the modes is which bytes the collector may ask for,
// and that rule lives in one place: [Target.ReadFile] on a remote target
// refuses any path whose [Identity] is not public.
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
}

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

// Public reports whether a file of this identity holds nothing private, so
// its bytes may cross a remote connection: a certificate, a public key, a
// request, a revocation list, parameters, or plain text. A file holding a
// private key in any form is not public, and neither is a keystore, a PGP
// keyring or anything unidentified.
func (i Identity) Public() bool {
	switch i.Class {
	case ClassCertificate, ClassPublicKey, ClassCSR, ClassCRL, ClassDHParams, ClassText:
		return true
	default:
		return false
	}
}
