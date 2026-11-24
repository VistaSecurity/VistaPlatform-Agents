//go:build windows

// The one place build tags are allowed in this package: reading a local
// file's owner and DACL is a Win32 call. Everything that describes ANOTHER
// host's files is in untagged code.

package hostcrypto

import (
	"io/fs"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// broadReadSIDs are the principals whose read grant makes a file readable by
// anyone on the machine: Everyone, BUILTIN\Users and Authenticated Users.
var broadReadSIDs = []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-11"}

// readRights are the access-mask bits that let a principal read a file's
// contents.
const readRights = windows.FILE_READ_DATA | windows.GENERIC_READ | windows.GENERIC_ALL

// localOwnership fills Owner and WorldReadable from the file's security
// descriptor. Mode stays 0 and GroupReadable nil: Windows has no group
// permission class. When the descriptor cannot be read, the readability answer
// stays nil rather than guessing.
func localOwnership(path string, _ fs.FileInfo, out *FileInfo, ids *idCache) {
	out.Mode = 0
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return
	}
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		sidStr := owner.String()
		out.Owner = ids.lookup("sid"+sidStr, func() string {
			account, domain, _, err := owner.LookupAccount("")
			if err != nil || account == "" {
				return sidStr
			}
			if domain != "" {
				return domain + `\` + account
			}
			return account
		})
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return
	}
	world := daclGrantsBroadRead(dacl)
	out.WorldReadable = &world
}

// daclGrantsBroadRead reports whether the DACL lets Everyone, Users or
// Authenticated Users read the file. A NULL DACL grants everyone everything.
//
// A deny entry for the same principal and right cancels the grant. This is an
// approximation of Windows' ordered evaluation, deliberately on the side of
// reporting a file as readable: a finding raised in error is a nuisance, a
// readable key reported as private is a miss.
func daclGrantsBroadRead(dacl *windows.ACL) bool {
	if dacl == nil {
		return true
	}
	allowed := map[string]bool{}
	denied := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // the ACE layout puts the SID at SidStart
		s := sid.String()
		if !isBroadSID(s) || ace.Mask&readRights == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allowed[s] = true
		case windows.ACCESS_DENIED_ACE_TYPE:
			denied[s] = true
		}
	}
	for s := range allowed {
		if !denied[s] {
			return true
		}
	}
	return false
}

func isBroadSID(s string) bool {
	for _, b := range broadReadSIDs {
		if s == b {
			return true
		}
	}
	return false
}

// localDevice returns the volume a path is on. The walk never descends into a
// junction or mount point (they are reparse points, which WalkDir does not
// follow), so in practice every directory shares its root's volume; this keeps
// the rule explicit.
func localDevice(path string, _ fs.FileInfo) (uint64, bool) {
	vol := strings.ToUpper(filepath.VolumeName(path))
	if vol == "" {
		return 0, false
	}
	var h uint64 = 14695981039346656037
	for i := 0; i < len(vol); i++ {
		h ^= uint64(vol[i])
		h *= 1099511628211
	}
	return h, true
}
