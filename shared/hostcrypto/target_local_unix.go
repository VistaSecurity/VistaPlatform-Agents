//go:build unix

// The one place build tags are allowed in this package: reading a local
// file's owner, group and device is a system call whose shape differs by OS.
// Everything that describes ANOTHER host's files is in untagged code, so a
// Linux agent can still collect a Windows host remotely.

package hostcrypto

import (
	"io/fs"
	"os/user"
	"strconv"
	"syscall"
)

// localOwnership fills Mode, Owner, Group and the readability answers from the
// file's mode bits and stat_t.
func localOwnership(_ string, fi fs.FileInfo, out *FileInfo, ids *idCache) {
	out.Mode = unixModeBits(fi.Mode())
	world := out.Mode&0o004 != 0
	group := out.Mode&0o040 != 0
	out.WorldReadable = &world
	out.GroupReadable = &group

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	gid := strconv.FormatUint(uint64(st.Gid), 10)
	out.Owner = ids.lookup("u"+uid, func() string {
		if u, err := user.LookupId(uid); err == nil && u.Username != "" {
			return u.Username
		}
		return uid
	})
	out.Group = ids.lookup("g"+gid, func() string {
		if g, err := user.LookupGroupId(gid); err == nil && g.Name != "" {
			return g.Name
		}
		return gid
	})
}

// unixModeBits returns the permission bits as the octal number ls shows,
// including setuid, setgid and sticky, which Go keeps outside Perm().
func unixModeBits(m fs.FileMode) uint32 {
	bits := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

// localDevice returns the filesystem a path is on, so a walk can stay on its
// root's.
func localDevice(_ string, fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true //nolint:unconvert // Dev is int32 on darwin, uint64 on linux
}
