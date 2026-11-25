//go:build windows

package agentoutput

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createOwnerOnly creates the temporary output file with a security
// descriptor of its own, passed to CreateFile so the file never exists
// without it: owned by the running user, its DACL protected (nothing
// inherited from the folder) and granting full control to that user,
// SYSTEM and Administrators only. The DACL is then read back from the open
// handle, before a byte is written: a volume that holds no ACL (FAT) creates
// the file regardless and reads back nothing, which is refused unless
// allowInherited.
//
// The file is later renamed over the output path (Writer.Close), and a
// rename keeps the renamed file's own security, so an existing permissive
// file at the path is replaced by a restricted one.
func createOwnerOnly(dir, prefix string, allowInherited bool) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("cannot read the running user: %w", err)
	}
	me := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + me + "D:P(A;;FA;;;" + me + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, fmt.Errorf("cannot build the output file's permissions: %w", err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for try := 0; try < 10; try++ {
		var rnd [6]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(rnd[:]))
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, sa,
			windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == windows.ERROR_FILE_EXISTS {
			continue
		}
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(h), name)
		if err := checkOwnerOnly(h, user.User.Sid); err != nil && !allowInherited {
			_ = f.Close()
			_ = os.Remove(name)
			return nil, fmt.Errorf("%w (%v)", ErrCannotRestrict, err)
		}
		return f, nil
	}
	return nil, fmt.Errorf("cannot find a free name for the output file in %s", dir)
}

// checkOwnerOnly reads a file's DACL back and requires exactly what
// createOwnerOnly asked for: protected, three allow entries, for me, SYSTEM
// and Administrators.
func checkOwnerOnly(h windows.Handle, me *windows.SID) error {
	got, err := ownerOnlyTrustees(h)
	if err != nil {
		return err
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	want := map[string]bool{me.String(): true, system.String(): true, admins.String(): true}
	if len(got) != len(want) {
		return fmt.Errorf("the file's ACL has %d entries, want %d", len(got), len(want))
	}
	for _, sid := range got {
		if !want[sid] {
			return fmt.Errorf("the file's ACL grants %s", sid)
		}
	}
	return nil
}

// ownerOnlyTrustees returns the SIDs of a file's DACL entries, and an error
// when the DACL is missing, inherits, or holds anything but allow entries.
func ownerOnlyTrustees(h windows.Handle) ([]string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	control, _, err := sd.Control()
	if err != nil {
		return nil, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return nil, fmt.Errorf("the file's ACL is not protected from inheritance")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil, fmt.Errorf("the file has no ACL")
	}
	var out []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return nil, fmt.Errorf("the file's ACL holds an entry of type %d, flags %#x", ace.Header.AceType, ace.Header.AceFlags)
		}
		out = append(out, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return out, nil
}
