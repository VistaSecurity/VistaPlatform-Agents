package agentoutput

import "errors"

// ErrCannotRestrict is returned when an owner-only output file cannot be
// given its owner-only permissions (a volume that holds no ACL), and the
// caller did not allow the folder's inherited permissions instead.
var ErrCannotRestrict = errors.New("the output file cannot be restricted to its owner on this volume (it keeps the folder's permissions); write it to an NTFS folder, or pass --allow-inherited-permissions to accept that")
