package hostcrypto

// macOS file keychains (login.keychain-db, System.keychain, any *.keychain)
// share one container format that opens with the magic "kych". The
// data-protection keychain (keychain-2.db, SQLite) is not one of these and is
// not recognised here. Contents come from the security command in a later
// slice; this only says the file is a keychain.

// IdentifyKeychain reports whether b starts like a macOS file keychain.
func IdentifyKeychain(b []byte) (Keystore, bool) {
	if len(b) < 4 || string(b[:4]) != "kych" {
		return Keystore{}, false
	}
	return Keystore{Type: KeystoreKeychain, Opened: OpenedNot, Protection: "macOS file keychain"}, true
}
