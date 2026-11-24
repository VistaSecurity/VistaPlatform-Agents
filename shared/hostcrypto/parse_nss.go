package hostcrypto

import "strings"

// NSS databases (Firefox and Thunderbird profiles, Chrome on Linux, Red Hat's
// system database, 389 Directory Server, libpq with NSS) are recognised by the
// files a directory holds, never opened: the modern generation is SQLite and
// the legacy one Berkeley DB, neither of which this package reads. Their
// contents come from certutil in a later slice.

// IdentifyNSSDatabase describes the NSS database in a directory from the base
// names of the files it holds. It reports false when none of the four NSS
// database files is among them.
func IdentifyNSSDatabase(fileNames []string) (Keystore, bool) {
	has := map[string]bool{}
	for _, n := range fileNames {
		has[strings.ToLower(n)] = true
	}
	var gens []string
	if has["cert9.db"] || has["key4.db"] {
		gens = append(gens, "NSS SQLite database ("+ksPresent(has, "cert9.db", "key4.db")+")")
	}
	if has["cert8.db"] || has["key3.db"] {
		gens = append(gens, "NSS legacy Berkeley DB database ("+ksPresent(has, "cert8.db", "key3.db")+")")
	}
	if len(gens) == 0 {
		return Keystore{}, false
	}
	return Keystore{Type: KeystoreNSS, Opened: OpenedNot, Protection: strings.Join(gens, "; ")}, true
}

func ksPresent(has map[string]bool, names ...string) string {
	var out []string
	for _, n := range names {
		if has[n] {
			out = append(out, n)
		} else {
			out = append(out, n+" missing")
		}
	}
	return strings.Join(out, ", ")
}
