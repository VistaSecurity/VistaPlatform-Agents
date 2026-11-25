package hostcrypto

// The Report on the wire. One collection travels three ways, and all three
// carry the SAME bytes, produced here:
//
//   - a managed `host_crypto` job's result (`job-result.device-agent`,
//     property `host_crypto`), for a job the platform queued, local or remote;
//   - a LOCAL scheduled collection's submission (`host-crypto.submission`),
//     which has no job, exactly as local host inventory has none;
//   - a standalone run's `host_crypto` record (`vista.agent-output/v1`).
//
// Unlike host inventory there is no projection into facts here. Host
// inventory's facts are a registered vocabulary the platform already
// materialised before it had a report; host crypto has no such vocabulary,
// and the Report itself is the published contract
// (schemas/managed/v1/defs/host-crypto-report.json, held field for field to
// report.go by observations_test.go). What this file adds is what a contract
// alone cannot do: a size bound that cuts the report honestly, and a last
// check of the exact bytes that will leave the agent.

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CapabilityHostCrypto is the managed-protocol capability an agent that runs
// `host_crypto` jobs and posts local collections declares. Capabilities are
// additive: a platform that does not offer it queues no such job, and the
// agent then sends no local collection either.
const CapabilityHostCrypto = "host_crypto_v1"

// JobTypeHostCrypto is the job type the platform queues for a collection.
const JobTypeHostCrypto = "host_crypto"

// LimitMaxResultBytes names the bound [ResultPayload] applies, as a
// [LimitHit.Limit].
const LimitMaxResultBytes = "max_result_bytes"

// DefaultMaxResultBytes bounds the serialized report. A device-agent job
// result is at most 32 MiB in all (job-result.device-agent); half of it for
// the report leaves the envelope and any later field room, and is several
// times what a busy host's report measures at the collector's own bounds.
const DefaultMaxResultBytes = 16 << 20

// ErrKeyMaterial is returned when, after every field was sanitised, the
// serialized report still holds private key material. It cannot happen
// unless the sanitiser itself is broken; it is the last refusal, kept so
// that a broken sanitiser fails closed.
var ErrKeyMaterial = errors.New("hostcrypto: the serialized report carries private key material; nothing was sent")

// ErrResultTooLarge is returned when the report cannot be cut to the bound
// without dropping what makes it a report (its sections and errors).
var ErrResultTooLarge = errors.New("hostcrypto: the report does not fit the result bound")

// WithheldName replaces a host-supplied string (a file name, an alias, a
// subject) that resembles key material without being any: it is data, and
// the report is sent, but a reader never sees a key-shaped string.
const WithheldName = "[name withheld: resembles key material]"

// ResultPayload serializes rep for the wire, bounded to maxBytes (0 or less:
// unbounded), and checks the bytes that will be sent.
//
// Every string of the report is first sanitised as DATA (jobSanitise): one
// that holds real private key material (a complete PEM private key block,
// or text that parses as a private key) is removed and its section marked
// partial with a step error naming the item; one that merely resembles key
// material (a file named like a PuTTY key, an alias spelled like a PEM
// label) is replaced with [WithheldName] and noted. One host-supplied name
// never stops the report.
//
// When the report is too large it is cut, never silently: first every
// certificate's PEM is left out (its fingerprint and fields stay), then the
// largest list is cut to the longest prefix that fits, and so on, and every
// section cut (with the sweep and home directories when what was cut came
// from them) gets a [LimitHit] with [LimitMaxResultBytes] and is marked
// partial. rep itself is not changed; the report that was sent is returned
// beside its bytes.
func ResultPayload(rep *Report, maxBytes int) (json.RawMessage, *Report, error) {
	if rep == nil {
		return nil, nil, errors.New("hostcrypto: no report")
	}
	clean, err := jobSanitise(rep)
	if err != nil {
		return nil, nil, err
	}
	sent, b, err := jobBound(clean, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	if err := jobCheckNoKeyMaterial(b); err != nil {
		return nil, nil, err
	}
	return json.RawMessage(b), sent, nil
}

// OutputData is the data of a standalone `host_crypto` record:
// {"report": <the report>}, the same shape host inventory's record has. It
// passes the same sanitising as a managed result; a standalone file is not
// bounded (it is the operator's own disk).
func OutputData(rep *Report) (map[string]json.RawMessage, error) {
	b, _, err := ResultPayload(rep, 0)
	if err != nil {
		return nil, err
	}
	return map[string]json.RawMessage{"report": b}, nil
}

// jobNameMarkers are shapes that only resemble key material in a name:
// a PEM private key armour line, PuTTY's and SSH-1's file headers, and the
// base64 of OpenSSH's "openssh-key-v1" magic.
var jobNameMarkers = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`),
	regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`),
	regexp.MustCompile(`PuTTY-User-Key-File-[0-9]`),
	regexp.MustCompile(`SSH PRIVATE KEY FILE FORMAT 1\.1`),
	regexp.MustCompile(`b3BlbnNzaC1rZXktdjE`),
}

// jobResemblesKey reports whether s carries a key-like marker.
func jobResemblesKey(s string) bool {
	for _, re := range jobNameMarkers {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

var (
	jobPEMBegin = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----`)
	jobB64Only  = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
)

// jobHasPrivateBlock reports whether s holds a complete PEM private key
// block: its BEGIN line, a base64 body of some length, and the END line of
// the same label.
func jobHasPrivateBlock(s string) bool {
	for _, m := range jobPEMBegin.FindAllStringSubmatchIndex(s, -1) {
		label := s[m[2]:m[3]]
		rest := s[m[1]:]
		end := strings.Index(rest, "-----END "+label+"-----")
		if end < 0 {
			continue
		}
		body := 0
		for _, c := range rest[:end] {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' {
				body++
			}
		}
		if body >= 32 {
			return true
		}
	}
	return false
}

// jobParsesAsPrivateKey reports whether s holds, as a long run of base64 or
// of hexadecimal (alone, or as a word of a phrase), a private key of a
// format this package knows.
func jobParsesAsPrivateKey(s string) bool {
	if len(s) < 64 {
		return false
	}
	if jobB64Only.MatchString(s) {
		if der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), "")); err == nil && jobIsPrivateDER(der) {
			return true
		}
	}
	for _, w := range jobLongEncoded.FindAllString(s, -1) {
		if der, err := hex.DecodeString(w); err == nil && jobIsPrivateDER(der) {
			return true
		}
		if der, err := base64.StdEncoding.DecodeString(w); err == nil && jobIsPrivateDER(der) {
			return true
		}
	}
	return false
}

// jobLongEncoded is a run long enough to hold a key (an Ed25519 PKCS#8 is 48 bytes): 64 or more base64 or
// hexadecimal characters.
var jobLongEncoded = regexp.MustCompile(`[A-Za-z0-9+/]{64,}={0,2}`)

// jobIsPrivateDER reports whether der is a private key: PKCS#8, PKCS#1,
// SEC 1, or an OpenSSH private key body.
func jobIsPrivateDER(der []byte) bool {
	if bytes.HasPrefix(der, []byte("openssh-key-v1\x00")) {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return true
	}
	return false
}

// jobTopSection names the section a top-level report field's items belong
// to, for the notes the sanitiser makes.
func jobTopSection(key, sub string) string {
	switch key {
	case "certificates", "private_keys", "keystores", "configs", "libraries", "ssh":
		return key
	case "protection":
		switch sub {
		case "volumes":
			return SectionDiskEncryption
		case "tokens":
			return SectionTokens
		case "tpm", "secure_enclave":
			return SectionTPM
		case "secure_boot":
			return SectionSecureBoot
		case "fips_mode":
			return SectionFIPSMode
		}
	}
	return ""
}

// jobSanitiseEvent is one value the sanitiser changed.
type jobSanitiseEvent struct {
	section string
	item    int // index in the section's list, -1 when not a list item
	key     bool
}

// jobSanitise returns a deep copy of rep with every string judged as data.
func jobSanitise(rep *Report) (*Report, error) {
	b, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
	}
	var tree map[string]any
	if err := json.Unmarshal(b, &tree); err != nil {
		return nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
	}
	var events []jobSanitiseEvent
	var walk func(v any, section string, item int) any
	walk = func(v any, section string, item int) any {
		switch t := v.(type) {
		case string:
			switch {
			case jobHasPrivateBlock(t) || jobParsesAsPrivateKey(t):
				events = append(events, jobSanitiseEvent{section, item, true})
				return ""
			case jobResemblesKey(t):
				events = append(events, jobSanitiseEvent{section, item, false})
				return WithheldName
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i], section, item)
			}
			return t
		case map[string]any:
			for k, x := range t {
				t[k] = walk(x, section, item)
			}
			return t
		}
		return v
	}
	for k, v := range tree {
		switch k {
		case "protection", "ssh":
			if m, ok := v.(map[string]any); ok {
				for sub, x := range m {
					sec := jobTopSection(k, sub)
					if list, ok := x.([]any); ok {
						for i := range list {
							list[i] = walk(list[i], sec, i)
						}
						continue
					}
					m[sub] = walk(x, sec, -1)
				}
				continue
			}
		}
		sec := jobTopSection(k, "")
		if list, ok := v.([]any); ok && sec != "" {
			for i := range list {
				list[i] = walk(list[i], sec, i)
			}
			continue
		}
		tree[k] = walk(v, sec, -1)
	}
	if len(events) == 0 {
		return rep, nil
	}
	b, err = json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
	}
	var cp Report
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
	}
	if cp.Sections == nil {
		cp.Sections = map[string]string{}
	}
	for _, e := range events {
		step := e.section
		if step == "" {
			step = "report"
		}
		where := "a value"
		if e.item >= 0 {
			where = fmt.Sprintf("item %d", e.item)
		}
		if e.key {
			if e.section != "" {
				cp.mark(e.section, SectionPartial)
			}
			cp.recordError(step, fmt.Errorf("%s: a value held private key material and was removed", where))
			continue
		}
		cp.recordError(step, fmt.Errorf("%s: a name was withheld: it resembles key material", where))
	}
	return &cp, nil
}

// jobCheckNoKeyMaterial is the last, structural check over the exact bytes
// that leave the agent: no complete PEM private key block (JSON writes a
// line break as the two characters \n, which the body count ignores).
func jobCheckNoKeyMaterial(b []byte) error {
	if jobHasPrivateBlock(string(b)) {
		return ErrKeyMaterial
	}
	return nil
}

// jobList is one list of the report that may be cut to fit the bound.
type jobList struct {
	section string
	size    func(r *Report) int
	cut     func(r *Report, n int)
	encode  func(r *Report) ([]byte, error)
	// sweep reports whether any item from index n on was found by the
	// sweep; nil for a list whose items carry no Location.
	sweep func(r *Report, n int) bool
}

// jobSwept reports whether any location from n on was found by the sweep.
func jobSwept[T any](items []T, n int, loc func(*T) *Location) bool {
	for i := n; i < len(items); i++ {
		if loc(&items[i]).FoundBy == FoundBySweep {
			return true
		}
	}
	return false
}

// jobLists are the report's lists, each with the section a cut marks.
var jobLists = []jobList{
	{SectionCertificates,
		func(r *Report) int { return len(r.Certificates) },
		func(r *Report, n int) { r.Certificates = r.Certificates[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Certificates) },
		func(r *Report, n int) bool {
			return jobSwept(r.Certificates, n, func(x *Certificate) *Location { return &x.Location })
		}},
	{SectionPrivateKeys,
		func(r *Report) int { return len(r.PrivateKeys) },
		func(r *Report, n int) { r.PrivateKeys = r.PrivateKeys[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.PrivateKeys) },
		func(r *Report, n int) bool {
			return jobSwept(r.PrivateKeys, n, func(x *PrivateKey) *Location { return &x.Location })
		}},
	{SectionKeystores,
		func(r *Report) int { return len(r.Keystores) },
		func(r *Report, n int) { r.Keystores = r.Keystores[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Keystores) },
		func(r *Report, n int) bool {
			return jobSwept(r.Keystores, n, func(x *Keystore) *Location { return &x.Location })
		}},
	{SectionConfigs,
		func(r *Report) int { return len(r.Configs) },
		func(r *Report, n int) { r.Configs = r.Configs[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Configs) },
		func(r *Report, n int) bool {
			return jobSwept(r.Configs, n, func(x *CryptoConfig) *Location { return &x.Location })
		}},
	{SectionLibraries,
		func(r *Report) int { return len(r.Libraries) },
		func(r *Report, n int) { r.Libraries = r.Libraries[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Libraries) }, nil},
	{SectionSSH,
		func(r *Report) int { return len(r.SSH.AuthorizedKeys) },
		func(r *Report, n int) { r.SSH.AuthorizedKeys = r.SSH.AuthorizedKeys[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.SSH.AuthorizedKeys) }, nil},
	{SectionSSH,
		func(r *Report) int { return len(r.SSH.KnownHosts) },
		func(r *Report, n int) { r.SSH.KnownHosts = r.SSH.KnownHosts[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.SSH.KnownHosts) }, nil},
	{SectionSSH,
		func(r *Report) int { return len(r.SSH.HostPublicKeys) },
		func(r *Report, n int) { r.SSH.HostPublicKeys = r.SSH.HostPublicKeys[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.SSH.HostPublicKeys) }, nil},
	{SectionDiskEncryption,
		func(r *Report) int { return len(r.Protection.Volumes) },
		func(r *Report, n int) { r.Protection.Volumes = r.Protection.Volumes[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Protection.Volumes) }, nil},
	{SectionTokens,
		func(r *Report) int { return len(r.Protection.Tokens) },
		func(r *Report, n int) { r.Protection.Tokens = r.Protection.Tokens[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Protection.Tokens) }, nil},
}

// jobBound returns rep, or a cut copy of it, whose encoding fits maxBytes.
func jobBound(rep *Report, maxBytes int) (*Report, []byte, error) {
	b, err := json.Marshal(rep)
	if err != nil {
		return nil, nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
	}
	if maxBytes <= 0 || len(b) <= maxBytes {
		return rep, b, nil
	}
	detail := fmt.Sprintf("cut to fit the %d-byte result bound", maxBytes)
	cp := jobCopy(rep)

	// 1. Certificate PEM: the largest field by far and the one a reader can
	// do without, since the fingerprint names the certificate.
	if len(cp.Certificates) > 0 {
		certs := make([]Certificate, len(cp.Certificates))
		copy(certs, cp.Certificates)
		stripped := false
		for i := range certs {
			if certs[i].CertificatePEM != "" {
				certs[i].CertificatePEM = ""
				stripped = true
			}
		}
		cp.Certificates = certs
		if stripped {
			cp.limit(SectionCertificates, LimitMaxResultBytes, "certificate PEM left out to fit the result bound")
			if b, err = json.Marshal(cp); err == nil && len(b) <= maxBytes {
				return cp, b, nil
			}
		}
	}

	// 2. Cut the largest list, by encoded size, to the longest prefix with
	// which the report fits (a binary search on its length), then the next
	// largest, until it fits. Every section cut is partial with the limit,
	// and so are the sweep and home directories when what was cut came
	// from them (or, for home directories, may have: an item does not say
	// which pass found it in a home directory).
	cutDone := map[int]bool{}
	for {
		best, bestSize := -1, 0
		for i, l := range jobLists {
			if cutDone[i] || l.size(cp) == 0 {
				continue
			}
			enc, err := l.encode(cp)
			if err != nil {
				return nil, nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
			}
			if len(enc) > bestSize {
				best, bestSize = i, len(enc)
			}
		}
		if best < 0 {
			break
		}
		cutDone[best] = true
		l := jobLists[best]
		full := l.size(cp)
		// apply cuts r to n items and records what the cut means; the
		// search measures exactly what will be sent, limits included.
		apply := func(r *Report, n int) {
			if l.sweep != nil && l.sweep(r, n) {
				r.limit(SectionSweep, LimitMaxResultBytes, detail)
			}
			l.cut(r, n)
			r.limit(l.section, LimitMaxResultBytes, detail)
			if r.Scope.HomeDirectories {
				r.limit(SectionHomeDirectories, LimitMaxResultBytes, detail)
			}
		}
		fits := func(n int) bool {
			trial := jobCopy(cp)
			apply(trial, n)
			tb, err := json.Marshal(trial)
			return err == nil && len(tb) <= maxBytes
		}
		lo, hi := 0, full-1 // the largest n below full that fits, or 0
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if fits(mid) {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		apply(cp, lo)
		if b, err = json.Marshal(cp); err != nil {
			return nil, nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
		}
		if len(b) <= maxBytes {
			return cp, b, nil
		}
	}

	// 3. The step errors, which a pathological host can make long: keep the
	// first ones and say how many were left out.
	if n := len(cp.Errors); n > 1 {
		for keep := n / 2; keep >= 0; keep /= 2 {
			errs := append([]StepError(nil), rep.Errors[:keep]...)
			cp.Errors = append(errs, StepError{Step: "result", Message: fmt.Sprintf("%d further errors left out to fit the result bound", n-keep)})
			if b, err = json.Marshal(cp); err != nil {
				return nil, nil, fmt.Errorf("hostcrypto: encode the report: %w", err)
			}
			if len(b) <= maxBytes {
				return cp, b, nil
			}
			if keep == 0 {
				break
			}
		}
	}
	return nil, nil, fmt.Errorf("%w: %d bytes over %d with every list cut", ErrResultTooLarge, len(b), maxBytes)
}

// jobCopy copies rep deeply enough that cutting the copy leaves rep alone:
// the map and the slices the bound changes are new, the list elements are
// shared (they are only re-sliced, except certificates, which are copied
// before their PEM is cleared).
func jobCopy(rep *Report) *Report {
	cp := *rep
	cp.Sections = make(map[string]string, len(rep.Sections))
	for k, v := range rep.Sections {
		cp.Sections[k] = v
	}
	cp.Limits = append([]LimitHit(nil), rep.Limits...)
	cp.Errors = append([]StepError(nil), rep.Errors...)
	return &cp
}
