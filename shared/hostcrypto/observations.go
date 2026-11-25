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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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

// ErrKeyMaterial is returned when the serialized report carries something
// shaped like private key material. Nothing is sent: the report types hold no
// such field, so reaching this means a parser or a target broke its rule, and
// the safe answer to that is no report at all.
var ErrKeyMaterial = errors.New("hostcrypto: the serialized report carries private key material; nothing was sent")

// ErrResultTooLarge is returned when the report cannot be cut to the bound
// without dropping what makes it a report (its sections and errors).
var ErrResultTooLarge = errors.New("hostcrypto: the report does not fit the result bound")

// ResultPayload serializes rep for the wire, bounded to maxBytes (0 or less:
// unbounded), and checks the bytes that will be sent.
//
// When the report is too large it is cut, never silently: first every
// certificate's PEM is left out (its fingerprint and fields stay), then the
// largest list is halved until it fits, and each section cut gets a
// [LimitHit] with [LimitMaxResultBytes] and is marked partial, so no shortened
// list reads as a complete one. rep itself is not changed; the report that
// was sent is returned beside its bytes.
func ResultPayload(rep *Report, maxBytes int) (json.RawMessage, *Report, error) {
	if rep == nil {
		return nil, nil, errors.New("hostcrypto: no report")
	}
	sent, b, err := jobBound(rep, maxBytes)
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
// passes the same check as a managed result; a standalone file is not bounded
// (it is the operator's own disk).
func OutputData(rep *Report) (map[string]json.RawMessage, error) {
	b, _, err := ResultPayload(rep, 0)
	if err != nil {
		return nil, err
	}
	return map[string]json.RawMessage{"report": b}, nil
}

// jobKeyMarkers are shapes no honest report contains: a PEM private key
// armour line, PuTTY's and SSH-1's file headers, and the base64 of OpenSSH's
// "openssh-key-v1" magic, which starts every OpenSSH private key body.
// Encoded JSON keeps all of them literal (none holds a character
// encoding/json escapes).
var jobKeyMarkers = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`),
	regexp.MustCompile(`PuTTY-User-Key-File-[0-9]`),
	regexp.MustCompile(`SSH PRIVATE KEY FILE FORMAT 1\.1`),
	regexp.MustCompile(`b3BlbnNzaC1rZXktdjE`),
}

// jobCheckNoKeyMaterial is the backstop over the exact bytes that leave the
// agent. It cannot prove a report clean (no pattern can tell random key
// bytes from random anything); it refuses the shapes a leak of a whole key
// file would have, which is the failure a wrong field assignment produces.
func jobCheckNoKeyMaterial(b []byte) error {
	for _, re := range jobKeyMarkers {
		if re.Match(b) {
			return ErrKeyMaterial
		}
	}
	return nil
}

// jobList is one list of the report that may be cut to fit the bound.
type jobList struct {
	section string
	size    func(r *Report) int
	cut     func(r *Report, n int)
	encode  func(r *Report) ([]byte, error)
}

// jobLists are the report's lists, each with the section a cut marks.
var jobLists = []jobList{
	{SectionCertificates,
		func(r *Report) int { return len(r.Certificates) },
		func(r *Report, n int) { r.Certificates = r.Certificates[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Certificates) }},
	{SectionPrivateKeys,
		func(r *Report) int { return len(r.PrivateKeys) },
		func(r *Report, n int) { r.PrivateKeys = r.PrivateKeys[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.PrivateKeys) }},
	{SectionKeystores,
		func(r *Report) int { return len(r.Keystores) },
		func(r *Report, n int) { r.Keystores = r.Keystores[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Keystores) }},
	{SectionConfigs,
		func(r *Report) int { return len(r.Configs) },
		func(r *Report, n int) { r.Configs = r.Configs[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Configs) }},
	{SectionLibraries,
		func(r *Report) int { return len(r.Libraries) },
		func(r *Report, n int) { r.Libraries = r.Libraries[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Libraries) }},
	{SectionSSH,
		func(r *Report) int { return len(r.SSH.AuthorizedKeys) },
		func(r *Report, n int) { r.SSH.AuthorizedKeys = r.SSH.AuthorizedKeys[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.SSH.AuthorizedKeys) }},
	{SectionSSH,
		func(r *Report) int { return len(r.SSH.KnownHosts) },
		func(r *Report, n int) { r.SSH.KnownHosts = r.SSH.KnownHosts[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.SSH.KnownHosts) }},
	{SectionSSH,
		func(r *Report) int { return len(r.SSH.HostPublicKeys) },
		func(r *Report, n int) { r.SSH.HostPublicKeys = r.SSH.HostPublicKeys[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.SSH.HostPublicKeys) }},
	{SectionDiskEncryption,
		func(r *Report) int { return len(r.Protection.Volumes) },
		func(r *Report, n int) { r.Protection.Volumes = r.Protection.Volumes[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Protection.Volumes) }},
	{SectionTokens,
		func(r *Report) int { return len(r.Protection.Tokens) },
		func(r *Report, n int) { r.Protection.Tokens = r.Protection.Tokens[:n] },
		func(r *Report) ([]byte, error) { return json.Marshal(r.Protection.Tokens) }},
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

	// 2. Halve the largest list, by encoded size, until the report fits.
	for {
		best, bestSize := -1, 0
		for i, l := range jobLists {
			if l.size(cp) == 0 {
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
		l := jobLists[best]
		l.cut(cp, l.size(cp)/2)
		cp.limit(l.section, LimitMaxResultBytes, detail)
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
