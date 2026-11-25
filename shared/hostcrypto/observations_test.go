package hostcrypto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/outputschema"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// The report's wire contract: schemas/managed/v1/defs/host-crypto-report.json
// against report.go, field for field, in both directions.

// jobDefOf names the schema definition of each struct type reachable from
// Report. A new struct type fails TestJobSchemaNamesEveryReportField until
// it has a definition here and in the schema.
var jobDefOf = map[reflect.Type]string{
	reflect.TypeOf(Report{}):             "",
	reflect.TypeOf(Access{}):             "access",
	reflect.TypeOf(Scope{}):              "scope",
	reflect.TypeOf(Location{}):           "location",
	reflect.TypeOf(Usage{}):              "usage",
	reflect.TypeOf(Certificate{}):        "certificate",
	reflect.TypeOf(PrivateKey{}):         "private_key",
	reflect.TypeOf(Keystore{}):           "keystore",
	reflect.TypeOf(KeystoreEntry{}):      "keystore_entry",
	reflect.TypeOf(SSH{}):                "ssh",
	reflect.TypeOf(AuthorizedKeysFile{}): "authorized_keys_file",
	reflect.TypeOf(SSHPublicKey{}):       "ssh_public_key",
	reflect.TypeOf(KnownHostsFile{}):     "known_hosts_file",
	reflect.TypeOf(CryptoConfig{}):       "crypto_config",
	reflect.TypeOf(ConfigReference{}):    "config_reference",
	reflect.TypeOf(CryptoLibrary{}):      "crypto_library",
	reflect.TypeOf(Protection{}):         "protection",
	reflect.TypeOf(VolumeEncryption{}):   "volume_encryption",
	reflect.TypeOf(SecureEnclave{}):      "secure_enclave",
	reflect.TypeOf(TPM{}):                "tpm",
	reflect.TypeOf(Token{}):              "token",
	reflect.TypeOf(StepError{}):          "step_error",
	reflect.TypeOf(LimitHit{}):           "limit_hit",
}

type jobSchemaObject struct {
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
	Defs       map[string]jobSchemaObject `json:"$defs"`
	Enum       []string                   `json:"enum"`
}

func jobLoadSchemaDoc(t *testing.T) jobSchemaObject {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(set.Root, "schemas", "managed", "v1", "defs", "host-crypto-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc jobSchemaObject
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func jobCompile(t *testing.T, rel string) *jsonschema.Schema {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	s, err := set.CompileDef(rel)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jobValidate(s *jsonschema.Schema, b []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

// jobFields lists a struct's JSON field names and which are omitted when
// empty (and so are not required).
func jobFields(t reflect.Type) (names []string, optional map[string]bool) {
	optional = map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		names = append(names, parts[0])
		for _, o := range parts[1:] {
			if o == "omitempty" || o == "omitzero" {
				optional[parts[0]] = true
			}
		}
	}
	sort.Strings(names)
	return names, optional
}

// jobStructsOf returns every struct type of this package reachable from t.
func jobStructsOf(t reflect.Type, seen map[reflect.Type]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] || t.PkgPath() != reflect.TypeOf(Report{}).PkgPath() {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		jobStructsOf(t.Field(i).Type, seen)
	}
}

// Every field of every report type is a property of its definition, every
// property is a field, and required is exactly the fields that are always
// written. This is the test that fails when report.go gains a field the
// schema lacks (or loses one it has).
func TestJobSchemaNamesEveryReportField(t *testing.T) {
	doc := jobLoadSchemaDoc(t)
	seen := map[reflect.Type]bool{}
	jobStructsOf(reflect.TypeOf(Report{}), seen)
	for typ := range seen {
		def, ok := jobDefOf[typ]
		if !ok {
			t.Errorf("%s is reachable from Report but has no schema definition (add one, and a jobDefOf entry)", typ.Name())
			continue
		}
		obj := doc
		if def != "" {
			if obj, ok = doc.Defs[def]; !ok {
				t.Errorf("schema has no $defs/%s for %s", def, typ.Name())
				continue
			}
		}
		names, optional := jobFields(typ)
		var props []string
		for p := range obj.Properties {
			props = append(props, p)
		}
		sort.Strings(props)
		if strings.Join(names, ",") != strings.Join(props, ",") {
			t.Errorf("%s: report.go fields %v, schema properties %v", typ.Name(), names, props)
		}
		var always []string
		for _, n := range names {
			if !optional[n] {
				always = append(always, n)
			}
		}
		req := append([]string(nil), obj.Required...)
		sort.Strings(req)
		if strings.Join(always, ",") != strings.Join(req, ",") {
			t.Errorf("%s: fields always written %v, schema requires %v", typ.Name(), always, req)
		}
	}
}

// The fields report.go gives constants for are plain strings in the schema
// (the protocol has no rule for negotiating a new enum value, so a closed
// enum would make a newer agent's value an error), and each one's
// description names every constant.
func TestJobSchemaDocumentsEveryConstant(t *testing.T) {
	doc := jobLoadSchemaDoc(t)
	desc := func(def, prop string) string {
		raw := doc.Properties[prop]
		if def != "" {
			raw = doc.Defs[def].Properties[prop]
		}
		var o struct {
			Type        string          `json:"type"`
			Enum        []string        `json:"enum"`
			Description string          `json:"description"`
			AP          json.RawMessage `json:"additionalProperties"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatalf("%s.%s: %v", def, prop, err)
		}
		if def == "" && prop == "sections" {
			if err := json.Unmarshal(o.AP, &o); err != nil {
				t.Fatal(err)
			}
		}
		if len(o.Enum) != 0 || o.Type != "string" {
			t.Errorf("%s.%s: want a plain string, got type %q enum %v", def, prop, o.Type, o.Enum)
		}
		return o.Description
	}
	for _, c := range []struct {
		def, prop string
		want      []string
	}{
		{"", "mode", []string{string(hostinventory.ModeLocal), string(hostinventory.ModeRemote)}},
		{"", "sections", []string{SectionOK, SectionPartial, SectionFailed, SectionUnsupported, SectionSkipped}},
		{"location", "found_by", []string{FoundByProcess, FoundByConfig, FoundByKnownLocation, FoundBySweep, FoundByPlatformStore}},
		{"private_key", "format", []string{KeyFormatPKCS1, KeyFormatSEC1, KeyFormatPKCS8, KeyFormatDSA, KeyFormatOpenSSH, KeyFormatPuTTY, KeyFormatPGP, KeyFormatSSH1, KeyFormatPlatformStore}},
		{"private_key", "protection", []string{KeyProtectionFile, KeyProtectionSoftware, KeyProtectionTPM, KeyProtectionHSM, KeyProtectionEnclave}},
		{"private_key", "provider_kind", []string{ProviderKindSoftware, ProviderKindTPM, ProviderKindSmartCard, ProviderKindSecureEnclave, ProviderKindUnknown}},
		{"keystore", "type", []string{KeystoreJKS, KeystoreJCEKS, KeystorePKCS12, KeystoreBCFKS, KeystoreBKS, KeystoreNSS, KeystoreGnuPG, KeystoreKeytab, KeystoreKeychain, KeystoreUBER}},
		{"keystore", "opened", []string{OpenedNot, OpenedWithoutPassword, OpenedDefaultPassword}},
		{"config_reference", "status", []string{RefFound, RefMissing, RefUnreadable, RefNotFollowed}},
	} {
		d := desc(c.def, c.prop)
		for _, v := range c.want {
			if !strings.Contains(d, v) {
				t.Errorf("%s.%s: the description does not name %q: %q", c.def, c.prop, v, d)
			}
		}
	}
	// And the schema is open: no object of it refuses a field it does not
	// name (the additive rule), which this test would otherwise not see.
	b, _ := os.ReadFile(filepath.Join(jobRepoRoot(t), "schemas", "managed", "v1", "defs", "host-crypto-report.json"))
	if strings.Contains(string(b), `"additionalProperties": false`) {
		t.Error("the report schema closes an object")
	}
}

func jobRepoRoot(t *testing.T) string {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	return set.Root
}

// jobEnumValue is the value a populated report gives a field whose schema
// is an enumeration.
var jobEnumValue = map[string]string{
	"Report.mode":              "local",
	"Location.found_by":        FoundByConfig,
	"Usage.kind":               "listener",
	"PrivateKey.format":        KeyFormatPKCS8,
	"PrivateKey.protection":    KeyProtectionTPM,
	"PrivateKey.provider_kind": ProviderKindTPM,
	"Keystore.type":            KeystorePKCS12,
	"Keystore.opened":          OpenedDefaultPassword,
	"ConfigReference.status":   RefFound,
}

// jobPopulate sets every field reachable from v to a non-zero value, so a
// field added to report.go is in the encoding whether or not anyone
// remembered it.
func jobPopulate(v reflect.Value, owner, field string) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		jobPopulate(v.Elem(), owner, field)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			name := strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0]
			jobPopulate(v.Field(i), v.Type().Name(), name)
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		jobPopulate(s.Index(0), owner, field)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		val := "v"
		if owner == "Report" && field == "sections" {
			val = SectionOK
		}
		m.SetMapIndex(reflect.ValueOf("k"), reflect.ValueOf(val))
		v.Set(m)
	case reflect.String:
		if e, ok := jobEnumValue[owner+"."+field]; ok {
			v.SetString(e)
		} else {
			v.SetString("x-" + field)
		}
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(7)
	}
}

func jobFullReport() *Report {
	var r Report
	jobPopulate(reflect.ValueOf(&r).Elem(), "Report", "")
	return &r
}

// A report with every field set validates, and so does the zero report a
// failed platform step leaves. (A field added to report.go and not to the
// schema fails TestJobSchemaNamesEveryReportField: the schema is open.)
func TestJobFullyPopulatedReportValidates(t *testing.T) {
	s := jobCompile(t, "defs/host-crypto-report.json")
	full := jobFullReport()
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := jobValidate(s, b); err != nil {
		t.Fatalf("a fully populated report does not validate: %v\n%s", err, b)
	}
	minimal := &Report{Collected: time.Now(), Mode: hostinventory.ModeRemote, Sections: map[string]string{SectionPlatform: SectionFailed}}
	b, _ = json.Marshal(minimal)
	if err := jobValidate(s, b); err != nil {
		t.Fatalf("a minimal report does not validate: %v\n%s", err, b)
	}

	// The schema is not inert: each of these must be refused.
	for name, mutate := range map[string]func(m map[string]any){
		"key as a certificate": func(m map[string]any) {
			m["certificates"].([]any)[0].(map[string]any)["certificate_pem"] = "-----BEGIN PRIVATE KEY-----"
		},
		"no sections": func(m map[string]any) { delete(m, "sections") },
		"wrong type": func(m map[string]any) {
			m["certificates"].([]any)[0].(map[string]any)["key_size"] = "big"
		},
		"no found_by": func(m map[string]any) {
			delete(m["certificates"].([]any)[0].(map[string]any)["location"].(map[string]any), "found_by")
		},
	} {
		var m map[string]any
		b, _ := json.Marshal(full)
		_ = json.Unmarshal(b, &m)
		mutate(m)
		b, _ = json.Marshal(m)
		if err := jobValidate(s, b); err == nil {
			t.Errorf("%s: the schema accepted it", name)
		}
	}
	// And open: what a newer agent adds is accepted.
	var m map[string]any
	b, _ = json.Marshal(full)
	_ = json.Unmarshal(b, &m)
	m["a_future_field"] = 1
	m["private_keys"].([]any)[0].(map[string]any)["a_future_field"] = "x"
	m["sections"].(map[string]any)["future"] = "deferred"
	b, _ = json.Marshal(m)
	if err := jobValidate(s, b); err != nil {
		t.Errorf("a newer agent's additions were refused: %v", err)
	}
}

// The job result and the local submission carry the report under the same
// definition.
func TestJobResultAndSubmissionCarryTheReport(t *testing.T) {
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := ResultPayload(jobFullReport(), DefaultMaxResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	res := map[string]any{"job_id": "6e1d8f3b-4c52-4a7f-8b9e-2d3c4b5e6f70", "success": true,
		"completed_at": "2026-11-23T14:00:00Z", "host_crypto": payload}
	if err := set.Validate("job-result.device-agent", res); err != nil {
		t.Fatal(err)
	}
	sub := map[string]any{"agent_id": "7f2e9a4c-5d63-4b80-9caf-3e4d5c6f7a81", "mode": "local",
		"collected_at": "2026-11-23T14:00:00Z", "report": payload}
	if err := set.Validate("host-crypto.submission", sub); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// The bound
// ---------------------------------------------------------------------------

func jobBigReport(n int) *Report {
	r := &Report{Collected: time.Now().UTC(), Mode: hostinventory.ModeLocal, Platform: "linux",
		Sections: map[string]string{SectionPlatform: SectionOK, SectionCertificates: SectionOK, SectionConfigs: SectionOK}}
	pemBlock := strings.Repeat("A", 1500)
	for i := 0; i < n; i++ {
		r.Certificates = append(r.Certificates, Certificate{
			Location:          Location{Path: "/etc/ssl/c" + strings.Repeat("x", i%7), FoundBy: FoundByKnownLocation},
			FingerprintSHA256: strings.Repeat("0", 64), CertificatePEM: pemBlock,
		})
		r.Configs = append(r.Configs, CryptoConfig{Location: Location{Path: "/etc/x", FoundBy: FoundByKnownLocation}, Product: "nginx"})
	}
	return r
}

func TestJobResultPayloadIsBoundedHonestly(t *testing.T) {
	s := jobCompile(t, "defs/host-crypto-report.json")
	orig := jobBigReport(400)
	full, _ := json.Marshal(orig)

	// Fits: unchanged, the same report.
	b, sent, err := ResultPayload(orig, len(full))
	if err != nil || sent != orig || len(b) != len(full) {
		t.Fatalf("a report within the bound was changed: %v", err)
	}

	// Just over: certificate PEM goes first, and says so.
	b, sent, err = ResultPayload(orig, len(full)-10)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > len(full)-10 || len(sent.Certificates) != 400 || sent.Certificates[0].CertificatePEM != "" {
		t.Fatalf("PEM was not dropped first: %d bytes, %d certificates", len(b), len(sent.Certificates))
	}
	if sent.Sections[SectionCertificates] != SectionPartial || !jobHasLimit(sent, SectionCertificates) {
		t.Fatalf("the cut is not recorded: %v %v", sent.Sections, sent.Limits)
	}
	if orig.Certificates[0].CertificatePEM == "" || orig.Sections[SectionCertificates] != SectionOK || len(orig.Limits) != 0 {
		t.Fatal("the caller's report was changed")
	}
	if err := jobValidate(s, b); err != nil {
		t.Fatal(err)
	}

	// Far over: lists are cut, each cut section partial with a limit.
	b, sent, err = ResultPayload(orig, 20000)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 20000 || len(sent.Certificates)+len(sent.Configs) >= 800 {
		t.Fatalf("not cut: %d bytes, %d certificates, %d configs", len(b), len(sent.Certificates), len(sent.Configs))
	}
	for _, sec := range []string{SectionCertificates, SectionConfigs} {
		if sent.Sections[sec] != SectionPartial || !jobHasLimit(sent, sec) {
			t.Errorf("%s cut without saying so: %v %v", sec, sent.Sections, sent.Limits)
		}
	}
	if err := jobValidate(s, b); err != nil {
		t.Fatal(err)
	}

	// Impossible: an error, never a report over the bound.
	if _, _, err := ResultPayload(orig, 50); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("a 50-byte bound: %v", err)
	}
	// Unbounded: unchanged.
	if _, sent, err := ResultPayload(orig, 0); err != nil || sent != orig {
		t.Fatalf("unbounded: %v", err)
	}
}

func jobHasLimit(r *Report, section string) bool {
	for _, l := range r.Limits {
		if l.Section == section && l.Limit == LimitMaxResultBytes {
			return true
		}
	}
	return false
}

// The step errors are cut last, and the cut says how many went.
func TestJobResultPayloadCutsErrorsLast(t *testing.T) {
	r := &Report{Collected: time.Now().UTC(), Mode: hostinventory.ModeLocal, Platform: "linux",
		Sections: map[string]string{SectionPlatform: SectionOK}}
	for i := 0; i < 200; i++ {
		r.Errors = append(r.Errors, StepError{Step: SectionConfigs, Message: strings.Repeat("e", 250)})
	}
	b, sent, err := ResultPayload(r, 6000)
	if err != nil {
		t.Fatal(err)
	}
	last := sent.Errors[len(sent.Errors)-1]
	if len(b) > 6000 || last.Step != "result" || !strings.Contains(last.Message, "further errors left out") {
		t.Fatalf("%d bytes, last error %+v", len(b), last)
	}
	if len(r.Errors) != 200 {
		t.Fatal("the caller's errors were changed")
	}
}

// ---------------------------------------------------------------------------
// The backstop
// ---------------------------------------------------------------------------

// A host-supplied string that only RESEMBLES key material (a file named like
// a PuTTY key, a keystore alias spelled as a PEM label, a path holding the
// OpenSSH magic in base64) is data: the report is sent, the value is
// replaced with WithheldName and noted, and no section is marked partial for
// it. One name can never suppress the host's report.
func TestJobKeyShapedNamesNeverStopTheReport(t *testing.T) {
	for _, name := range []string{
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN PGP PRIVATE KEY BLOCK-----", "/etc/ssl/PuTTY-User-Key-File-2.pem", "SSH PRIVATE KEY FILE FORMAT 1.1",
		"/home/u/b3BlbnNzaC1rZXktdjE/id", "-----END EC PRIVATE KEY-----",
	} {
		r := jobFullReport()
		r.Sections = map[string]string{SectionPlatform: SectionOK, SectionKeystores: SectionOK, SectionCertificates: SectionOK}
		r.Keystores[0].Entries[0].Alias = name
		r.Certificates[0].Location.Path = name
		b, sent, err := ResultPayload(r, DefaultMaxResultBytes)
		if err != nil {
			t.Fatalf("%q stopped the report: %v", name, err)
		}
		if strings.Contains(string(b), name) || sent.Keystores[0].Entries[0].Alias != WithheldName || sent.Certificates[0].Location.Path != WithheldName {
			t.Errorf("%q: not withheld", name)
		}
		if sent.Sections[SectionKeystores] != SectionOK || sent.Sections[SectionCertificates] != SectionOK {
			t.Errorf("%q: a withheld name made a section partial: %v", name, sent.Sections)
		}
		noted := 0
		for _, e := range sent.Errors {
			if strings.Contains(e.Message, "name was withheld") {
				noted++
			}
		}
		if noted != 2 {
			t.Errorf("%q: %d notes, want 2: %+v", name, noted, sent.Errors)
		}
		if r.Keystores[0].Entries[0].Alias != name {
			t.Fatal("the caller's report was changed")
		}
		if _, err := OutputData(r); err != nil {
			t.Errorf("%q stopped the standalone record: %v", name, err)
		}
	}
}

// Real key material in a field (a leaking parser) is removed from that
// field, the section is marked partial with the item named, and the report
// is still sent without a byte of the key.
func TestJobKeyMaterialInAFieldIsRemoved(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	secrets := ksSecretsOf(t, key)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for name, leak := range map[string]string{
		"pem block":       pemText,
		"pem in a phrase": "unparsed: " + pemText + " (see file)",
		"bare base64 der": base64.StdEncoding.EncodeToString(der),
		"hex der":         fmt.Sprintf("%x", der),
		"hex in a phrase": "key " + fmt.Sprintf("%x", der) + " left",
	} {
		r := jobFullReport()
		r.Sections = map[string]string{SectionPlatform: SectionOK, SectionPrivateKeys: SectionOK}
		r.PrivateKeys[0].Unknown = leak
		b, sent, err := ResultPayload(r, DefaultMaxResultBytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		jobAssertNoSecret(t, name, b, secrets)
		if sent.PrivateKeys[0].Unknown != "" || sent.Sections[SectionPrivateKeys] != SectionPartial {
			t.Fatalf("%s: unknown %q, section %q", name, sent.PrivateKeys[0].Unknown, sent.Sections[SectionPrivateKeys])
		}
		found := false
		for _, e := range sent.Errors {
			found = found || (e.Step == SectionPrivateKeys && strings.Contains(e.Message, "item 0") && strings.Contains(e.Message, "removed"))
		}
		if !found {
			t.Fatalf("%s: the removal is not recorded: %+v", name, sent.Errors)
		}
	}
	// The last, structural check still refuses a complete block in bytes.
	if jobCheckNoKeyMaterial([]byte(pemText)) == nil || jobCheckNoKeyMaterial([]byte("-----BEGIN PRIVATE KEY----- name")) != nil {
		t.Fatal("the structural check is wrong in one direction")
	}
}

// ---------------------------------------------------------------------------
// End to end: generated keys on disk, the real collector, the wire bytes
// ---------------------------------------------------------------------------

func jobWritePEM(t *testing.T, path, label string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// jobKeyDir writes one generated key of each common kind, and a certificate,
// to a fresh directory, and returns the directory and the keys' private
// bytes (ksSecretsOf).
func jobKeyDir(t *testing.T) (string, [][]byte) {
	t.Helper()
	dir := t.TempDir()
	var secrets [][]byte

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jobWritePEM(t, filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))
	secrets = append(secrets, ksSecretsOf(t, rsaKey)...)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	jobWritePEM(t, filepath.Join(dir, "backup.txt"), "EC PRIVATE KEY", sec1)
	secrets = append(secrets, ksSecretsOf(t, ecKey)...)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	jobWritePEM(t, filepath.Join(dir, "signing.pem"), "PRIVATE KEY", p8)
	secrets = append(secrets, ksSecretsOf(t, edKey)...)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(sshKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets = append(secrets, ksSecretsOf(t, sshKey)...)

	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "job.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	jobWritePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", certDER)
	return dir, secrets
}

// jobAssertNoSecret is ksFindSecret over bytes already serialized.
func jobAssertNoSecret(t *testing.T, label string, b []byte, secrets [][]byte) {
	t.Helper()
	if where := ksFindSecret(json.RawMessage(b), secrets...); where != "" {
		t.Fatalf("%s: private material in what is sent: %s", label, where)
	}
}

// The real collector sweeps a directory of generated keys; the bytes that
// would be sent (a job result, a local submission) and the standalone record
// hold every key's description and no run of any key's private bytes.
func TestJobSecrecyOfTheSerializedReport(t *testing.T) {
	dir, secrets := jobKeyDir(t)
	rep, err := Collect(context.Background(), NewLocalTarget(), Options{SweepRoots: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, k := range rep.PrivateKeys {
		if strings.HasPrefix(k.Location.Path, dir) {
			found++
		}
	}
	if found < 4 {
		t.Fatalf("the sweep found %d of the 4 generated keys (sections %v); the test proves nothing", found, rep.Sections)
	}
	b, _, err := ResultPayload(rep, DefaultMaxResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	jobAssertNoSecret(t, "result payload", b, secrets)
	if err := jobValidate(jobCompile(t, "defs/host-crypto-report.json"), b); err != nil {
		t.Fatalf("a real report does not validate: %v", err)
	}
	data, err := OutputData(rep)
	if err != nil {
		t.Fatal(err)
	}
	ob, _ := json.Marshal(data)
	jobAssertNoSecret(t, "standalone record", ob, secrets)

	// The check itself is live: the same bytes with one key's private
	// scalar appended, hex-encoded, are caught.
	leaky := append(append([]byte(nil), b...), []byte(strings.ToUpper(jobHex(secrets[0])))...)
	if ksFindSecret(json.RawMessage(leaky), secrets...) == "" {
		t.Fatal("the secrecy check is inert")
	}
}

func jobHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// TestJobValidateRealOutputs validates standalone output files from real runs
// (HOSTCRYPTO_JOB_OUTPUTS: space-separated paths): every record against the
// output schema, every report against the managed definition, and no private
// key marker anywhere. It prints each report's section states and counts.
func TestJobValidateRealOutputs(t *testing.T) {
	paths := strings.Fields(os.Getenv("HOSTCRYPTO_JOB_OUTPUTS"))
	if len(paths) == 0 {
		t.Skip("set HOSTCRYPTO_JOB_OUTPUTS to validate real outputs")
	}
	rs := outputschema.Compile(t)
	ds := jobCompile(t, "defs/host-crypto-report.json")
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if err := outputschema.Validate(rs, line); err != nil {
				t.Errorf("%s: record: %v", p, err)
			}
			if err := jobCheckNoKeyMaterial(line); err != nil {
				t.Errorf("%s: %v", p, err)
			}
			var rec struct {
				Kind string `json:"kind"`
				Data struct {
					Report json.RawMessage `json:"report"`
				} `json:"data"`
			}
			_ = json.Unmarshal(line, &rec)
			if rec.Kind != "host_crypto" {
				continue
			}
			if err := jobValidate(ds, rec.Data.Report); err != nil {
				t.Errorf("%s: report: %v", p, err)
			}
			var r Report
			if err := json.Unmarshal(rec.Data.Report, &r); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: mode %s platform %s access %s", p, r.Mode, r.Platform, jobAccess(r.Access))
			t.Logf("  counts: certificates %d, private_keys %d, keystores %d, ssh authorized_keys %d known_hosts %d host_public_keys %d, configs %d, libraries %d, volumes %d, tokens %d, errors %d, limits %d",
				len(r.Certificates), len(r.PrivateKeys), len(r.Keystores), len(r.SSH.AuthorizedKeys), len(r.SSH.KnownHosts),
				len(r.SSH.HostPublicKeys), len(r.Configs), len(r.Libraries), len(r.Protection.Volumes), len(r.Protection.Tokens),
				len(r.Errors), len(r.Limits))
			var secs []string
			for k, v := range r.Sections {
				secs = append(secs, k+"="+v)
			}
			sort.Strings(secs)
			t.Logf("  sections: %s", strings.Join(secs, " "))
		}
		_ = f.Close()
	}
}

func jobAccess(a Access) string {
	s := func(b *bool) string {
		if b == nil {
			return "unknown"
		}
		if *b {
			return "yes"
		}
		return "no"
	}
	return "elevated=" + s(a.Elevated) + " full_disk_access=" + s(a.FullDiskAccess)
}

// A permission denial says what the platform needs, once per platform, and
// not when the message already says it; an elevated run takes it back off.
// The same step and message is counted, not repeated.
func TestJobRecordErrorPrivilegeAndRepeats(t *testing.T) {
	for platform, want := range map[string]string{
		hostinventory.PlatformLinux:   "/etc/ssl/private: hostcrypto: permission denied (needs root)",
		hostinventory.PlatformDarwin:  "/etc/ssl/private: hostcrypto: permission denied (needs root and Full Disk Access)",
		hostinventory.PlatformWindows: "/etc/ssl/private: hostcrypto: permission denied (needs SYSTEM or an elevated administrator)",
	} {
		r := &Report{Platform: platform}
		r.partial(SectionPrivateKeys, fmt.Errorf("/etc/ssl/private: %w", ErrPermission))
		if got := r.Errors[0].Message; got != want {
			t.Errorf("%s: %q, want %q", platform, got, want)
		}
	}
	r := &Report{Platform: hostinventory.PlatformLinux}
	r.partial(SectionCertificates, errors.New("/opt: 7 directories could not be read"))
	r.partial(SectionCertificates, errors.New("/opt: 7 directories could not be read"))
	r.partial(SectionCertificates, errors.New("/opt: 7 directories could not be read"))
	r.partial(SectionConfigs, errors.New("/opt: 7 directories could not be read"))
	r.partial(SectionCertificates, errors.New("/opt: 2 entries could not be read"))
	r.partial(SectionProcesses, errors.New("12 processes could not be inspected without root: permission denied"))
	msgs := []string{}
	for _, e := range r.Errors {
		msgs = append(msgs, e.Step+"|"+e.Message)
	}
	want := []string{
		"certificates|/opt: 7 directories could not be read (needs root) (3 times)",
		"configs|/opt: 7 directories could not be read (needs root)",
		"certificates|/opt: 2 entries could not be read",
		"processes|12 processes could not be inspected without root: permission denied",
	}
	if strings.Join(msgs, "\n") != strings.Join(want, "\n") {
		t.Fatalf("errors:\n%s\nwant:\n%s", strings.Join(msgs, "\n"), strings.Join(want, "\n"))
	}
	yes, no := true, false
	r.Access.Elevated = &yes
	r.jobDropPrivilegeNotes()
	if r.Errors[0].Message != "/opt: 7 directories could not be read (3 times)" {
		t.Fatalf("elevated run kept the note: %q", r.Errors[0].Message)
	}
	d := &Report{Platform: hostinventory.PlatformDarwin, Access: Access{Elevated: &yes, FullDiskAccess: &no}}
	d.partial(SectionSSH, ErrPermission)
	d.jobDropPrivilegeNotes()
	if !strings.Contains(d.Errors[0].Message, "Full Disk Access") {
		t.Fatalf("root without Full Disk Access dropped the note: %q", d.Errors[0].Message)
	}
}

// Collect takes the notes off at the end of an elevated run, and keeps them
// on an unprivileged one (the call in Collect, not only the method).
func TestJobCollectDropsPrivilegeNotesWhenElevated(t *testing.T) {
	saved := passes
	defer func() { passes = saved }()
	for _, elevated := range []bool{true, false} {
		passes = []pass{func(_ context.Context, c *collection) {
			e := elevated
			c.report.Access.Elevated = &e
			c.partial(SectionPrivateKeys, fmt.Errorf("/etc/ssl/private: %w", ErrPermission))
		}}
		rep, err := Collect(context.Background(), newTgtFakeTarget(true), Options{Platform: hostinventory.PlatformLinux})
		if err != nil {
			t.Fatal(err)
		}
		has := strings.Contains(rep.Errors[0].Message, "needs root")
		if has == elevated {
			t.Errorf("elevated=%v: %q", elevated, rep.Errors[0].Message)
		}
	}
}

// The reviewer's case: 60,000 swept keys in a report with home directories
// on. The cut keeps as many as fit (not half), and private keys, the sweep
// that found them and home directories all read partial with the limit.
func TestJobBoundCutsToFitAndMarksThePasses(t *testing.T) {
	s := jobCompile(t, "defs/host-crypto-report.json")
	r := &Report{Collected: time.Now().UTC(), Mode: hostinventory.ModeLocal, Platform: "linux", Sections: map[string]string{},
		Scope: Scope{HomeDirectories: true}}
	for _, sec := range []string{SectionPlatform, SectionPrivateKeys, SectionSweep, SectionHomeDirectories, SectionCertificates} {
		r.Sections[sec] = SectionOK
	}
	for i := 0; i < 60000; i++ {
		r.PrivateKeys = append(r.PrivateKeys, PrivateKey{Location: Location{Path: fmt.Sprintf("/home/u%d/.ssh/%s", i, strings.Repeat("k", 200)), FoundBy: FoundBySweep},
			Format: KeyFormatPKCS8, Algorithm: "RSA", SizeBits: 2048, Protection: KeyProtectionFile})
	}
	b, sent, err := ResultPayload(r, DefaultMaxResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := jobValidate(s, b); err != nil {
		t.Fatal(err)
	}
	if len(b) > DefaultMaxResultBytes || len(b) < DefaultMaxResultBytes-2048 {
		t.Fatalf("%d bytes sent: the cut is not to fit", len(b))
	}
	for _, sec := range []string{SectionPrivateKeys, SectionSweep, SectionHomeDirectories} {
		if sent.Sections[sec] != SectionPartial || !jobHasLimit(sent, sec) {
			t.Errorf("%s: %q, limits %v", sec, sent.Sections[sec], sent.Limits)
		}
	}
	if sent.Sections[SectionCertificates] != SectionOK {
		t.Errorf("an uncut section was marked: %v", sent.Sections)
	}
	t.Logf("kept %d of %d keys in %d bytes", len(sent.PrivateKeys), len(r.PrivateKeys), len(b))
}
