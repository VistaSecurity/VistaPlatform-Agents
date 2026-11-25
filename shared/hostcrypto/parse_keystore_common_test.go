package hostcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Shared helpers for the keystore parser tests. Every key is generated here,
// in the test; nothing private is committed.

// ksTestRSA hands out one of a few RSA keys generated once per run: a 2048-bit
// key costs tens of milliseconds and the fixtures need many.
func ksTestRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	ksRSAPool.mu.Lock()
	defer ksRSAPool.mu.Unlock()
	if len(ksRSAPool.keys) < 3 {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		ksRSAPool.keys = append(ksRSAPool.keys, k)
	}
	ksRSAPool.next++
	return ksRSAPool.keys[ksRSAPool.next%len(ksRSAPool.keys)]
}

var ksRSAPool struct {
	mu   sync.Mutex
	keys []*rsa.PrivateKey
	next int
}

func ksTestECDSA(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ksTestEd25519(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ksTestCert makes a self-signed certificate for key.
func ksTestCert(t testing.TB, key crypto.Signer, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example Fixture"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		DNSNames:              []string{cn + ".example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ksPKCS8 is the PKCS#8 DER of a key: the bytes a leak would carry.
func ksPKCS8(t testing.TB, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ksSecretsOf lists the private byte strings of a key that must never appear
// in a result: its private scalars. Not its whole PKCS#8 encoding, which also
// carries the algorithm OID and (RSA, ECDSA) the public key, both of which a
// certificate rightly carries too.
func ksSecretsOf(t testing.TB, key any) [][]byte {
	t.Helper()
	var out [][]byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		out = append(out, k.D.Bytes())
		for _, p := range k.Primes {
			out = append(out, p.Bytes())
		}
	case *ecdsa.PrivateKey:
		b, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	case ed25519.PrivateKey:
		out = append(out, k.Seed())
	}
	return out
}

// ksAssertNoSecret fails if any 16-byte window of any secret appears in v's
// JSON raw, as hex (either case) or as base64 (standard or URL alphabet, at
// every alignment).
func ksAssertNoSecret(t testing.TB, label string, v any, secrets ...[]byte) {
	t.Helper()
	if where := ksFindSecret(v, secrets...); where != "" {
		t.Fatalf("%s: private material in the result: %s", label, where)
	}
}

// ksFindSecret says where a secret appears in v's JSON, or "".
func ksFindSecret(v any, secrets ...[]byte) string {
	blob, err := json.Marshal(v)
	if err != nil {
		return "marshal failed: " + err.Error()
	}
	// JSON replaces invalid UTF-8, so raw bytes are looked for in the
	// strings and byte slices of the value itself as well.
	js := string(blob) + "\x00" + ksAllStrings(reflect.ValueOf(v))
	lower := strings.ToLower(js)
	const w = 16
	for si, s := range secrets {
		if len(s) < w {
			return fmt.Sprintf("secret %d shorter than the window", si)
		}
		for i := 0; i+w <= len(s); i++ {
			win := s[i : i+w]
			if strings.Contains(js, string(win)) {
				return fmt.Sprintf("secret %d raw at offset %d", si, i)
			}
			if strings.Contains(lower, hex.EncodeToString(win)) {
				return fmt.Sprintf("secret %d as hex at offset %d", si, i)
			}
		}
		for shift := 0; shift < 3; shift++ {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
				e := enc.EncodeToString(s[shift:])
				// 20 characters cover 15 bytes; step by whole groups and stay
				// clear of the final, padded group.
				for i := 0; i+20 <= len(e)-4; i += 4 {
					if strings.Contains(js, e[i:i+20]) {
						return fmt.Sprintf("secret %d as base64 near offset %d", si, shift+i/4*3)
					}
				}
			}
		}
	}
	return ""
}

// ksAllStrings joins every string and byte slice reachable from v.
func ksAllStrings(v reflect.Value) string {
	var sb strings.Builder
	var walk func(reflect.Value, int)
	walk = func(v reflect.Value, depth int) {
		if depth > 20 || !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.String:
			sb.WriteString(v.String())
			sb.WriteByte(0)
		case reflect.Slice, reflect.Array:
			if v.Type().Elem().Kind() == reflect.Uint8 && v.Kind() == reflect.Slice {
				sb.Write(v.Bytes())
				sb.WriteByte(0)
				return
			}
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), depth+1)
			}
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem(), depth+1)
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), depth+1)
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				walk(it.Key(), depth+1)
				walk(it.Value(), depth+1)
			}
		}
	}
	walk(v, 0)
	return sb.String()
}

// The guard must be able to fail: a value carrying the secret in each
// encoding is caught, and a clean one is not.
func TestKsFindSecret_CatchesEachEncoding(t *testing.T) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	for name, leaked := range map[string]any{
		"raw":    string(secret[10:40]),
		"bytes":  secret[3:33], // json marshals []byte as base64
		"hex":    hex.EncodeToString(secret[5:30]),
		"HEX":    strings.ToUpper(hex.EncodeToString(secret[5:30])),
		"base64": base64.StdEncoding.EncodeToString(secret[1:50]),
		"b64url": base64.URLEncoding.EncodeToString(secret[2:60]),
	} {
		if ksFindSecret(map[string]any{"x": leaked}, secret) == "" {
			t.Errorf("%s: the guard did not catch a leak", name)
		}
	}
	if w := ksFindSecret(map[string]string{"x": "nothing here"}, secret); w != "" {
		t.Errorf("the guard failed a clean value: %s", w)
	}
}

func TestKsCertificate_Conventions(t *testing.T) {
	key := ksTestECDSA(t)
	c := ksTestCert(t, key, "svc", false)
	got, ok := ksCertificate(c.Raw)
	if !ok {
		t.Fatal("not parsed")
	}
	if got.KeyAlgorithm != "ECDSA" || got.KeySize != 256 || got.Curve != "P-256" {
		t.Errorf("key: %q %d %q", got.KeyAlgorithm, got.KeySize, got.Curve)
	}
	if got.FingerprintSHA256 != ksDERFingerprint(c.Raw) || len(got.FingerprintSHA256) != 64 || strings.ToLower(got.FingerprintSHA256) != got.FingerprintSHA256 {
		t.Errorf("fingerprint spelling: %q", got.FingerprintSHA256)
	}
	spki, _ := x509.MarshalPKIXPublicKey(key.Public())
	if got.PublicKeySHA256 != ksDERFingerprint(spki) {
		t.Error("public key hash is not the SPKI's SHA-256")
	}
	if got.NotAfter != "2036-01-01T00:00:00Z" || got.NotBefore != "2026-01-01T00:00:00Z" {
		t.Errorf("dates: %q %q", got.NotBefore, got.NotAfter)
	}
	if !got.SelfSigned || got.IsCA || got.CertificatePEM == "" || !reflect.DeepEqual(got.Location, Location{}) {
		t.Errorf("flags or location: %+v", got)
	}
	if _, ok := ksCertificate([]byte("not a certificate")); ok {
		t.Error("garbage parsed as a certificate")
	}
	ed := ksTestEd25519(t)
	if g, _ := ksCertificate(ksTestCert(t, ed, "ed", false).Raw); g.KeyAlgorithm != "Ed25519" || g.KeySize != 256 {
		t.Errorf("ed25519: %q %d", g.KeyAlgorithm, g.KeySize)
	}
	if g, _ := ksCertificate(ksTestCert(t, ksTestRSA(t), "rsa", true).Raw); g.KeyAlgorithm != "RSA" || g.KeySize != 2048 || !g.IsCA {
		t.Errorf("rsa: %q %d", g.KeyAlgorithm, g.KeySize)
	}
}
