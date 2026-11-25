package hostcrypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// platFakeWin is tgtFakeTarget that also takes stdin, as the Windows SSH
// runner does: a PowerShell program sent by platPS arrives here, is decoded
// exactly as the Windows target's tests decode theirs (tgtDecodePS), and is
// answered by which program it is.
type platFakeWin struct {
	*tgtFakeTarget
	t       *testing.T
	answers map[string]string // program name -> JSON answer
	mu      sync.Mutex
	sent    []string // the program names, in order
	args    []map[string]any
}

func newPlatFakeWin(t *testing.T, local bool) *platFakeWin {
	return &platFakeWin{tgtFakeTarget: newTgtFakeTarget(local), t: t, answers: map[string]string{}}
}

// platPSPrograms are this file set's PowerShell programs, by name.
func platPSPrograms() map[string]string {
	return map[string]string{
		"stores":     platPSStores,
		"protection": platPSProtection,
		"libraries":  platPSLibraries,
		"running":    platPSRunning,
	}
}

func (f *platFakeWin) RunInput(_ context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	script, args := tgtDecodePS(f.t, argv, stdin)
	name := "unknown"
	for n, body := range platPSPrograms() {
		if script == platPSPrelude+body {
			name = n
		}
	}
	f.mu.Lock()
	f.sent = append(f.sent, name)
	f.args = append(f.args, args)
	f.mu.Unlock()
	ans, ok := f.answers[name]
	if !ok {
		return nil, []byte("not scripted"), 1, nil
	}
	return []byte("J:" + base64.StdEncoding.EncodeToString([]byte(ans))), nil, 0, nil
}

var _ hostinventory.InputRunner = (*platFakeWin)(nil)

// platCollect runs only the platform passes over t, as Collect does.
func platCollect(t *testing.T, target Target, opts Options) *Report {
	t.Helper()
	saved := passes
	passes = []pass{platPass, platRunningPass}
	defer func() { passes = saved }()
	opts.Now = tgtNow
	rep, err := Collect(context.Background(), target, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// platKey is a generated key with its certificate, for the store and
// projection tests.
type platKey struct {
	key     *ecdsa.PrivateKey
	certDER []byte
	keyDER  []byte
	certPEM []byte
	keyPEM  []byte
}

func platNewKey(t *testing.T, cn string) platKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return platKey{key: key, certDER: der, keyDER: kder,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})}
}

// secret is the key's private scalar, the bytes no record may carry.
func (k platKey) secret() []byte {
	b, err := k.key.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// platJSON marshals v for a hand-written answer.
func platJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func platHasUsage(l Location, kind, process string, port int) bool {
	for _, u := range l.UsedBy {
		if u.Kind == kind && (process == "" || u.Process == process) && (port == 0 || u.Port == port) {
			return true
		}
	}
	return false
}

func platErrorsContain(rep *Report, step, sub string) bool {
	for _, e := range rep.Errors {
		if e.Step == step && strings.Contains(e.Message, sub) {
			return true
		}
	}
	return false
}
