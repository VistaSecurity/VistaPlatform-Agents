// Package kubetest is an in-process Kubernetes API server for tests: it
// serves fixture files over TLS, checks the service-account token, honours
// list paging and the Secret type selector, and records every request.
//
// It serves only GET. A fixture directory mirrors API paths:
// testdata/x/api/v1/pods.json is served at /api/v1/pods. A file holding
// "items" is a list; a namespaced list path (/api/v1/namespaces/shop/pods) is
// answered from the cluster-wide file by namespace. Any other file is one
// object. Placeholders in fixtures are replaced with material generated for
// the test, so no certificate or key is ever committed:
//
//	{{CERT:name}}  base64 of a PEM certificate (for []byte fields)
//	{{PEM:name}}   the same PEM as a JSON string body (for ConfigMap data)
//	{{KEY:name}}   base64 of that certificate's PEM private key
//	{{CSR:name}}   base64 of a PEM certificate signing request
//	{{PORT:name}}  the port of a TLS listener on 127.0.0.1 presenting that
//	               certificate (a stand-in for a kubelet)
//
// A name starting with "ca-" is a CA certificate.
package kubetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Token is the service-account token the server accepts.
const Token = "synthetic-service-account-token"

// Request is one request the server received.
type Request struct {
	Path  string
	Query url.Values
}

type material struct {
	certPEM []byte
	keyPEM  []byte
	csrPEM  []byte
	port    int
}

// Cluster is a fake API server and the service-account directory for it.
type Cluster struct {
	t      testing.TB
	Server *httptest.Server
	// Dir is a service-account directory (token, ca.crt, namespace).
	Dir string

	mu       sync.Mutex
	lists    map[string][]json.RawMessage
	objects  map[string]json.RawMessage
	statuses map[string]int
	requests []Request
	pki      map[string]*material
}

// New starts a server with no objects. It answers /version and 404 for
// everything else until fixtures are loaded.
func New(t testing.TB) *Cluster {
	t.Helper()
	c := &Cluster{
		t: t, lists: map[string][]json.RawMessage{}, objects: map[string]json.RawMessage{},
		statuses: map[string]int{}, pki: map[string]*material{},
	}
	c.Server = httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Server.Close)
	c.Dir = t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Server.Certificate().Raw})
	for name, data := range map[string][]byte{"token": []byte(Token + "\n"), "ca.crt": ca, "namespace": []byte("vista-agents")} {
		if err := os.WriteFile(filepath.Join(c.Dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.SetObject("/version", map[string]string{"major": "1", "minor": "33", "gitVersion": "v1.33.4", "platform": "linux/amd64"})
	return c
}

// HostPort is the server's address, as the kubelet would give it to a pod.
func (c *Cluster) HostPort() (host, port string) {
	host, port, err := net.SplitHostPort(c.Server.Listener.Addr().String())
	if err != nil {
		c.t.Fatal(err)
	}
	return host, port
}

// Load serves every fixture file under dir.
func (c *Cluster) Load(dir string) {
	c.t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		apiPath := "/" + strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		data := c.expand(raw)
		var doc struct {
			Items *[]json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			c.t.Fatalf("%s: %v", path, err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if doc.Items != nil {
			c.lists[apiPath] = *doc.Items
		} else {
			c.objects[apiPath] = data
		}
		return nil
	})
	if err != nil {
		c.t.Fatal(err)
	}
}

// SetList serves items as the list at path.
func (c *Cluster) SetList(path string, items ...any) {
	c.t.Helper()
	var raw []json.RawMessage
	for _, item := range items {
		b, err := json.Marshal(item)
		if err != nil {
			c.t.Fatal(err)
		}
		raw = append(raw, c.expand(b))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists[path] = raw
}

// SetObject serves obj at path.
func (c *Cluster) SetObject(path string, obj any) {
	c.t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.objects[path] = c.expandLocked(b)
}

// SetStatus makes path (a list path or an object path) answer with an HTTP
// status instead of its content; 0 removes the override.
func (c *Cluster) SetStatus(path string, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if status == 0 {
		delete(c.statuses, path)
		return
	}
	c.statuses[path] = status
}

// Requests returns the requests received so far.
func (c *Cluster) Requests() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Request(nil), c.requests...)
}

var namespacedPath = regexp.MustCompile(`^(/api/v1|/apis/[^/]+/[^/]+)/namespaces/([^/]+)/([^/]+)$`)

func (c *Cluster) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.requests = append(c.requests, Request{Path: r.URL.Path, Query: r.URL.Query()})
	status := c.statuses[r.URL.Path]
	obj, isObj := c.objects[r.URL.Path]
	items, isList := c.lists[r.URL.Path]
	namespace := ""
	if !isObj && !isList {
		if m := namespacedPath.FindStringSubmatch(r.URL.Path); m != nil {
			if all, ok := c.lists[m[1]+"/"+m[3]]; ok {
				items, isList, namespace = all, true, m[2]
			}
		}
	}
	c.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method != http.MethodGet:
		writeStatus(w, http.StatusMethodNotAllowed, "this server is read-only")
	case r.Header.Get("Authorization") != "Bearer "+Token:
		writeStatus(w, http.StatusUnauthorized, "Unauthorized")
	case status != 0:
		writeStatus(w, status, strings.TrimPrefix(r.URL.Path, "/")+" is forbidden or unavailable (synthetic)")
	case isObj:
		_, _ = w.Write(obj)
	case isList:
		c.serveList(w, r, items, namespace)
	default:
		writeStatus(w, http.StatusNotFound, "the server could not find the requested resource")
	}
}

func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": msg, "code": code})
}

func (c *Cluster) serveList(w http.ResponseWriter, r *http.Request, items []json.RawMessage, namespace string) {
	wantType := ""
	if sel := r.URL.Query().Get("fieldSelector"); sel != "" {
		t, ok := strings.CutPrefix(sel, "type=")
		if !ok {
			writeStatus(w, http.StatusBadRequest, "unsupported field selector")
			return
		}
		wantType = t
	}
	var kept []json.RawMessage
	for _, item := range items {
		var head struct {
			Type     string `json:"type"`
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		_ = json.Unmarshal(item, &head)
		if (namespace == "" || head.Metadata.Namespace == namespace) && (wantType == "" || head.Type == wantType) {
			kept = append(kept, item)
		}
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("continue"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = len(kept)
	}
	if start > len(kept) {
		start = len(kept)
	}
	end := min(start+limit, len(kept))
	next := ""
	if end < len(kept) {
		next = strconv.Itoa(end)
	}
	page := kept[start:end]
	if page == nil {
		page = []json.RawMessage{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "List", "apiVersion": "v1", "metadata": map[string]string{"continue": next}, "items": page})
}

// ---- generated certificates ----

var placeholder = regexp.MustCompile(`\{\{(CERT|PEM|KEY|CSR|PORT):([A-Za-z0-9._-]+)\}\}`)

func (c *Cluster) expand(data []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expandLocked(data)
}

func (c *Cluster) expandLocked(data []byte) []byte {
	return placeholder.ReplaceAllFunc(data, func(m []byte) []byte {
		parts := placeholder.FindSubmatch(m)
		mat := c.materialLocked(string(parts[2]))
		switch string(parts[1]) {
		case "CERT":
			return []byte(base64.StdEncoding.EncodeToString(mat.certPEM))
		case "KEY":
			return []byte(base64.StdEncoding.EncodeToString(mat.keyPEM))
		case "CSR":
			return []byte(base64.StdEncoding.EncodeToString(mat.csrPEM))
		case "PORT":
			return []byte(strconv.Itoa(c.serveTLS(mat)))
		}
		quoted, _ := json.Marshal(string(mat.certPEM))
		return quoted[1 : len(quoted)-1]
	})
}

func (c *Cluster) materialLocked(name string) *material {
	if m := c.pki[name]; m != nil {
		return m
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		c.t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	isCA := strings.HasPrefix(name, "ca-")
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name + ".example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{name + ".example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: isCA, BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		c.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		c.t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name + ".example.test"}, DNSNames: []string{name + ".example.test"},
	}, key)
	if err != nil {
		c.t.Fatal(err)
	}
	m := &material{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		csrPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}
	c.pki[name] = m
	return m
}

// Fingerprint is the SHA-256 fingerprint of the certificate generated for
// name, as the record spells it.
func (c *Cluster) Fingerprint(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	block, _ := pem.Decode(c.materialLocked(name).certPEM)
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// KeyPEM is the PEM private key generated for name: what a test must prove
// never leaves the server's answers.
func (c *Cluster) KeyPEM(name string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.materialLocked(name).keyPEM...)
}

// serveTLS starts a TLS listener on 127.0.0.1 that presents m's certificate
// and completes handshakes, once per certificate, and returns its port.
func (c *Cluster) serveTLS(m *material) int {
	if m.port != 0 {
		return m.port
	}
	cert, err := tls.X509KeyPair(m.certPEM, m.keyPEM)
	if err != nil {
		c.t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
				_, _ = conn.Read(make([]byte, 1))
			}()
		}
	}()
	m.port = ln.Addr().(*net.TCPAddr).Port
	return m.port
}
