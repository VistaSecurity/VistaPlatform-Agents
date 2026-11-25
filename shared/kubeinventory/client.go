package kubeinventory

// A thin read-only client for the API server of the cluster this process runs
// in. It is deliberately not k8s.io/client-go: the collector needs GET on a
// fixed list of paths and JSON decoding into its own projections, and nothing
// else of a Kubernetes client.
//
// There is no way to point it at another cluster: no kubeconfig, no flag, no
// job parameter. It takes the API server address from the environment the
// kubelet gives every pod and the credential from the pod's service-account
// volume.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// ServiceAccountDir is where the kubelet mounts a pod's service account.
const ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

const (
	envServiceHost = "KUBERNETES_SERVICE_HOST"
	envServicePort = "KUBERNETES_SERVICE_PORT"

	listPageSize      = 500
	maxResponseBytes  = 256 << 20
	requestTimeout    = 60 * time.Second
	apiServerHostname = "kubernetes.default.svc"
)

// ErrNotInCluster is returned when this process is not a pod with a service
// account.
var ErrNotInCluster = errors.New("not running in a Kubernetes cluster: no service account is mounted and no API server address is set")

// ErrItemLimit is returned by list when a class holds more rows than allowed.
var ErrItemLimit = errors.New("item limit reached")

// APIError is an answer from the API server that is not a success.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the API server answered %d", e.Status)
	}
	return fmt.Sprintf("the API server answered %d: %s", e.Status, e.Message)
}

func statusOf(err error) int {
	var api *APIError
	if errors.As(err, &api) {
		return api.Status
	}
	return 0
}

// Request is one request the client made, as an authoriser would see it.
type Request struct {
	Group     string
	Resource  string
	Verb      string
	Namespace string
	Name      string
	Path      string
	Query     string
}

// Client reads the API server. It is safe for concurrent use.
type Client struct {
	base      string
	host      string
	port      int
	namespace string
	hc        *http.Client
	token     func() (string, error)
	caCerts   []*x509.Certificate
	caPool    *x509.CertPool

	mu       sync.Mutex
	tlsState *tls.ConnectionState
	requests []Request
}

// InClusterAvailable reports whether this process looks like a pod with a
// service account, without contacting anything.
func InClusterAvailable() bool {
	if os.Getenv(envServiceHost) == "" || os.Getenv(envServicePort) == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(ServiceAccountDir, "token"))
	return err == nil
}

// InCluster returns a client for the cluster this process runs in.
func InCluster() (*Client, error) {
	host, port := os.Getenv(envServiceHost), os.Getenv(envServicePort)
	if host == "" || port == "" {
		return nil, ErrNotInCluster
	}
	return NewClient(host, port, ServiceAccountDir)
}

// NewClient builds a client from an API server address and a service-account
// directory (token, ca.crt, namespace). It exists for tests, which serve a
// fake API server; the agent calls only InCluster, and a test
// (TestOnlyInClusterIsUsedOutsideTests) fails if any shipped code calls this.
func NewClient(host, port, dir string) (*Client, error) {
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("%w (bad API server port)", ErrNotInCluster)
	}
	tokenPath := filepath.Join(dir, "token")
	if _, err := os.Stat(tokenPath); err != nil {
		return nil, ErrNotInCluster
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("the service account has no cluster CA: %w", err)
	}
	caCerts := parseCertificates(caPEM)
	if len(caCerts) == 0 {
		return nil, errors.New("the service account's ca.crt holds no certificate")
	}
	pool := x509.NewCertPool()
	for _, c := range caCerts {
		pool.AddCert(c)
	}
	ns, _ := os.ReadFile(filepath.Join(dir, "namespace"))

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		// The address comes from the kubelet; a proxy variable in the pod's
		// environment must not send the service-account token elsewhere.
		Proxy: nil,
	}
	return &Client{
		base:      "https://" + net.JoinHostPort(host, port),
		host:      host,
		port:      portNum,
		namespace: strings.TrimSpace(string(ns)),
		hc: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// The API server does not redirect; following one could carry the
			// token to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		// The kubelet rotates the token file; it is read for every request.
		token: func() (string, error) {
			b, err := os.ReadFile(tokenPath)
			return strings.TrimSpace(string(b)), err
		},
		caCerts: caCerts,
		caPool:  pool,
	}, nil
}

// Namespace is the namespace the agent's pod runs in.
func (c *Client) Namespace() string { return c.namespace }

// Requests returns what the client has asked for so far.
func (c *Client) Requests() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Request(nil), c.requests...)
}

func (c *Client) connectionState() *tls.ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tlsState
}

// do sends one GET and decodes a success into out.
func (c *Client) do(ctx context.Context, rec Request, out any) error {
	u := c.base + rec.Path
	if rec.Query != "" {
		u += "?" + rec.Query
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	token, err := c.token()
	if err != nil || token == "" {
		return errors.New("the service-account token could not be read")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vista-device-agent/kubernetes-inventory")

	c.mu.Lock()
	c.requests = append(c.requests, rec)
	c.mu.Unlock()

	resp, err := c.hc.Do(req)
	if err != nil {
		// A transport error can quote the URL but never the token, which is a
		// header; redact anyway, as every error that leaves the agent is.
		return errors.New(redact.Text(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.TLS != nil {
		c.mu.Lock()
		if c.tlsState == nil {
			state := *resp.TLS
			c.tlsState = &state
		}
		c.mu.Unlock()
	}
	body := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode != http.StatusOK {
		var status struct {
			Message string `json:"message"`
		}
		data, _ := io.ReadAll(io.LimitReader(body, 16<<10))
		_ = json.Unmarshal(data, &status)
		return &APIError{Status: resp.StatusCode, Message: clip(redact.Text(status.Message), maxMessageLen)}
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("the API server's answer for %s could not be read: %w", rec.Resource, err)
	}
	return nil
}

func resourcePath(r Resource, version, namespace, name string) string {
	var b strings.Builder
	if r.Group == "" {
		b.WriteString("/api/" + version)
	} else {
		b.WriteString("/apis/" + r.Group + "/" + version)
	}
	if namespace != "" {
		b.WriteString("/namespaces/" + url.PathEscape(namespace))
	}
	b.WriteString("/" + r.Name)
	if name != "" {
		b.WriteString("/" + url.PathEscape(name))
	}
	return b.String()
}

// getNamed reads one object by name. The name must be one the Resource lists.
func getNamed[T any](ctx context.Context, c *Client, r Resource, namespace, name string) (*T, error) {
	if r.Verb != VerbGet || !contains(r.Names, name) {
		return nil, fmt.Errorf("kubeinventory: %s %q is not a declared read", r.Name, name)
	}
	var out T
	var lastErr error
	for _, version := range r.Versions {
		rec := Request{Group: r.Group, Resource: r.Name, Verb: VerbGet, Namespace: namespace, Name: name, Path: resourcePath(r, version, namespace, name)}
		lastErr = c.do(ctx, rec, &out)
		if statusOf(lastErr) != http.StatusNotFound {
			break
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return &out, nil
}

// getVersion reads /version.
func (c *Client) getVersion(ctx context.Context) (*versionObject, error) {
	var out versionObject
	if err := c.do(ctx, Request{Verb: VerbGet, Path: NonResourceURLs[0]}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// list reads every object of a resource, in all namespaces or in one, page by
// page. With max > 0 it stops after max rows and returns them with
// ErrItemLimit. On any other error it returns the rows read so far.
func list[T any](ctx context.Context, c *Client, r Resource, namespace string, query url.Values, max int) ([]T, error) {
	if r.Verb != VerbList {
		return nil, fmt.Errorf("kubeinventory: %s is not a declared list", r.Name)
	}
	var (
		rows    []T
		lastErr error
	)
	for _, version := range r.Versions {
		rows, lastErr = listVersion[T](ctx, c, r, version, namespace, query, max)
		if statusOf(lastErr) != http.StatusNotFound {
			break
		}
	}
	return rows, lastErr
}

func listVersion[T any](ctx context.Context, c *Client, r Resource, version, namespace string, query url.Values, max int) ([]T, error) {
	var rows []T
	next := ""
	for {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("limit", strconv.Itoa(listPageSize))
		if next != "" {
			q.Set("continue", next)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		rec := Request{Group: r.Group, Resource: r.Name, Verb: VerbList, Namespace: namespace, Path: resourcePath(r, version, namespace, ""), Query: q.Encode()}
		if err := c.do(ctx, rec, &page); err != nil {
			return rows, err
		}
		rows = append(rows, page.Items...)
		if max > 0 && len(rows) > max {
			return rows[:max], ErrItemLimit
		}
		next = page.Metadata.Continue
		if next == "" {
			return rows, nil
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
