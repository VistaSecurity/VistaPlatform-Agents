package kubeinventory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory/kubetest"
)

const (
	traefikRoutesPath    = "/apis/traefik.io/v1alpha1/ingressroutes"
	traefikTCPPath       = "/apis/traefik.io/v1alpha1/ingressroutetcps"
	traefikOptionsPath   = "/apis/traefik.io/v1alpha1/tlsoptions"
	traefikStoresPath    = "/apis/traefik.io/v1alpha1/tlsstores"
	legacyRoutesPath     = "/apis/traefik.containo.us/v1alpha1/ingressroutes"
	legacyTCPPath        = "/apis/traefik.containo.us/v1alpha1/ingressroutetcps"
	legacyOptionsPath    = "/apis/traefik.containo.us/v1alpha1/tlsoptions"
	legacyStoresPath     = "/apis/traefik.containo.us/v1alpha1/tlsstores"
	traefikFixtureFolder = "apis/traefik.io/v1alpha1"
)

var traefikPaths = []string{traefikRoutesPath, traefikTCPPath, traefikOptionsPath, traefikStoresPath}

func traefikRow(t *testing.T, inv *Inventory, group, kind, ns, name string) TraefikIngressRoute {
	t.Helper()
	for _, r := range inv.TraefikIngressRoutes {
		if r.APIGroup == group && r.Kind == kind && r.Namespace == ns && r.Name == name {
			return r
		}
	}
	t.Fatalf("no %s %s %s/%s in %+v", group, kind, ns, name, inv.TraefikIngressRoutes)
	return TraefikIngressRoute{}
}

// fixtureItems reads the items of one of the full cluster's Traefik fixtures,
// to serve them again elsewhere.
func fixtureItems(t *testing.T, file string) []any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "full", filepath.FromSlash(traefikFixtureFolder), file))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []any `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Items
}

func TestTraefikFullCluster(t *testing.T) {
	cl, c := fullCluster(t)
	inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
	section(t, inv, SectionTraefik, StatusOK, "")
	if n := *inv.Sections[SectionTraefik].Count; n != 6+3+1 || len(inv.TraefikIngressRoutes) != 6 || len(inv.TraefikTLSOptions) != 3 || len(inv.TraefikTLSStores) != 1 {
		t.Fatalf("count %d: %d routes, %d options, %d stores", n, len(inv.TraefikIngressRoutes), len(inv.TraefikTLSOptions), len(inv.TraefikTLSStores))
	}

	web := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "web")
	want := TraefikIngressRoute{
		Kind: "IngressRoute", APIGroup: "traefik.io", Namespace: "shop", Name: "web", UID: "7a1e0f52-3c4d-4e8f-9a0b-1c2d3e4f5a01",
		EntryPoints: []string{"websecure"},
		Routes: []TraefikRoute{
			{Match: "Host(`Shop.example.test`) && PathPrefix(`/`)", Hosts: []string{"shop.example.test"}, Services: []TraefikServiceRef{
				{Kind: "Service", Name: "web", Port: "443"}, {Kind: "TraefikService", Name: "canary"}}},
			{Match: "Host(`a.example.test`) || Host(`b.example.test`)", Hosts: []string{"a.example.test", "b.example.test"}, Services: []TraefikServiceRef{
				{Kind: "Service", Name: "web", Port: "https"}}},
			{Match: "HostRegexp(`^.+\\.example\\.test$`)", Services: []TraefikServiceRef{{Kind: "Service", Name: "web", Port: "443"}}},
		},
		TLS: &TraefikRouteTLS{
			SecretName: "web-tls", OptionsRef: &TraefikRef{Namespace: "shop", Name: "modern"},
			EffectiveOptions: &TraefikEffectiveOptions{Source: TraefikOptionsReferenced, Namespace: "shop", Name: "modern"},
			CertResolver:     "letsencrypt",
			Domains:          []TraefikDomain{{Main: "shop.example.test", SANs: []string{"*.shop.example.test"}}},
		},
		CreatedAt: web.CreatedAt,
	}
	if !reflect.DeepEqual(web, want) {
		got, _ := json.Marshal(web)
		exp, _ := json.Marshal(want)
		t.Errorf("web:\n got %s\nwant %s", got, exp)
	}

	// An empty tls block is TLS with the default options: the one TLSOption
	// named default, wherever it is.
	if api := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "api"); api.TLS == nil ||
		*api.TLS.EffectiveOptions != (TraefikEffectiveOptions{Source: TraefikOptionsDefault, Namespace: "edge", Name: "default"}) {
		t.Errorf("api: %+v", api.TLS)
	}
	plain := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "plain")
	if plain.TLS != nil {
		t.Errorf("plain has TLS: %+v", plain.TLS)
	}
	// The rule's secrets are redacted; a port that is not a port is dropped.
	if r := plain.Routes[0]; r.Match != "Host(`plain.example.test`) && Header(`X-Api-Key`, `[REDACTED]`) && Query(`token`, \"[REDACTED]\") && ClientIP(`[REDACTED]`)" ||
		!reflect.DeepEqual(r.Hosts, []string{"plain.example.test"}) || r.Services[0].Port != "" {
		t.Errorf("plain: %+v", r)
	}
	// A cross-provider reference names an option the API cannot show.
	file := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "filecfg")
	if *file.TLS.OptionsRef != (TraefikRef{Name: "hardened", Provider: "file"}) ||
		*file.TLS.EffectiveOptions != (TraefikEffectiveOptions{Source: TraefikOptionsReferenced, Name: "hardened", Provider: "file"}) ||
		*file.TLS.Store != (TraefikRef{Namespace: "shop", Name: "default"}) {
		t.Errorf("filecfg: %+v %+v %+v", file.TLS.OptionsRef, file.TLS.EffectiveOptions, file.TLS.Store)
	}
	// Passthrough is not terminated, so no options are in force.
	db := traefikRow(t, inv, traefikGroup, traefikKindTCP, "shop", "db")
	if !db.TLS.Passthrough || db.TLS.EffectiveOptions != nil || !reflect.DeepEqual(db.Routes[0].Hosts, []string{"db.example.test"}) {
		t.Errorf("db: %+v %+v", db.TLS, db.Routes)
	}
	mq := traefikRow(t, inv, traefikGroup, traefikKindTCP, "shop", "mq")
	if mq.Routes[0].Hosts != nil || *mq.TLS.EffectiveOptions != (TraefikEffectiveOptions{Source: TraefikOptionsReferenced, Namespace: "edge", Name: "mtls"}) {
		t.Errorf("mq: %+v %+v", mq.Routes, mq.TLS.EffectiveOptions)
	}

	for _, o := range inv.TraefikTLSOptions {
		if o.Name != "mtls" {
			continue
		}
		want := TraefikTLSOption{
			APIGroup: "traefik.io", Namespace: "edge", Name: "mtls", UID: "7a1e0f52-3c4d-4e8f-9a0b-1c2d3e4f5a08",
			MinVersion: "VersionTLS12", MaxVersion: "VersionTLS13",
			CipherSuites:     []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			CurvePreferences: []string{"X25519", "CurveP256"},
			ClientAuth:       &TraefikClientAuth{Type: "RequireAndVerifyClientCert", SecretNames: []string{"client-ca"}},
			CreatedAt:        o.CreatedAt,
		}
		if !reflect.DeepEqual(o, want) {
			t.Errorf("mtls: %+v", o)
		}
	}
	if s := inv.TraefikTLSStores[0]; s.DefaultCertificateSecret != "edge-default-tls" || !reflect.DeepEqual(s.CertificateSecrets, []string{"a-tls", "b-tls"}) {
		t.Errorf("store: %+v", s)
	}

	// Posture only: nothing but the projection, no Secret read for it.
	doc, _ := json.Marshal(inv)
	for _, forbidden := range []string{"secret-value", "privateKey", "caFiles", "middlewares", "serversTransport", "annotations", "PRIVATE KEY"} {
		if bytes.Contains(doc, []byte(forbidden)) {
			t.Errorf("%s is in the result", forbidden)
		}
	}
	for _, r := range cl.Requests() {
		if strings.Contains(r.Path, "secrets") {
			t.Errorf("Traefik made the collector call %s", r.Path)
		}
	}
	// The legacy group is not served here: it is none, not a failure.
	for _, p := range []string{legacyRoutesPath, legacyTCPPath, legacyOptionsPath, legacyStoresPath} {
		asked := false
		for _, r := range cl.Requests() {
			asked = asked || r.Path == p
		}
		if !asked {
			t.Errorf("%s was not asked for", p)
		}
	}
}

// normalised is a collection's document without what differs between two
// collections of the same cluster.
func normalised(t *testing.T, inv *Inventory) string {
	t.Helper()
	cp := *inv
	cp.CollectionID, cp.DurationMS = "", 0
	cp.CollectedAt = time.Time{}
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Without the parameter the record is what it was before Traefik existed:
// no request for a Traefik API, no Traefik member, no traefik section, and
// byte for byte the same document whether or not the cluster runs Traefik.
func TestTraefikOffLeavesTheRecordUnchanged(t *testing.T) {
	cl, c := fullCluster(t)
	off := collect(t, c, Options{SkipKubeletProbe: true})
	for _, r := range cl.Requests() {
		if strings.Contains(r.Path, "traefik") {
			t.Errorf("asked for %s without the parameter", r.Path)
		}
	}
	if _, ok := off.Sections[SectionTraefik]; ok {
		t.Error("a traefik section without the parameter")
	}
	doc, _ := json.Marshal(off)
	if bytes.Contains(doc, []byte("traefik")) {
		t.Error("the record names Traefik without the parameter")
	}

	// And the parameter adds exactly the Traefik members.
	on := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
	if len(on.TraefikIngressRoutes) == 0 {
		t.Fatal("the comparison needs a cluster that runs Traefik")
	}
	delete(on.Sections, SectionTraefik)
	on.TraefikIngressRoutes, on.TraefikTLSOptions, on.TraefikTLSStores = nil, nil, nil
	if normalised(t, off) != normalised(t, on) {
		t.Error("the parameter changed more than the Traefik members")
	}

	// The same cluster without Traefik's CRDs, parameter off: the same
	// document (the generated certificates are the cluster's, so it is the
	// same cluster with the Traefik APIs taken away).
	for _, p := range traefikPaths {
		cl.SetStatus(p, http.StatusNotFound)
	}
	without := collect(t, c, Options{SkipKubeletProbe: true})
	if normalised(t, off) != normalised(t, without) {
		t.Error("the record differs between a cluster with Traefik and one without, with the parameter off")
	}
}

func TestTraefikAnswers(t *testing.T) {
	t.Run("neither group serves IngressRoutes: not_installed, no rows", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus(traefikRoutesPath, http.StatusNotFound)
		inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusUnsupported, ReasonNotInstalled)
		if inv.TraefikIngressRoutes != nil || inv.TraefikTLSOptions != nil || inv.TraefikTLSStores != nil {
			t.Error("rows were sent for Traefik that is not installed")
		}
	})
	t.Run("a bare cluster with the parameter: not_installed", func(t *testing.T) {
		cl := kubetest.New(t)
		cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-2222-4333-8444-555555555555"}})
		inv := collect(t, testClient(t, cl), Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusUnsupported, ReasonNotInstalled)
	})
	t.Run("the legacy group only", func(t *testing.T) {
		cl, c := fullCluster(t)
		for _, p := range traefikPaths {
			cl.SetStatus(p, http.StatusNotFound)
		}
		cl.SetList(legacyRoutesPath, fixtureItems(t, "ingressroutes.json")...)
		cl.SetList(legacyOptionsPath, fixtureItems(t, "tlsoptions.json")...)
		inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusOK, "")
		if len(inv.TraefikIngressRoutes) != 4 || len(inv.TraefikTLSOptions) != 3 {
			t.Fatalf("%d routes, %d options", len(inv.TraefikIngressRoutes), len(inv.TraefikTLSOptions))
		}
		for _, r := range inv.TraefikIngressRoutes {
			if r.APIGroup != traefikLegacyGroup {
				t.Errorf("%s: group %s", r.Name, r.APIGroup)
			}
		}
		if api := traefikRow(t, inv, traefikLegacyGroup, traefikKindHTTP, "shop", "api"); api.TLS.EffectiveOptions.Source != TraefikOptionsDefault {
			t.Errorf("api: %+v", api.TLS.EffectiveOptions)
		}
	})
	t.Run("both groups: the same name twice is two rows, one default", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetList(legacyRoutesPath, fixtureItems(t, "ingressroutes.json")[:1]...)
		cl.SetList(legacyOptionsPath, fixtureItems(t, "tlsoptions.json")...)
		inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusOK, "")
		a := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "web")
		b := traefikRow(t, inv, traefikLegacyGroup, traefikKindHTTP, "shop", "web")
		if a.UID != b.UID || len(inv.TraefikIngressRoutes) != 7 || len(inv.TraefikTLSOptions) != 6 {
			t.Errorf("%d routes, %d options", len(inv.TraefikIngressRoutes), len(inv.TraefikTLSOptions))
		}
		// edge/default under both groups is one candidate, not a conflict.
		if api := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "api"); api.TLS.EffectiveOptions.Source != TraefikOptionsDefault {
			t.Errorf("api: %+v", api.TLS.EffectiveOptions)
		}
	})
	t.Run("forbidden: failed, not_permitted", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus(traefikRoutesPath, http.StatusForbidden)
		inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusFailed, ReasonNotPermitted)
		if len(inv.TraefikIngressRoutes) != 2 {
			t.Errorf("the IngressRouteTCPs that could be read are still sent: %d", len(inv.TraefikIngressRoutes))
		}
	})
	t.Run("forbidden on the legacy group only: failed, not_permitted", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus(legacyRoutesPath, http.StatusForbidden)
		inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusFailed, ReasonNotPermitted)
	})
	t.Run("TLS options unreadable: only referenced options are resolved", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus(traefikOptionsPath, http.StatusForbidden)
		inv := collect(t, c, Options{SkipKubeletProbe: true, Traefik: true})
		section(t, inv, SectionTraefik, StatusFailed, ReasonNotPermitted)
		if api := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "api"); api.TLS.EffectiveOptions != nil {
			t.Errorf("api was resolved without the options: %+v", api.TLS.EffectiveOptions)
		}
		if web := traefikRow(t, inv, traefikGroup, traefikKindHTTP, "shop", "web"); web.TLS.EffectiveOptions.Source != TraefikOptionsReferenced {
			t.Errorf("web: %+v", web.TLS.EffectiveOptions)
		}
	})
	t.Run("more rows than the limit: failed, item_limit", func(t *testing.T) {
		cl := kubetest.New(t)
		cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-2222-4333-8444-555555555555"}})
		cl.SetList(traefikRoutesPath, fixtureItems(t, "ingressroutes.json")...)
		inv := collect(t, testClient(t, cl), Options{SkipKubeletProbe: true, Traefik: true, MaxItemsPerClass: 2})
		section(t, inv, SectionTraefik, StatusFailed, ReasonItemLimit)
		if len(inv.TraefikIngressRoutes) != 2 {
			t.Errorf("%d routes", len(inv.TraefikIngressRoutes))
		}
	})
}

func TestTraefikOptionResolution(t *testing.T) {
	ref := &TraefikRef{Namespace: "a", Name: "x"}
	for _, tc := range []struct {
		name  string
		index traefikOptionIndex
		tls   TraefikRouteTLS
		want  *TraefikEffectiveOptions
	}{
		{"referenced wins over a default", traefikOptionIndex{readable: true, defaultNamespaces: []string{"edge"}}, TraefikRouteTLS{OptionsRef: ref},
			&TraefikEffectiveOptions{Source: TraefikOptionsReferenced, Namespace: "a", Name: "x"}},
		{"one default, any namespace", traefikOptionIndex{readable: true, defaultNamespaces: []string{"edge"}}, TraefikRouteTLS{},
			&TraefikEffectiveOptions{Source: TraefikOptionsDefault, Namespace: "edge", Name: "default"}},
		{"no default: built-in", traefikOptionIndex{readable: true}, TraefikRouteTLS{},
			&TraefikEffectiveOptions{Source: TraefikOptionsBuiltin}},
		{"several defaults: built-in, and says why", traefikOptionIndex{readable: true, defaultNamespaces: []string{"a", "b"}}, TraefikRouteTLS{},
			&TraefikEffectiveOptions{Source: TraefikOptionsBuiltin, DefaultConflict: true}},
		{"options unreadable: not guessed", traefikOptionIndex{}, TraefikRouteTLS{}, nil},
		{"options unreadable, referenced: as written", traefikOptionIndex{}, TraefikRouteTLS{OptionsRef: ref},
			&TraefikEffectiveOptions{Source: TraefikOptionsReferenced, Namespace: "a", Name: "x"}},
		{"passthrough: none apply", traefikOptionIndex{readable: true}, TraefikRouteTLS{Passthrough: true, OptionsRef: ref}, nil},
	} {
		if got := tc.index.resolve(&tc.tls); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if r := traefikRef(&traefikRefObject{Name: "x"}, "route-ns"); *r != (TraefikRef{Namespace: "route-ns", Name: "x"}) {
		t.Errorf("the namespace defaults to the route's: %+v", r)
	}
	if r := traefikRef(&traefikRefObject{Name: "x@kubernetescrd", Namespace: "ignored"}, "route-ns"); *r != (TraefikRef{Name: "x", Provider: "kubernetescrd"}) {
		t.Errorf("cross-provider: %+v", r)
	}
	if r := traefikRef(&traefikRefObject{Name: "not a name"}, "ns"); r != nil {
		t.Errorf("an invalid name: %+v", r)
	}
}

func TestTraefikHosts(t *testing.T) {
	for match, want := range map[string][]string{
		"Host(`example.test`)":                                   {"example.test"},
		"Host(`B.example.test`) && PathPrefix(`/api`)":           {"b.example.test"},
		"Host(`a.example.test`) || Host(`b.example.test`)":       {"a.example.test", "b.example.test"},
		"Host(`a.example.test`, `b.example.test`)":               {"a.example.test", "b.example.test"},
		`Host("q.example.test")`:                                 {"q.example.test"},
		"HostSNI(`db.example.test`)":                             {"db.example.test"},
		"HostSNI(`*`)":                                           nil,
		"Host(`*.example.test`)":                                 {"*.example.test"},
		"Host(`a.example.test`) || PathPrefix(`/`)":              nil,
		"!Host(`a.example.test`)":                                nil,
		"HostRegexp(`^.+$`)":                                     nil,
		"PathPrefix(`/`)":                                        nil,
		"Host(`a.example.test`) && (Path(`/a`) || Path(`/b`))":   nil,
		"Host(`a.example.test`) && Header(`X-Forwarded`, `yes`)": {"a.example.test"},
		"Host(unquoted.example.test)":                            nil,
		// An alternative inside a group could be met without its host.
		"(Host(`a.test`) || Header(`X`, `y`)) && Host(`b.test`)": nil,
		"(Host(`a.test`) || Host(`c.test`)) && Path(`/`)":        nil,
		"(Host(`a.test`) && Path(`/`)) || Host(`b.test`)":        {"a.test", "b.test"},
		"Host(`a.test`) || Header(`X`, `y`)":                     nil,
		"PathRegexp(`^/a$`) && Host(`a.test`)":                   {"a.test"},
		"HostRegexp(`a`) || Host(`a.test`)":                      nil,
		"Host(`a.test`) && `stray`":                              nil,
		"":                                                       nil,
	} {
		if got := traefikHosts(match); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", match, got, want)
		}
	}
}

// A long match is cut to the schema's bound; its hosts are read from the
// whole text.
func TestTraefikLongMatch(t *testing.T) {
	cl := kubetest.New(t)
	cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-2222-4333-8444-555555555555"}})
	long := strings.Repeat("PathPrefix(`/x`) && ", 100) + "Host(`late.example.test`)"
	cl.SetList(traefikRoutesPath, map[string]any{
		"metadata": map[string]string{"namespace": "shop", "name": "long"},
		"spec":     map[string]any{"routes": []any{map[string]any{"match": long}}},
	})
	inv := collect(t, testClient(t, cl), Options{SkipKubeletProbe: true, Traefik: true})
	r := inv.TraefikIngressRoutes[0].Routes[0]
	if len(r.Match) != maxTraefikMatch || !reflect.DeepEqual(r.Hosts, []string{"late.example.test"}) {
		t.Errorf("%d characters, hosts %v", len(r.Match), r.Hosts)
	}
}

func TestTraefikRuleRedaction(t *testing.T) {
	for _, tc := range []struct{ rule, want, secret string }{
		// v3 syntax: one argument per Host, Header with a key and a value.
		{"Host(`a.example.test`) && Header(`X-Api-Key`, `s3cr3t`)", "Host(`a.example.test`) && Header(`X-Api-Key`, `[REDACTED]`)", "s3cr3t"},
		{"Host(`a.example.test`) && Query(`token`, `abc123`)", "Host(`a.example.test`) && Query(`token`, `[REDACTED]`)", "abc123"},
		{"HeaderRegexp(`Authorization`, `^Bearer xyz$`)", "HeaderRegexp(`Authorization`, `[REDACTED]`)", "Bearer xyz"},
		{"QueryRegexp(`sig`, `^k3y.*$`)", "QueryRegexp(`sig`, `[REDACTED]`)", "k3y"},
		{"ClientIP(`192.0.2.0/24`) && PathPrefix(`/admin`)", "ClientIP(`[REDACTED]`) && PathPrefix(`/admin`)", "192.0.2.0/24"},
		{"PathPrefix(`/`) && Unknown(`first-arg-secret`, `x`)", "PathPrefix(`/`) && Unknown(`[REDACTED]`, `[REDACTED]`)", "first-arg-secret"},
		// v2 syntax: several arguments, Headers, double quotes with escapes.
		{"Host(`a.example.test`, `b.example.test`) && Headers(`X-Token`, `v2secret`)", "Host(`a.example.test`, `b.example.test`) && Headers(`X-Token`, `[REDACTED]`)", "v2secret"},
		{`Host("q.example.test") && Header("X-Key", "quo\"ted-secret")`, `Host("q.example.test") && Header("X-Key", "[REDACTED]")`, "ted-secret"},
		{"!(Method(`POST`) || PathRegexp(`^/a/[0-9]+$`)) && HostSNI(`*`) && ALPN(`h2`)", "!(Method(`POST`) || PathRegexp(`^/a/[0-9]+$`)) && HostSNI(`*`) && ALPN(`h2`)", ""},
		{"HostRegexp(`^.+\\.example\\.test$`)", "HostRegexp(`^.+\\.example\\.test$`)", ""},
		{"Path(`/`)   &&Host(`x.example.test`)", "Path(`/`) && Host(`x.example.test`)", ""},
		// Not tokenisable safely: nothing is sent.
		{"Host(`a.example.test`) && Header(`X-Api-Key`, `unterminated-secret)", "", "unterminated-secret"},
		{"Header(X-Api-Key, bare-secret)", "", "bare-secret"},
		{"Host(`a`) && `stray-secret`", "", "stray-secret"},
		{"Header(`k`, `v` `adjacent-secret`)", "", "adjacent-secret"},
		{"Host(`a`) && (Path(`/`)", "", ""},
		{`Header("k", "bad\escape-secret")`, "", "escape-secret"},
		{"Header(`k`, Query(`nested-secret`))", "", "nested-secret"},
		{"Host(`a`) ; Header(`k`, `semi-secret`)", "", "semi-secret"},
		{"", "", ""},
	} {
		got := redactedRule(tc.rule)
		if got != tc.want {
			t.Errorf("%q: %q, want %q", tc.rule, got, tc.want)
		}
		if tc.secret == "" {
			continue
		}
		// Through the collector: the secret is nowhere in the record.
		cl := kubetest.New(t)
		cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-2222-4333-8444-555555555555"}})
		cl.SetList(traefikRoutesPath, map[string]any{
			"metadata": map[string]string{"namespace": "shop", "name": "r"},
			"spec":     map[string]any{"routes": []any{map[string]any{"match": tc.rule}}},
		})
		inv := collect(t, testClient(t, cl), Options{SkipKubeletProbe: true, Traefik: true})
		doc, _ := json.Marshal(inv)
		if bytes.Contains(doc, []byte(tc.secret)) {
			t.Errorf("%q: %q is in the record", tc.rule, tc.secret)
		}
		if len(inv.TraefikIngressRoutes) != 1 || inv.TraefikIngressRoutes[0].Routes[0].Match != tc.want {
			t.Errorf("%q: the route was not sent with its redacted rule: %+v", tc.rule, inv.TraefikIngressRoutes)
		}
	}
}

func TestTraefikServicePort(t *testing.T) {
	for in, want := range map[string]string{"443": "443", "https": "https", "web-tls": "web-tls", "1234567890123456": "", "Https": "", "a-very-long-port-name": "", "-x": "", "x y": ""} {
		if got := token(in, traefikPortRE, 63); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
