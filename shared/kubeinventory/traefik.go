package kubeinventory

// Traefik's Kubernetes CRDs: IngressRoute, IngressRouteTCP, TLSOption and
// TLSStore, in the current API group (traefik.io) and the legacy one
// (traefik.containo.us). Read only when a job asks for them (the parameter
// "traefik"), because the record is closed: an agent that sent these members
// to a platform that does not know them would have its result refused.
//
// What is kept is what the cluster's API declares about edge TLS: routes and
// the hosts they match, the Secret NAMES they and the stores refer to, the
// TLS options in force. Nothing is read from a Secret, and nothing in these
// objects holds key material; the projections below declare only the fields
// the record needs, so the rest of an object is never decoded.

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The two API groups Traefik has served its CRDs under.
const (
	traefikGroup       = "traefik.io"
	traefikLegacyGroup = "traefik.containo.us"
)

// The kinds of route.
const (
	traefikKindHTTP = "IngressRoute"
	traefikKindTCP  = "IngressRouteTCP"
)

// Where a route's effective TLS options come from.
const (
	TraefikOptionsReferenced = "referenced"
	TraefikOptionsDefault    = "default"
	TraefikOptionsBuiltin    = "traefik_builtin"
	traefikDefaultOptionName = "default"
)

var (
	resTraefikRoutes          = Resource{Group: traefikGroup, Versions: []string{"v1alpha1"}, Name: "ingressroutes", Verb: VerbList}
	resTraefikRoutesTCP       = Resource{Group: traefikGroup, Versions: []string{"v1alpha1"}, Name: "ingressroutetcps", Verb: VerbList}
	resTraefikTLSOptions      = Resource{Group: traefikGroup, Versions: []string{"v1alpha1"}, Name: "tlsoptions", Verb: VerbList}
	resTraefikTLSStores       = Resource{Group: traefikGroup, Versions: []string{"v1alpha1"}, Name: "tlsstores", Verb: VerbList}
	resTraefikLegacyRoutes    = Resource{Group: traefikLegacyGroup, Versions: []string{"v1alpha1"}, Name: "ingressroutes", Verb: VerbList}
	resTraefikLegacyRoutesTCP = Resource{Group: traefikLegacyGroup, Versions: []string{"v1alpha1"}, Name: "ingressroutetcps", Verb: VerbList}
	resTraefikLegacyOptions   = Resource{Group: traefikLegacyGroup, Versions: []string{"v1alpha1"}, Name: "tlsoptions", Verb: VerbList}
	resTraefikLegacyStores    = Resource{Group: traefikLegacyGroup, Versions: []string{"v1alpha1"}, Name: "tlsstores", Verb: VerbList}
)

type traefikResources struct {
	group                   string
	routes, tcp, opts, stor Resource
}

// traefikGroups is read in this order: the current group first.
var traefikGroups = []traefikResources{
	{traefikGroup, resTraefikRoutes, resTraefikRoutesTCP, resTraefikTLSOptions, resTraefikTLSStores},
	{traefikLegacyGroup, resTraefikLegacyRoutes, resTraefikLegacyRoutesTCP, resTraefikLegacyOptions, resTraefikLegacyStores},
}

// ---- the record ----

// TraefikServiceRef is a Service (or a TraefikService) a route sends to.
type TraefikServiceRef struct {
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Port      string `json:"port,omitempty"`
}

// TraefikRoute is one route of an IngressRoute or IngressRouteTCP.
type TraefikRoute struct {
	Match    string              `json:"match,omitempty"`
	Hosts    []string            `json:"hosts,omitempty"`
	Services []TraefikServiceRef `json:"services,omitempty"`
}

// TraefikRef names a TLSOption or TLSStore. Provider is set when the name used
// Traefik's cross-provider form (name@provider); the namespace is then not
// used.
type TraefikRef struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Provider  string `json:"provider,omitempty"`
}

// TraefikEffectiveOptions is the TLSOption in force for a route, as resolved
// by the agent.
type TraefikEffectiveOptions struct {
	Source    string `json:"source"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Provider  string `json:"provider,omitempty"`
	// DefaultConflict: more than one TLSOption is named "default", which
	// Traefik answers by using its built-in options.
	DefaultConflict bool `json:"default_conflict,omitempty"`
}

// TraefikDomain is one entry of a route's tls.domains.
type TraefikDomain struct {
	Main string   `json:"main,omitempty"`
	SANs []string `json:"sans,omitempty"`
}

// TraefikRouteTLS is a route's tls block.
type TraefikRouteTLS struct {
	SecretName       string                   `json:"secret_name,omitempty"`
	OptionsRef       *TraefikRef              `json:"options_ref,omitempty"`
	EffectiveOptions *TraefikEffectiveOptions `json:"effective_options,omitempty"`
	Store            *TraefikRef              `json:"store,omitempty"`
	CertResolver     string                   `json:"cert_resolver,omitempty"`
	Domains          []TraefikDomain          `json:"domains,omitempty"`
	Passthrough      bool                     `json:"passthrough,omitempty"`
}

// TraefikIngressRoute is an IngressRoute or IngressRouteTCP.
type TraefikIngressRoute struct {
	Kind        string           `json:"kind"`
	APIGroup    string           `json:"api_group"`
	Namespace   string           `json:"namespace"`
	Name        string           `json:"name"`
	UID         string           `json:"uid,omitempty"`
	EntryPoints []string         `json:"entry_points,omitempty"`
	Routes      []TraefikRoute   `json:"routes,omitempty"`
	TLS         *TraefikRouteTLS `json:"tls,omitempty"`
	CreatedAt   *time.Time       `json:"created_at,omitempty"`
}

// TraefikClientAuth is a TLSOption's client-certificate setting. SecretNames
// are the names of the Secrets holding the CA certificates; they are never
// read.
type TraefikClientAuth struct {
	Type        string   `json:"type,omitempty"`
	SecretNames []string `json:"secret_names,omitempty"`
}

// TraefikTLSOption is a TLSOption.
type TraefikTLSOption struct {
	APIGroup         string             `json:"api_group"`
	Namespace        string             `json:"namespace"`
	Name             string             `json:"name"`
	UID              string             `json:"uid,omitempty"`
	MinVersion       string             `json:"min_version,omitempty"`
	MaxVersion       string             `json:"max_version,omitempty"`
	CipherSuites     []string           `json:"cipher_suites,omitempty"`
	CurvePreferences []string           `json:"curve_preferences,omitempty"`
	ClientAuth       *TraefikClientAuth `json:"client_auth,omitempty"`
	SNIStrict        bool               `json:"sni_strict"`
	ALPNProtocols    []string           `json:"alpn_protocols,omitempty"`
	CreatedAt        *time.Time         `json:"created_at,omitempty"`
}

// TraefikTLSStore is a TLSStore: the names of the Secrets it serves.
type TraefikTLSStore struct {
	APIGroup                 string     `json:"api_group"`
	Namespace                string     `json:"namespace"`
	Name                     string     `json:"name"`
	UID                      string     `json:"uid,omitempty"`
	DefaultCertificateSecret string     `json:"default_certificate_secret,omitempty"`
	CertificateSecrets       []string   `json:"certificate_secrets,omitempty"`
	CreatedAt                *time.Time `json:"created_at,omitempty"`
}

// ---- the projections ----

type traefikRefObject struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type traefikServiceObject struct {
	Kind      string      `json:"kind"`
	Name      string      `json:"name"`
	Namespace string      `json:"namespace"`
	Port      intOrString `json:"port"`
}

type traefikDomainObject struct {
	Main string   `json:"main"`
	SANs []string `json:"sans"`
}

type traefikRouteObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		EntryPoints []string `json:"entryPoints"`
		Routes      []struct {
			Match    string                 `json:"match"`
			Services []traefikServiceObject `json:"services"`
		} `json:"routes"`
		TLS *struct {
			SecretName   string                `json:"secretName"`
			Options      *traefikRefObject     `json:"options"`
			Store        *traefikRefObject     `json:"store"`
			CertResolver string                `json:"certResolver"`
			Domains      []traefikDomainObject `json:"domains"`
			Passthrough  bool                  `json:"passthrough"`
		} `json:"tls"`
	} `json:"spec"`
}

type traefikTLSOptionObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		MinVersion       string   `json:"minVersion"`
		MaxVersion       string   `json:"maxVersion"`
		CipherSuites     []string `json:"cipherSuites"`
		CurvePreferences []string `json:"curvePreferences"`
		ClientAuth       *struct {
			SecretNames    []string `json:"secretNames"`
			ClientAuthType string   `json:"clientAuthType"`
		} `json:"clientAuth"`
		SNIStrict     bool     `json:"sniStrict"`
		ALPNProtocols []string `json:"alpnProtocols"`
	} `json:"spec"`
}

type traefikSecretRefObject struct {
	SecretName string `json:"secretName"`
}

type traefikTLSStoreObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		DefaultCertificate *traefikSecretRefObject  `json:"defaultCertificate"`
		Certificates       []traefikSecretRefObject `json:"certificates"`
	} `json:"spec"`
}

// ---- bounds ----

var (
	traefikTokenRE    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	traefikALPNRE     = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	traefikProviderRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	traefikHostRE     = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	traefikPortRE     = regexp.MustCompile(`^([0-9]{1,5}|[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?)$`)
)

const (
	maxTraefikMatch = 1024
	maxTraefikToken = 128
)

// tokens keeps the values that are short words of the given syntax.
func tokens(in []string, re *regexp.Regexp, maxLen, maxItems int) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && len(s) <= maxLen && re.MatchString(s) {
			out = append(out, s)
		}
	}
	return limit(out, maxItems)
}

func token(s string, re *regexp.Regexp, maxLen int) string {
	if v := tokens([]string{s}, re, maxLen, 1); len(v) == 1 {
		return v[0]
	}
	return ""
}

func cleanHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) <= 253 && traefikHostRE.MatchString(s) {
		return s
	}
	return ""
}

// splitProvider splits Traefik's cross-provider form name@provider.
func splitProvider(s string) (name, provider string) {
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		return s[:i], token(s[i+1:], traefikProviderRE, 63)
	}
	return s, ""
}

func traefikRef(r *traefikRefObject, routeNamespace string) *TraefikRef {
	if r == nil {
		return nil
	}
	name, provider := splitProvider(strings.TrimSpace(r.Name))
	ref := &TraefikRef{Name: cleanName(name), Provider: provider}
	if ref.Name == "" {
		return nil
	}
	if provider == "" {
		ref.Namespace = cleanName(r.Namespace)
		if ref.Namespace == "" {
			ref.Namespace = routeNamespace
		}
	}
	return ref
}

// ---- collection ----

// traefikOptionIndex resolves a route's effective TLSOption by Traefik's
// documented rules: the option the route references (its namespace defaulting
// to the route's); else the one TLSOption named "default", whatever its
// namespace; else, when there is none or more than one, Traefik's built-in
// options. readable is false when the TLSOptions could not be read in full:
// a route that references none then cannot be resolved and says nothing.
type traefikOptionIndex struct {
	readable          bool
	defaultNamespaces []string
}

func (x traefikOptionIndex) resolve(tls *TraefikRouteTLS) *TraefikEffectiveOptions {
	if tls.Passthrough {
		// Traefik does not terminate TLS on a passthrough route: no options
		// apply.
		return nil
	}
	if ref := tls.OptionsRef; ref != nil {
		return &TraefikEffectiveOptions{Source: TraefikOptionsReferenced, Namespace: ref.Namespace, Name: ref.Name, Provider: ref.Provider}
	}
	if !x.readable {
		return nil
	}
	if len(x.defaultNamespaces) == 1 {
		return &TraefikEffectiveOptions{Source: TraefikOptionsDefault, Namespace: x.defaultNamespaces[0], Name: traefikDefaultOptionName}
	}
	return &TraefikEffectiveOptions{Source: TraefikOptionsBuiltin, DefaultConflict: len(x.defaultNamespaces) > 1}
}

func (k *collector) collectTraefik(ctx context.Context) {
	if !k.opts.Traefik {
		return
	}
	type routeSource struct {
		group, kind string
		objs        []traefikRouteObject
	}
	var (
		routes          []routeSource
		errs            []error
		routes404       = 0
		firstRouteErr   error
		optionsReadable = true
		defaults        []string
	)
	for _, g := range traefikGroups {
		httpRoutes, err := list[traefikRouteObject](ctx, k.c, g.routes, "", nil, k.max)
		if statusOf(err) == http.StatusNotFound {
			routes404++
			if firstRouteErr == nil {
				firstRouteErr = err
			}
		}
		errs = append(errs, notFoundIsNone(err))
		tcp, tcpErr := list[traefikRouteObject](ctx, k.c, g.tcp, "", nil, k.max)
		errs = append(errs, notFoundIsNone(tcpErr))
		routes = append(routes, routeSource{g.group, traefikKindHTTP, httpRoutes}, routeSource{g.group, traefikKindTCP, tcp})

		options, optErr := list[traefikTLSOptionObject](ctx, k.c, g.opts, "", nil, k.max)
		if notFoundIsNone(optErr) != nil {
			optionsReadable = false
		}
		errs = append(errs, notFoundIsNone(optErr))
		for _, o := range options {
			if row, ok := traefikOption(g.group, o); ok {
				k.inv.TraefikTLSOptions = append(k.inv.TraefikTLSOptions, row)
				if row.Name == traefikDefaultOptionName {
					defaults = append(defaults, row.Namespace)
				}
			}
		}

		stores, storeErr := list[traefikTLSStoreObject](ctx, k.c, g.stor, "", nil, k.max)
		errs = append(errs, notFoundIsNone(storeErr))
		for _, s := range stores {
			if row, ok := traefikStore(g.group, s); ok {
				k.inv.TraefikTLSStores = append(k.inv.TraefikTLSStores, row)
			}
		}
	}
	if routes404 == len(traefikGroups) {
		// Neither group serves IngressRoutes: Traefik's CRDs are not
		// installed, whatever else answered.
		k.inv.TraefikTLSOptions, k.inv.TraefikTLSStores = nil, nil
		k.answer(SectionTraefik, 0, firstRouteErr)
		return
	}

	// The same option may be served under both groups during a migration;
	// one namespace is one candidate.
	index := traefikOptionIndex{readable: optionsReadable, defaultNamespaces: sortedUnique(defaults)}
	for _, src := range routes {
		for _, o := range src.objs {
			if row, ok := traefikRoute(src.group, src.kind, o, index); ok {
				k.inv.TraefikIngressRoutes = append(k.inv.TraefikIngressRoutes, row)
			}
		}
	}
	k.answer(SectionTraefik, len(k.inv.TraefikIngressRoutes)+len(k.inv.TraefikTLSOptions)+len(k.inv.TraefikTLSStores), errs...)
}

func traefikRoute(group, kind string, o traefikRouteObject, index traefikOptionIndex) (TraefikIngressRoute, bool) {
	ns, name := cleanName(o.Metadata.Namespace), cleanName(o.Metadata.Name)
	if ns == "" || name == "" {
		return TraefikIngressRoute{}, false
	}
	row := TraefikIngressRoute{
		Kind: kind, APIGroup: group, Namespace: ns, Name: name, UID: cleanUID(o.Metadata.UID),
		EntryPoints: tokens(o.Spec.EntryPoints, traefikTokenRE, maxTraefikToken, 32),
		CreatedAt:   utc(o.Metadata.CreationTimestamp),
	}
	for _, r := range limit(o.Spec.Routes, 256) {
		// The rule is redacted before it is cut, and never sent as written
		// (traefik_rule.go).
		route := TraefikRoute{Match: clip(redactedRule(r.Match), maxTraefikMatch), Hosts: traefikHosts(r.Match)}
		for _, s := range limit(r.Services, 64) {
			svc := TraefikServiceRef{Name: cleanName(s.Name), Namespace: cleanName(s.Namespace), Port: token(string(s.Port), traefikPortRE, 63)}
			switch s.Kind {
			case "", "Service":
				svc.Kind = "Service"
			case "TraefikService":
				svc.Kind = "TraefikService"
			}
			if svc.Name != "" {
				route.Services = append(route.Services, svc)
			}
		}
		row.Routes = append(row.Routes, route)
	}
	if t := o.Spec.TLS; t != nil {
		tls := &TraefikRouteTLS{
			SecretName:   cleanName(t.SecretName),
			OptionsRef:   traefikRef(t.Options, ns),
			Store:        traefikRef(t.Store, ns),
			CertResolver: token(t.CertResolver, traefikTokenRE, maxTraefikToken),
			Passthrough:  kind == traefikKindTCP && t.Passthrough,
		}
		for _, d := range limit(t.Domains, 64) {
			dom := TraefikDomain{Main: cleanHost(d.Main)}
			for _, san := range limit(d.SANs, 128) {
				if h := cleanHost(san); h != "" {
					dom.SANs = append(dom.SANs, h)
				}
			}
			if dom.Main != "" || len(dom.SANs) > 0 {
				tls.Domains = append(tls.Domains, dom)
			}
		}
		tls.EffectiveOptions = index.resolve(tls)
		row.TLS = tls
	}
	return row, true
}

func traefikOption(group string, o traefikTLSOptionObject) (TraefikTLSOption, bool) {
	ns, name := cleanName(o.Metadata.Namespace), cleanName(o.Metadata.Name)
	if ns == "" || name == "" {
		return TraefikTLSOption{}, false
	}
	s := o.Spec
	row := TraefikTLSOption{
		APIGroup: group, Namespace: ns, Name: name, UID: cleanUID(o.Metadata.UID),
		MinVersion:       token(s.MinVersion, traefikTokenRE, 32),
		MaxVersion:       token(s.MaxVersion, traefikTokenRE, 32),
		CipherSuites:     tokens(s.CipherSuites, traefikTokenRE, maxTraefikToken, 128),
		CurvePreferences: tokens(s.CurvePreferences, traefikTokenRE, 64, 32),
		SNIStrict:        s.SNIStrict,
		ALPNProtocols:    tokens(s.ALPNProtocols, traefikALPNRE, 64, 16),
		CreatedAt:        utc(o.Metadata.CreationTimestamp),
	}
	if ca := s.ClientAuth; ca != nil {
		auth := &TraefikClientAuth{Type: token(ca.ClientAuthType, traefikTokenRE, 64)}
		var names []string
		for _, n := range ca.SecretNames {
			names = append(names, cleanName(n))
		}
		auth.SecretNames = limit(sortedUnique(names), 64)
		if auth.Type != "" || len(auth.SecretNames) > 0 {
			row.ClientAuth = auth
		}
	}
	return row, true
}

func traefikStore(group string, o traefikTLSStoreObject) (TraefikTLSStore, bool) {
	ns, name := cleanName(o.Metadata.Namespace), cleanName(o.Metadata.Name)
	if ns == "" || name == "" {
		return TraefikTLSStore{}, false
	}
	row := TraefikTLSStore{APIGroup: group, Namespace: ns, Name: name, UID: cleanUID(o.Metadata.UID), CreatedAt: utc(o.Metadata.CreationTimestamp)}
	if d := o.Spec.DefaultCertificate; d != nil {
		row.DefaultCertificateSecret = cleanName(d.SecretName)
	}
	var names []string
	for _, c := range o.Spec.Certificates {
		names = append(names, cleanName(c.SecretName))
	}
	row.CertificateSecrets = limit(sortedUnique(names), 256)
	return row, true
}
