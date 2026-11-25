package kubeinventory

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ---- cert-manager and signing requests ----

func readyCondition(conds []condition) *Condition {
	c := findCondition(conds, "Ready")
	if c == nil {
		return nil
	}
	out := &Condition{Status: "unknown", Reason: clip(c.Reason, 128), Message: message(c.Message)}
	switch c.Status {
	case "True":
		out.Status = "true"
	case "False":
		out.Status = "false"
	}
	return out
}

func issuerRef(r issuerRefObject) *IssuerRef {
	name := cleanName(r.Name)
	if name == "" {
		return nil
	}
	return &IssuerRef{Group: cleanGroup(r.Group), Kind: cleanKind(r.Kind), Name: name}
}

func (k *collector) collectCertManager(ctx context.Context) {
	if !k.reads(ClassCertManager) {
		return
	}
	certs, err := list[cmCertificateObject](ctx, k.c, resCMCertificates, "", nil, k.max)
	if statusOf(err) == http.StatusNotFound {
		k.answer(ClassCertManager, 0, err)
		return
	}
	for _, c := range certs {
		ns, name := cleanName(c.Metadata.Namespace), cleanName(c.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := CertManagerCertificate{
			Namespace: ns, Name: name, UID: cleanUID(c.Metadata.UID),
			SecretName: cleanName(c.Spec.SecretName), IssuerRef: issuerRef(c.Spec.IssuerRef),
			CommonName:  clip(c.Spec.CommonName, 253),
			DNSNames:    limit(clipAll(c.Spec.DNSNames, 253), 1024),
			IPAddresses: cleanIPs(c.Spec.IPAddresses, 256),
			URIs:        limit(clipAll(c.Spec.URIs, 1024), 256),
			IsCA:        c.Spec.IsCA, Usages: limit(clipAll(c.Spec.Usages, 64), 32),
			Duration: cleanDuration(c.Spec.Duration), RenewBefore: cleanDuration(c.Spec.RenewBefore),
			Ready:     readyCondition(c.Status.Conditions),
			NotBefore: utc(c.Status.NotBefore), NotAfter: utc(c.Status.NotAfter), RenewalTime: utc(c.Status.RenewalTime),
			CreatedAt: utc(c.Metadata.CreationTimestamp),
		}
		if c.Status.Revision > 0 {
			row.Revision = c.Status.Revision
		}
		if pk := c.Spec.PrivateKey; pk != nil {
			row.KeyRequest = &KeyRequest{Algorithm: clip(pk.Algorithm, 32), Encoding: clip(pk.Encoding, 16), RotationPolicy: clip(pk.RotationPolicy, 16)}
			if pk.Size > 0 {
				row.KeyRequest.Size = pk.Size
			}
		}
		k.inv.CertManagerCertificates = append(k.inv.CertManagerCertificates, row)
	}

	issuers, issuerErr := list[cmIssuerObject](ctx, k.c, resCMIssuers, "", nil, k.max)
	clusterIssuers, clusterIssuerErr := list[cmIssuerObject](ctx, k.c, resCMClusterIss, "", nil, k.max)
	addIssuer := func(scope string, i cmIssuerObject) {
		name := cleanName(i.Metadata.Name)
		if name == "" {
			return
		}
		row := CertManagerIssuer{
			Scope: scope, Name: name, UID: cleanUID(i.Metadata.UID), Type: "unknown",
			Ready: readyCondition(i.Status.Conditions), CreatedAt: utc(i.Metadata.CreationTimestamp),
		}
		if scope == "namespace" {
			if row.Namespace = cleanName(i.Metadata.Namespace); row.Namespace == "" {
				return
			}
		}
		switch spec := i.Spec; {
		case spec.ACME != nil:
			row.Type = "acme"
			row.ACMEServer = clip(spec.ACME.Server, 1024)
			var solvers []string
			for _, s := range spec.ACME.Solvers {
				if s.HTTP01 != nil {
					solvers = append(solvers, "http01")
				}
				if s.DNS01 != nil {
					solvers = append(solvers, "dns01")
				}
			}
			row.ACMESolvers = sortedUnique(solvers)
		case spec.CA != nil:
			row.Type = "ca"
			row.CASecretName = cleanName(spec.CA.SecretName)
		case spec.SelfSigned != nil:
			row.Type = "self_signed"
		case spec.Vault != nil:
			row.Type = "vault"
			row.VaultServer, row.VaultPath = clip(spec.Vault.Server, 1024), clip(spec.Vault.Path, 512)
		case spec.Venafi != nil:
			row.Type = "venafi"
			row.VenafiZone = clip(spec.Venafi.Zone, 512)
		}
		k.inv.CertManagerIssuers = append(k.inv.CertManagerIssuers, row)
	}
	for _, i := range clusterIssuers {
		addIssuer("cluster", i)
	}
	for _, i := range issuers {
		addIssuer("namespace", i)
	}

	requests, requestErr := list[cmRequestObject](ctx, k.c, resCMRequests, "", nil, k.max)
	for _, r := range requests {
		ns, name := cleanName(r.Metadata.Namespace), cleanName(r.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := CertManagerRequest{
			Namespace: ns, Name: name, UID: cleanUID(r.Metadata.UID), IssuerRef: issuerRef(r.Spec.IssuerRef),
			IsCA: r.Spec.IsCA, Usages: limit(clipAll(r.Spec.Usages, 64), 32), Duration: cleanDuration(r.Spec.Duration),
			Approval: approval(r.Status.Conditions), Ready: readyCondition(r.Status.Conditions),
			CSR: parseCSR(r.Spec.Request), CreatedAt: utc(r.Metadata.CreationTimestamp),
		}
		if row.Approval == "failed" { // not a cert-manager state
			row.Approval = "pending"
		}
		if owner := r.Metadata.controller(); owner != nil && owner.Kind == "Certificate" {
			row.CertificateName = cleanName(owner.Name)
		}
		if len(r.Status.Certificate) > 0 {
			row.CertificateChain = k.certs.addPEM(r.Status.Certificate)
		}
		if len(r.Status.CA) > 0 {
			row.CACertificates = k.certs.addPEM(r.Status.CA)
		}
		k.inv.CertManagerRequests = append(k.inv.CertManagerRequests, row)
	}
	count := len(k.inv.CertManagerCertificates) + len(k.inv.CertManagerIssuers) + len(k.inv.CertManagerRequests)
	k.answer(ClassCertManager, count, err, issuerErr, clusterIssuerErr, requestErr)
}

// approval reads Approved, Denied and Failed conditions.
func approval(conds []condition) string {
	is := func(kind string) bool {
		c := findCondition(conds, kind)
		return c != nil && c.Status == "True"
	}
	switch {
	case is("Denied"):
		return "denied"
	case is("Failed"):
		return "failed"
	case is("Approved"):
		return "approved"
	}
	return "pending"
}

func (k *collector) collectCSRs(ctx context.Context) {
	if !k.reads(ClassCSRs) {
		return
	}
	csrs, err := list[csrObject](ctx, k.c, resCSRs, "", nil, k.max)
	for _, r := range csrs {
		name := cleanName(r.Metadata.Name)
		if name == "" {
			continue
		}
		row := CertificateSigningRequest{
			Name: name, UID: cleanUID(r.Metadata.UID), SignerName: clip(r.Spec.SignerName, 253),
			Requestor: clip(r.Spec.Username, 253), Usages: limit(clipAll(r.Spec.Usages, 64), 32),
			Approval: approval(r.Status.Conditions), CSR: parseCSR(r.Spec.Request),
			CreatedAt: utc(r.Metadata.CreationTimestamp),
		}
		if r.Spec.ExpirationSeconds > 0 {
			row.ExpirationSeconds = r.Spec.ExpirationSeconds
		}
		if len(r.Status.Certificate) > 0 {
			row.CertificateChain = k.certs.addPEM(r.Status.Certificate)
		}
		k.inv.CertificateSigningRequests = append(k.inv.CertificateSigningRequests, row)
	}
	k.answer(ClassCSRs, len(k.inv.CertificateSigningRequests), err)
}

// ---- TLS Secrets (only when the cluster's administrators enabled it) ----

// tlsSecretSelector asks the API server for Secrets of type kubernetes.io/tls
// and no others, so that no other Secret is ever sent to this process.
var tlsSecretSelector = url.Values{"fieldSelector": {"type=kubernetes.io/tls"}}

func (k *collector) collectTLSSecrets(ctx context.Context) {
	if !k.wanted[ClassTLSSecrets] {
		return
	}
	if !k.opts.ReadTLSSecrets {
		// Not enabled: the Secrets API is not called at all, not even to
		// find out whether it would answer.
		k.inv.Sections[ClassTLSSecrets] = Section{
			Status: StatusUnsupported, Reason: ReasonNotEnabled,
			Message: "Reading TLS Secrets is not enabled for this agent. Secrets are known only by the names other objects use for them.",
		}
		return
	}
	readable := map[string]bool{}
	secrets, err := list[tlsSecretObject](ctx, k.c, resSecrets, "", tlsSecretSelector, k.max)
	switch {
	case err == nil:
		for _, ns := range k.namespaces {
			readable[ns.Metadata.Name] = true
		}
	case statusOf(err) == http.StatusForbidden:
		// The opt-in role may be bound in some namespaces only.
		secrets, err = nil, nil
		denied := 0
		for _, ns := range k.namespaces {
			rows, nsErr := list[tlsSecretObject](ctx, k.c, resSecrets, ns.Metadata.Name, tlsSecretSelector, k.max)
			switch {
			case nsErr == nil:
				readable[ns.Metadata.Name] = true
				secrets = append(secrets, rows...)
			case statusOf(nsErr) == http.StatusForbidden:
				readable[ns.Metadata.Name] = false
				denied++
			default:
				readable[ns.Metadata.Name] = false
				err = nsErr
			}
		}
		if err == nil && denied == len(k.namespaces) {
			err = &APIError{Status: http.StatusForbidden, Message: "the agent's service account may not list Secrets in any namespace"}
		}
	}
	for i := range k.inv.Namespaces {
		if ok, known := readable[k.inv.Namespaces[i].Name]; known {
			k.inv.Namespaces[i].TLSSecretsReadable = boolPtr(ok)
		}
	}
	for _, s := range secrets {
		// The selector already limits the answer; this holds even if a
		// server ignored it.
		if s.Type != "kubernetes.io/tls" {
			continue
		}
		ns, name := cleanName(s.Metadata.Namespace), cleanName(s.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := TLSSecret{
			Namespace: ns, Name: name, UID: cleanUID(s.Metadata.UID), CreatedAt: utc(s.Metadata.CreationTimestamp),
			CertManagerCertificate: cleanName(s.Metadata.Annotations.CertificateName),
		}
		if owner := s.Metadata.controller(); owner != nil {
			if on := cleanName(owner.Name); on != "" {
				row.Owner = &ObjectRef{Group: groupOf(owner.APIVersion), Kind: cleanKind(owner.Kind), Name: on}
			}
		}
		if len(s.Data.TLSCrt) > 0 {
			if row.CertificateChain = k.certs.addPEM(s.Data.TLSCrt); len(row.CertificateChain) == 0 {
				row.CertificateChain = nil
				row.UnparsedEntries = append(row.UnparsedEntries, "tls.crt")
			}
		}
		if len(s.Data.CACrt) > 0 {
			if row.CACertificates = k.certs.addPEM(s.Data.CACrt); len(row.CACertificates) == 0 {
				row.CACertificates = nil
				row.UnparsedEntries = append(row.UnparsedEntries, "ca.crt")
			}
		}
		k.inv.TLSSecrets = append(k.inv.TLSSecrets, row)
	}
	k.answer(ClassTLSSecrets, len(k.inv.TLSSecrets), err)
}

// ---- meshes ----

const (
	istioRootNamespace = "istio-system"
	linkerdNamespace   = "linkerd"

	mtlsStrict     = "strict"
	mtlsPermissive = "permissive"
	mtlsDisabled   = "disabled"
	mtlsNotMeshed  = "not_meshed"
	mtlsUnknown    = "unknown"
)

// istioPolicies is the PeerAuthentications of a cluster, oldest first, which
// is the order Istio prefers them in.
type istioPolicies struct {
	policies []peerAuthenticationObject
}

func istioMode(m *mtlsMode) string {
	if m == nil {
		return ""
	}
	switch strings.ToUpper(m.Mode) {
	case "STRICT":
		return mtlsStrict
	case "PERMISSIVE":
		return mtlsPermissive
	case "DISABLE":
		return mtlsDisabled
	}
	return ""
}

func rawIstioMode(m *mtlsMode, allowed ...string) string {
	if m != nil {
		for _, a := range allowed {
			if strings.EqualFold(m.Mode, a) {
				return a
			}
		}
	}
	return "UNSET"
}

// modeFor is the peer-authentication mode in force for pods with these labels
// in this namespace: a policy selecting them, else the namespace's, else the
// mesh's, else permissive. A policy that sets no mode inherits.
func (p *istioPolicies) modeFor(namespace string, labels map[string]string) string {
	var workload, ns, mesh string
	for _, pa := range p.policies {
		mode := istioMode(pa.Spec.MTLS)
		if mode == "" {
			continue
		}
		selector := map[string]string(nil)
		if pa.Spec.Selector != nil {
			selector = pa.Spec.Selector.MatchLabels
		}
		switch {
		case len(selector) > 0:
			if workload == "" && pa.Metadata.Namespace == namespace && labels != nil && selects(selector, labels) {
				workload = mode
			}
		case pa.Metadata.Namespace == namespace && namespace != istioRootNamespace:
			if ns == "" {
				ns = mode
			}
		case pa.Metadata.Namespace == istioRootNamespace:
			if mesh == "" {
				mesh = mode
			}
		}
	}
	for _, m := range []string{workload, ns, mesh} {
		if m != "" {
			return m
		}
	}
	return mtlsPermissive
}

func (k *collector) collectIstio(ctx context.Context) {
	if !k.reads(ClassMeshIstio) {
		return
	}
	policies, err := list[peerAuthenticationObject](ctx, k.c, resPeerAuths, "", nil, k.max)
	if statusOf(err) == http.StatusNotFound {
		k.inv.Mesh.Istio = &MeshIstio{Present: false}
		for i := range k.inv.Namespaces {
			k.inv.Namespaces[i].IstioMTLSMode = mtlsNotMeshed
		}
		k.answer(ClassMeshIstio, 0, err)
		return
	}
	sort.SliceStable(policies, func(i, j int) bool {
		a, b := policies[i].Metadata.CreationTimestamp, policies[j].Metadata.CreationTimestamp
		return a != nil && (b == nil || a.Before(*b))
	})
	if err == nil {
		k.istio = &istioPolicies{policies: policies}
	}
	for _, pa := range policies {
		ns, name := cleanName(pa.Metadata.Namespace), cleanName(pa.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := IstioPeerAuthentication{
			Namespace: ns, Name: name, UID: cleanUID(pa.Metadata.UID), Scope: "namespace",
			Mode: rawIstioMode(pa.Spec.MTLS, "STRICT", "PERMISSIVE", "DISABLE"),
		}
		switch {
		case pa.Spec.Selector != nil && len(pa.Spec.Selector.MatchLabels) > 0:
			row.Scope = "workload"
			row.Selector = selectorLabels(pa.Spec.Selector.MatchLabels)
		case ns == istioRootNamespace:
			row.Scope = "mesh"
		}
		ports := make([]string, 0, len(pa.Spec.PortLevelMTLS))
		for p := range pa.Spec.PortLevelMTLS {
			ports = append(ports, p)
		}
		sort.Strings(ports)
		for _, p := range limit(ports, 256) {
			m := pa.Spec.PortLevelMTLS[p]
			if n, convErr := strconv.Atoi(p); convErr == nil && cleanPort(n) != 0 {
				row.PortModes = append(row.PortModes, PortMode{Port: n, Mode: rawIstioMode(&m, "STRICT", "PERMISSIVE", "DISABLE")})
			}
		}
		k.inv.IstioPeerAuthentications = append(k.inv.IstioPeerAuthentications, row)
	}

	rules, ruleErr := list[destinationRuleObject](ctx, k.c, resDestRules, "", nil, k.max)
	for _, r := range rules {
		ns, name := cleanName(r.Metadata.Namespace), cleanName(r.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := IstioDestinationRule{Namespace: ns, Name: name, UID: cleanUID(r.Metadata.UID), Host: clip(r.Spec.Host, 253), TLSMode: "UNSET"}
		if tp := r.Spec.TrafficPolicy; tp != nil {
			row.TLSMode = rawIstioMode(tp.TLS, "DISABLE", "SIMPLE", "MUTUAL", "ISTIO_MUTUAL")
			for _, p := range limit(tp.PortLevelSettings, 256) {
				if mode := rawIstioMode(p.TLS, "DISABLE", "SIMPLE", "MUTUAL", "ISTIO_MUTUAL"); mode != "UNSET" && cleanPort(p.Port.Number) != 0 {
					row.PortTLSModes = append(row.PortTLSModes, PortMode{Port: p.Port.Number, Mode: mode})
				}
			}
		}
		k.inv.IstioDestinationRules = append(k.inv.IstioDestinationRules, row)
	}

	mesh := &MeshIstio{Present: true}
	var anchorErr error
	if k.namespaceObject(istioRootNamespace) != nil {
		mesh.RootNamespace = istioRootNamespace
		cm, cmErr := getNamed[istioRootConfigMap](ctx, k.c, resConfigMaps, istioRootNamespace, configMapIstioRoot)
		anchorErr = notFoundIsNone(cmErr)
		if cm != nil {
			if fps := k.certs.addPEM([]byte(cm.Data.RootCert)); len(fps) > 0 {
				mesh.TrustAnchors = fps
			}
		}
	}
	if k.istio != nil {
		mesh.MeshMTLSMode = k.istio.modeFor("", nil)
		for i := range k.inv.Namespaces {
			k.inv.Namespaces[i].IstioMTLSMode = k.istio.modeFor(k.inv.Namespaces[i].Name, nil)
		}
	} else {
		mesh.MeshMTLSMode = mtlsUnknown
		for i := range k.inv.Namespaces {
			k.inv.Namespaces[i].IstioMTLSMode = mtlsUnknown
		}
	}
	k.inv.Mesh.Istio = mesh
	k.answer(ClassMeshIstio, len(k.inv.IstioPeerAuthentications)+len(k.inv.IstioDestinationRules), err, notFoundIsNone(ruleErr), anchorErr)
}

// workloadMTLSMode is the mesh mTLS mode in force for a workload's pods.
func (k *collector) workloadMTLSMode(st *workloadState) string {
	ns := k.namespaceObject(st.row.Namespace)
	ambient := ns != nil && ns.Metadata.Labels["istio.io/dataplane-mode"] == "ambient"
	switch {
	case st.proxy == "istio" || ambient:
		if k.istio == nil {
			return mtlsUnknown
		}
		return k.istio.modeFor(st.row.Namespace, st.podLabels)
	case st.proxy == "linkerd":
		// Linkerd encrypts between meshed pods without configuration; what
		// varies is whether a pod still accepts traffic from outside the mesh.
		policy := ""
		if ns != nil {
			policy = ns.Metadata.Annotations.LinkerdInboundPolicy
		}
		switch {
		case strings.Contains(policy, "unauthenticated") || policy == "":
			return mtlsPermissive
		case strings.Contains(policy, "authenticated"):
			return mtlsStrict
		}
		return mtlsUnknown
	}
	return mtlsNotMeshed
}

func (k *collector) collectLinkerd(ctx context.Context) {
	if !k.reads(ClassMeshLinkerd) {
		return
	}
	servers, err := list[linkerdServerObject](ctx, k.c, resLinkerdServers, "", nil, k.max)
	if statusOf(err) == http.StatusNotFound {
		k.inv.Mesh.Linkerd = &MeshLinkerd{Present: false}
		k.answer(ClassMeshLinkerd, 0, err)
		return
	}
	for _, s := range servers {
		ns, name := cleanName(s.Metadata.Namespace), cleanName(s.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := LinkerdServer{Namespace: ns, Name: name, UID: cleanUID(s.Metadata.UID), Port: clip(string(s.Spec.Port), 63), ProxyProtocol: clip(s.Spec.ProxyProtocol, 32)}
		if s.Spec.PodSelector != nil {
			row.PodSelector = selectorLabels(s.Spec.PodSelector.MatchLabels)
		}
		k.inv.LinkerdServers = append(k.inv.LinkerdServers, row)
	}
	policies, policyErr := list[linkerdAuthorizationPolicyObject](ctx, k.c, resLinkerdAuthz, "", nil, k.max)
	ref := func(r linkerdRef) *ObjectRef {
		name := cleanName(r.Name)
		if name == "" {
			return nil
		}
		return &ObjectRef{Group: cleanGroup(r.Group), Kind: cleanKind(r.Kind), Namespace: cleanName(r.Namespace), Name: name}
	}
	for _, p := range policies {
		ns, name := cleanName(p.Metadata.Namespace), cleanName(p.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := LinkerdAuthorizationPolicy{Namespace: ns, Name: name, UID: cleanUID(p.Metadata.UID)}
		if p.Spec.TargetRef != nil {
			row.Target = ref(*p.Spec.TargetRef)
		}
		for _, r := range limit(p.Spec.RequiredAuthenticationRefs, 64) {
			if o := ref(r); o != nil {
				row.RequiredAuthentications = append(row.RequiredAuthentications, *o)
			}
		}
		k.inv.LinkerdAuthorizationPolicies = append(k.inv.LinkerdAuthorizationPolicies, row)
	}
	mesh := &MeshLinkerd{Present: true}
	var anchorErr error
	if k.namespaceObject(linkerdNamespace) != nil {
		mesh.Namespace = linkerdNamespace
		cm, cmErr := getNamed[linkerdTrustConfigMap](ctx, k.c, resConfigMaps, linkerdNamespace, configMapLinkerdTrust)
		anchorErr = notFoundIsNone(cmErr)
		if cm != nil {
			if fps := k.certs.addPEM([]byte(cm.Data.Bundle)); len(fps) > 0 {
				mesh.TrustAnchors = fps
			}
		}
	}
	k.inv.Mesh.Linkerd = mesh
	k.answer(ClassMeshLinkerd, len(k.inv.LinkerdServers)+len(k.inv.LinkerdAuthorizationPolicies), err, notFoundIsNone(policyErr), anchorErr)
}

func (k *collector) collectCilium(ctx context.Context) {
	if !k.reads(ClassMeshCilium) {
		return
	}
	cm, err := getNamed[ciliumConfigMap](ctx, k.c, resConfigMaps, kubeSystem, configMapCilium)
	if statusOf(err) == http.StatusNotFound {
		k.inv.Mesh.Cilium = &MeshCilium{Present: false}
		k.answer(ClassMeshCilium, 0, err)
		return
	}
	if err != nil {
		k.answer(ClassMeshCilium, 0, err)
		return
	}
	mesh := &MeshCilium{Present: true, Encryption: "none", NodeEncryption: boolPtr(cm.Data.EncryptNode == "true")}
	switch {
	case cm.Data.EnableWireguard == "true":
		mesh.Encryption = "wireguard"
	case cm.Data.EnableIPsec == "true":
		mesh.Encryption = "ipsec"
	}
	k.inv.Mesh.Cilium = mesh
	k.answer(ClassMeshCilium, 1)
}

// ---- admission webhooks and aggregated APIs ----

func serviceTarget(s *serviceReference) *ServiceTarget {
	if s == nil || cleanName(s.Name) == "" {
		return nil
	}
	return &ServiceTarget{Namespace: cleanName(s.Namespace), Name: s.Name, Port: cleanPort(s.Port)}
}

func (k *collector) collectAdmission(ctx context.Context) {
	if !k.reads(ClassAdmissionWebhooks) {
		return
	}
	var errs []error
	for _, src := range []struct {
		res  Resource
		kind string
	}{{resValidatingWH, "validating"}, {resMutatingWH, "mutating"}} {
		configs, err := list[webhookConfigurationObject](ctx, k.c, src.res, "", nil, k.max)
		errs = append(errs, err)
		for _, cfg := range configs {
			cfgName := cleanName(cfg.Metadata.Name)
			if cfgName == "" {
				continue
			}
			for _, w := range cfg.Webhooks {
				if w.Name == "" {
					continue
				}
				row := AdmissionWebhook{
					Kind: src.kind, Configuration: cfgName, ConfigurationUID: cleanUID(cfg.Metadata.UID),
					Name: clip(w.Name, 253), Service: serviceTarget(w.ClientConfig.Service),
					CABundle: k.certs.addPEM(w.ClientConfig.CABundle),
				}
				if w.FailurePolicy == "Fail" || w.FailurePolicy == "Ignore" {
					row.FailurePolicy = w.FailurePolicy
				}
				// Only the host of a webhook URL: its path and query can
				// carry anything.
				if u, parseErr := url.Parse(w.ClientConfig.URL); parseErr == nil && w.ClientConfig.URL != "" {
					row.URLHost = clip(u.Host, 253)
				}
				k.inv.AdmissionWebhooks = append(k.inv.AdmissionWebhooks, row)
			}
		}
	}
	k.answer(ClassAdmissionWebhooks, len(k.inv.AdmissionWebhooks), errs...)
}

func (k *collector) collectAPIServices(ctx context.Context) {
	if !k.reads(ClassAPIServices) {
		return
	}
	services, err := list[apiServiceObject](ctx, k.c, resAPIServices, "", nil, k.max)
	for _, s := range services {
		// An APIService without a Service is served by the API server itself
		// and has no TLS of its own.
		target := serviceTarget(s.Spec.Service)
		if target == nil || s.Metadata.Name == "" {
			continue
		}
		row := APIService{
			Name: clip(s.Metadata.Name, 253), UID: cleanUID(s.Metadata.UID), Group: cleanGroup(s.Spec.Group),
			Version: clip(s.Spec.Version, 63), Service: target, InsecureSkipTLSVerify: s.Spec.InsecureSkipTLSVerify,
			CABundle: k.certs.addPEM(s.Spec.CABundle),
		}
		if c := findCondition(s.Status.Conditions, "Available"); c != nil {
			row.Available = boolPtr(c.Status == "True")
		}
		k.inv.APIServices = append(k.inv.APIServices, row)
	}
	k.answer(ClassAPIServices, len(k.inv.APIServices), err)
}

// ---- control plane ----

// collectAPIServer describes the TLS connection the collector has had with
// the API server all along. It makes no new connection.
func (k *collector) collectAPIServer() {
	if !k.wanted[ClassAPIServerCert] {
		return
	}
	state := k.c.connectionState()
	if state == nil {
		k.inv.Sections[ClassAPIServerCert] = Section{Status: StatusFailed, Reason: ReasonUnreachable, Message: "No connection to the API server was completed."}
		return
	}
	h := &Handshake{Address: cleanIP(k.c.host), Port: k.c.port, ServerName: apiServerHostname}
	if h.Address == "" {
		// The kubelet gives an address; anything else is not reported.
		k.inv.Sections[ClassAPIServerCert] = Section{Status: StatusFailed, Reason: ReasonAPIError, Message: "The API server address is not an IP address."}
		return
	}
	describeState(h, state, k.certs, k.c.caPool)
	k.inv.APIServer = h
	k.answer(ClassAPIServerCert, 1)
}

const kubeletProbeWorkers = 16

// collectKubelets completes a TLS handshake with each node's kubelet port, at
// the node's internal address as the API reports it, and with nothing else.
func (k *collector) collectKubelets(ctx context.Context) {
	if !k.wanted[ClassKubeletCerts] {
		return
	}
	if k.opts.SkipKubeletProbe {
		k.inv.Sections[ClassKubeletCerts] = Section{Status: StatusUnsupported, Reason: ReasonNotRequested}
		return
	}
	if s := k.inv.Sections[ClassNodes]; s.Status != StatusOK && len(k.nodes) == 0 {
		k.inv.Sections[ClassKubeletCerts] = Section{Status: StatusFailed, Reason: s.Reason, Message: "The nodes could not be listed, so there was no kubelet to reach."}
		return
	}
	type target struct {
		node, address string
		port          int
	}
	var targets []target
	for _, n := range k.nodes {
		name, port := cleanName(n.Metadata.Name), cleanPort(n.Status.DaemonEndpoints.KubeletEndpoint.Port)
		if name == "" || port == 0 {
			continue
		}
		for _, a := range n.Status.Addresses {
			if addr := cleanIP(a.Address); a.Type == "InternalIP" && addr != "" {
				targets = append(targets, target{name, addr, port})
				break
			}
		}
	}
	rows := make([]Kubelet, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, kubeletProbeWorkers)
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rows[i] = Kubelet{Node: t.node, Handshake: probeTLS(ctx, t.address, t.port, k.certs, k.c.caPool)}
		}()
	}
	wg.Wait()
	reached := 0
	for _, r := range rows {
		if r.Status == handshakeOK {
			reached++
		}
	}
	k.inv.Kubelets = rows
	if len(rows) > 0 && reached == 0 {
		k.inv.Sections[ClassKubeletCerts] = Section{
			Status: StatusFailed, Reason: ReasonUnreachable, Count: intPtr(len(rows)),
			Message: "No kubelet completed a handshake. A network policy on the agent's namespace or a node firewall may be blocking the kubelet port.",
		}
		return
	}
	k.answer(ClassKubeletCerts, len(rows), nodesError(k.inv.Sections[ClassNodes]))
}

// nodesError turns a failed node listing back into an error for a class built
// from the nodes.
func nodesError(s Section) error {
	if s.Status == StatusOK {
		return nil
	}
	return &APIError{Status: http.StatusInternalServerError, Message: "the node list was incomplete: " + s.Reason}
}
