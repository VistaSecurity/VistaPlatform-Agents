package kubeinventory

// The complete list of what the collector can ask the API server. Every
// request goes through Client.get or list with one of these values, so this
// table is the collector's whole reach; the manifest's ClusterRole is tested
// against Calls() in both directions, and the collector tests fail on a
// request that matches no entry.

import "sort"

// The two verbs the collector uses. It never watches and never writes.
const (
	VerbGet  = "get"
	VerbList = "list"
)

// Resource is one kind of object the collector reads, and how.
type Resource struct {
	// Group is the API group; "" is the core group.
	Group string
	// Versions are tried in order; a 404 moves to the next.
	Versions []string
	// Name is the plural resource name.
	Name string
	// Verb is VerbList, or VerbGet for objects read by name.
	Verb string
	// Names, for VerbGet, are the only object names ever requested.
	Names []string
	// OptIn marks the calls made only when reading TLS Secrets is enabled.
	OptIn bool
}

var (
	resNamespaces     = Resource{Group: "", Versions: []string{"v1"}, Name: "namespaces", Verb: VerbList}
	resNodes          = Resource{Group: "", Versions: []string{"v1"}, Name: "nodes", Verb: VerbList}
	resPods           = Resource{Group: "", Versions: []string{"v1"}, Name: "pods", Verb: VerbList}
	resServices       = Resource{Group: "", Versions: []string{"v1"}, Name: "services", Verb: VerbList}
	resConfigMaps     = Resource{Group: "", Versions: []string{"v1"}, Name: "configmaps", Verb: VerbGet, Names: []string{configMapIstioRoot, configMapLinkerdTrust, configMapCilium}}
	resSecrets        = Resource{Group: "", Versions: []string{"v1"}, Name: "secrets", Verb: VerbList, OptIn: true}
	resDeployments    = Resource{Group: "apps", Versions: []string{"v1"}, Name: "deployments", Verb: VerbList}
	resStatefulSets   = Resource{Group: "apps", Versions: []string{"v1"}, Name: "statefulsets", Verb: VerbList}
	resDaemonSets     = Resource{Group: "apps", Versions: []string{"v1"}, Name: "daemonsets", Verb: VerbList}
	resReplicaSets    = Resource{Group: "apps", Versions: []string{"v1"}, Name: "replicasets", Verb: VerbList}
	resCronJobs       = Resource{Group: "batch", Versions: []string{"v1"}, Name: "cronjobs", Verb: VerbList}
	resJobs           = Resource{Group: "batch", Versions: []string{"v1"}, Name: "jobs", Verb: VerbList}
	resEndpointSlices = Resource{Group: "discovery.k8s.io", Versions: []string{"v1"}, Name: "endpointslices", Verb: VerbList}
	resIngresses      = Resource{Group: "networking.k8s.io", Versions: []string{"v1"}, Name: "ingresses", Verb: VerbList}
	resIngressClasses = Resource{Group: "networking.k8s.io", Versions: []string{"v1"}, Name: "ingressclasses", Verb: VerbList}
	resServiceCIDRs   = Resource{Group: "networking.k8s.io", Versions: []string{"v1", "v1beta1"}, Name: "servicecidrs", Verb: VerbList}
	resGatewayClasses = Resource{Group: "gateway.networking.k8s.io", Versions: []string{"v1", "v1beta1"}, Name: "gatewayclasses", Verb: VerbList}
	resGateways       = Resource{Group: "gateway.networking.k8s.io", Versions: []string{"v1", "v1beta1"}, Name: "gateways", Verb: VerbList}
	resHTTPRoutes     = Resource{Group: "gateway.networking.k8s.io", Versions: []string{"v1", "v1beta1"}, Name: "httproutes", Verb: VerbList}
	resGRPCRoutes     = Resource{Group: "gateway.networking.k8s.io", Versions: []string{"v1", "v1alpha2"}, Name: "grpcroutes", Verb: VerbList}
	resTLSRoutes      = Resource{Group: "gateway.networking.k8s.io", Versions: []string{"v1alpha3", "v1alpha2"}, Name: "tlsroutes", Verb: VerbList}
	resTCPRoutes      = Resource{Group: "gateway.networking.k8s.io", Versions: []string{"v1alpha2"}, Name: "tcproutes", Verb: VerbList}
	resCMCertificates = Resource{Group: "cert-manager.io", Versions: []string{"v1"}, Name: "certificates", Verb: VerbList}
	resCMRequests     = Resource{Group: "cert-manager.io", Versions: []string{"v1"}, Name: "certificaterequests", Verb: VerbList}
	resCMIssuers      = Resource{Group: "cert-manager.io", Versions: []string{"v1"}, Name: "issuers", Verb: VerbList}
	resCMClusterIss   = Resource{Group: "cert-manager.io", Versions: []string{"v1"}, Name: "clusterissuers", Verb: VerbList}
	resCSRs           = Resource{Group: "certificates.k8s.io", Versions: []string{"v1"}, Name: "certificatesigningrequests", Verb: VerbList}
	resPeerAuths      = Resource{Group: "security.istio.io", Versions: []string{"v1", "v1beta1"}, Name: "peerauthentications", Verb: VerbList}
	resDestRules      = Resource{Group: "networking.istio.io", Versions: []string{"v1", "v1beta1"}, Name: "destinationrules", Verb: VerbList}
	resLinkerdServers = Resource{Group: "policy.linkerd.io", Versions: []string{"v1beta3", "v1beta2", "v1beta1"}, Name: "servers", Verb: VerbList}
	resLinkerdAuthz   = Resource{Group: "policy.linkerd.io", Versions: []string{"v1alpha1"}, Name: "authorizationpolicies", Verb: VerbList}
	resValidatingWH   = Resource{Group: "admissionregistration.k8s.io", Versions: []string{"v1"}, Name: "validatingwebhookconfigurations", Verb: VerbList}
	resMutatingWH     = Resource{Group: "admissionregistration.k8s.io", Versions: []string{"v1"}, Name: "mutatingwebhookconfigurations", Verb: VerbList}
	resAPIServices    = Resource{Group: "apiregistration.k8s.io", Versions: []string{"v1"}, Name: "apiservices", Verb: VerbList}
)

// The ConfigMaps read by name, and nothing else of any ConfigMap.
const (
	configMapIstioRoot    = "istio-ca-root-cert"
	configMapLinkerdTrust = "linkerd-identity-trust-roots"
	configMapCilium       = "cilium-config"
)

// NonResourceURLs are the non-resource paths the collector gets.
var NonResourceURLs = []string{"/version"}

var allResources = []Resource{
	resNamespaces, resNodes, resPods, resServices, resConfigMaps, resSecrets,
	resDeployments, resStatefulSets, resDaemonSets, resReplicaSets, resCronJobs, resJobs,
	resEndpointSlices, resIngresses, resIngressClasses, resServiceCIDRs,
	resGatewayClasses, resGateways, resHTTPRoutes, resGRPCRoutes, resTLSRoutes, resTCPRoutes,
	resCMCertificates, resCMRequests, resCMIssuers, resCMClusterIss, resCSRs,
	resPeerAuths, resDestRules, resLinkerdServers, resLinkerdAuthz,
	resValidatingWH, resMutatingWH, resAPIServices,
	// Only when a job asks for Traefik (traefik.go).
	resTraefikRoutes, resTraefikRoutesTCP, resTraefikTLSOptions, resTraefikTLSStores,
	resTraefikLegacyRoutes, resTraefikLegacyRoutesTCP, resTraefikLegacyOptions, resTraefikLegacyStores,
}

// Calls is every resource the collector can read: with optIn false, what it
// reads by default; with optIn true, what it reads in addition when reading
// TLS Secrets is enabled.
func Calls(optIn bool) []Resource {
	var out []Resource
	for _, r := range allResources {
		if r.OptIn == optIn {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Name < out[j].Name
	})
	return out
}
