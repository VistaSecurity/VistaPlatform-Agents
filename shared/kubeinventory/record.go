// Package kubeinventory reads the Kubernetes API of the cluster the agent runs
// in and returns what the cluster says about its cryptography, as the record of
// schemas/managed/v1/defs/kubernetes-inventory.json
// (docs/design/kubernetes-inventory.md).
//
// The rules it keeps:
//
//   - Posture, never key material. No type in this package can hold a Secret's
//     data except the certificates of a TLS Secret, and a TLS Secret's key is
//     never decoded (see tlsSecretObject).
//   - Read-only, by name. Every call the collector can make is one entry of
//     the table in calls.go; the manifest's role is tested against it.
//   - Typed projections. Each API object is decoded into a struct that
//     declares only what the record needs (objects.go).
//   - Three answers per class: ok, failed, unsupported.
//   - Every pod and Service is attributed to a namespace and a workload, and
//     every part to the cluster.
package kubeinventory

import "time"

// SchemaVersion is the record's schema_version.
const SchemaVersion = 1

// Capability is the managed-protocol capability an agent offers when it can
// run this collection (it runs in a cluster).
const Capability = "kubernetes_inventory_v1"

// JobType is the device-agent job type.
const JobType = "kubernetes_inventory"

// Status is how one class answered.
type Status string

// The three answers.
const (
	StatusOK          Status = "ok"
	StatusFailed      Status = "failed"
	StatusUnsupported Status = "unsupported"
)

// The reasons a class is not ok.
const (
	ReasonNotPermitted  = "not_permitted"
	ReasonNotInstalled  = "not_installed"
	ReasonNotEnabled    = "not_enabled"
	ReasonNotRequested  = "not_requested"
	ReasonNotCollected  = "not_collected_in_this_release"
	ReasonAPIError      = "api_error"
	ReasonTimeout       = "timeout"
	ReasonItemLimit     = "item_limit"
	ReasonUnreachable   = "unreachable"
	maxMessageLen       = 512
	tlsSecretsEnabled   = "enabled"
	tlsSecretsNotEnable = "not_enabled"
)

// The classes, in the order the schema lists them.
const (
	ClassCluster           = "cluster"
	ClassNodes             = "nodes"
	ClassNamespaces        = "namespaces"
	ClassWorkloads         = "workloads"
	ClassPods              = "pods"
	ClassServices          = "services"
	ClassIngresses         = "ingresses"
	ClassGateways          = "gateways"
	ClassCertManager       = "cert_manager"
	ClassCSRs              = "certificate_signing_requests"
	ClassTLSSecrets        = "tls_secrets"
	ClassMeshIstio         = "mesh_istio"
	ClassMeshLinkerd       = "mesh_linkerd"
	ClassMeshCilium        = "mesh_cilium"
	ClassAPIServerCert     = "api_server_certificate"
	ClassKubeletCerts      = "kubelet_certificates"
	ClassControlPlaneFiles = "control_plane_node_certificates"
	ClassAdmissionWebhooks = "admission_webhooks"
	ClassAPIServices       = "api_services"
)

// Classes is every class, in schema order.
var Classes = []string{
	ClassCluster, ClassNodes, ClassNamespaces, ClassWorkloads, ClassPods, ClassServices, ClassIngresses,
	ClassGateways, ClassCertManager, ClassCSRs, ClassTLSSecrets, ClassMeshIstio, ClassMeshLinkerd,
	ClassMeshCilium, ClassAPIServerCert, ClassKubeletCerts, ClassControlPlaneFiles, ClassAdmissionWebhooks,
	ClassAPIServices,
}

// Section is one class's answer.
type Section struct {
	Status  Status `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	Count   *int   `json:"count,omitempty"`
}

// Part places one document in its collection.
type Part struct {
	Index int `json:"index"`
	Count int `json:"count"`
}

// Inventory is one part of one collection.
type Inventory struct {
	SchemaVersion int        `json:"schema_version"`
	CollectionID  string     `json:"collection_id"`
	Part          Part       `json:"part"`
	CollectedAt   time.Time  `json:"collected_at"`
	DurationMS    int64      `json:"duration_ms,omitempty"`
	Collector     *Collector `json:"collector,omitempty"`
	Cluster       Cluster    `json:"cluster"`

	Sections  map[string]Section `json:"sections,omitempty"`
	Mesh      *Mesh              `json:"mesh,omitempty"`
	APIServer *Handshake         `json:"api_server,omitempty"`

	Nodes                        []Node                       `json:"nodes,omitempty"`
	Namespaces                   []Namespace                  `json:"namespaces,omitempty"`
	Workloads                    []Workload                   `json:"workloads,omitempty"`
	Pods                         []Pod                        `json:"pods,omitempty"`
	Services                     []Service                    `json:"services,omitempty"`
	Ingresses                    []Ingress                    `json:"ingresses,omitempty"`
	Gateways                     []Gateway                    `json:"gateways,omitempty"`
	Routes                       []Route                      `json:"routes,omitempty"`
	CertManagerCertificates      []CertManagerCertificate     `json:"cert_manager_certificates,omitempty"`
	CertManagerIssuers           []CertManagerIssuer          `json:"cert_manager_issuers,omitempty"`
	CertManagerRequests          []CertManagerRequest         `json:"cert_manager_requests,omitempty"`
	CertificateSigningRequests   []CertificateSigningRequest  `json:"certificate_signing_requests,omitempty"`
	TLSSecrets                   []TLSSecret                  `json:"tls_secrets,omitempty"`
	IstioPeerAuthentications     []IstioPeerAuthentication    `json:"istio_peer_authentications,omitempty"`
	IstioDestinationRules        []IstioDestinationRule       `json:"istio_destination_rules,omitempty"`
	LinkerdServers               []LinkerdServer              `json:"linkerd_servers,omitempty"`
	LinkerdAuthorizationPolicies []LinkerdAuthorizationPolicy `json:"linkerd_authorization_policies,omitempty"`
	Kubelets                     []Kubelet                    `json:"kubelets,omitempty"`
	AdmissionWebhooks            []AdmissionWebhook           `json:"admission_webhooks,omitempty"`
	APIServices                  []APIService                 `json:"api_services,omitempty"`
	Certificates                 []Certificate                `json:"certificates,omitempty"`
}

// Collector says how this deployment was set up.
type Collector struct {
	TLSSecrets     string `json:"tls_secrets"`
	AgentNamespace string `json:"agent_namespace,omitempty"`
}

// Cluster identifies the cluster. Only ID travels in parts after the first.
type Cluster struct {
	ID                string        `json:"id"`
	KubernetesVersion string        `json:"kubernetes_version,omitempty"`
	VersionMajor      string        `json:"version_major,omitempty"`
	VersionMinor      string        `json:"version_minor,omitempty"`
	Platform          string        `json:"platform,omitempty"`
	Distribution      string        `json:"distribution,omitempty"`
	NodeCount         *int          `json:"node_count,omitempty"`
	CACertificates    []string      `json:"ca_certificates,omitempty"`
	APIEndpoints      []APIEndpoint `json:"api_endpoints,omitempty"`
	PodCIDRs          []string      `json:"pod_cidrs,omitempty"`
	ServiceCIDRs      []string      `json:"service_cidrs,omitempty"`
}

// APIEndpoint is one address the API server itself listens on.
type APIEndpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// WorkloadRef names a workload in the namespace of the row that carries it.
type WorkloadRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// ObjectRef names another object.
type ObjectRef struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Condition is a Ready-style condition.
type Condition struct {
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Certificate is one distinct certificate, in the field names of the one
// certificate format (defs/certificate.json).
type Certificate struct {
	SubjectDN               string     `json:"subject_dn"`
	IssuerDN                string     `json:"issuer_dn"`
	SerialNumber            string     `json:"serial_number,omitempty"`
	NotBefore               *time.Time `json:"not_before,omitempty"`
	NotAfter                *time.Time `json:"not_after,omitempty"`
	KeyAlgorithm            string     `json:"key_algorithm,omitempty"`
	KeySize                 int        `json:"key_size,omitempty"`
	SignatureAlg            string     `json:"signature_alg,omitempty"`
	IsCA                    bool       `json:"is_ca"`
	CertificatePEM          string     `json:"certificate_pem,omitempty"`
	FingerprintSHA256       string     `json:"fingerprint_sha256"`
	FingerprintSHA1         string     `json:"fingerprint_sha1,omitempty"`
	SubjectAlternativeNames []string   `json:"subject_alternative_names,omitempty"`
	KeyUsage                []string   `json:"key_usage,omitempty"`
	ExtendedKeyUsage        []string   `json:"extended_key_usage,omitempty"`
}

// CSR is what a certificate signing request asks for.
type CSR struct {
	SubjectDN    string   `json:"subject_dn,omitempty"`
	DNSNames     []string `json:"dns_names,omitempty"`
	KeyAlgorithm string   `json:"key_algorithm,omitempty"`
	KeySize      int      `json:"key_size,omitempty"`
	SignatureAlg string   `json:"signature_alg,omitempty"`
}

// Handshake is one TLS handshake the agent made itself.
type Handshake struct {
	Address           string   `json:"address"`
	Port              int      `json:"port"`
	ServerName        string   `json:"server_name,omitempty"`
	Status            string   `json:"status"`
	TLSVersion        string   `json:"tls_version,omitempty"`
	CipherSuite       string   `json:"cipher_suite,omitempty"`
	KeyExchangeGroup  string   `json:"key_exchange_group,omitempty"`
	CertificateChain  []string `json:"certificate_chain,omitempty"`
	ChainsToClusterCA *bool    `json:"chains_to_cluster_ca,omitempty"`
}

// Kubelet is the handshake with one node's kubelet.
type Kubelet struct {
	Node string `json:"node"`
	Handshake
}

// NodeAddress is one address of a node.
type NodeAddress struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

// Node is a node of the cluster.
type Node struct {
	Name                    string            `json:"name"`
	UID                     string            `json:"uid"`
	Addresses               []NodeAddress     `json:"addresses,omitempty"`
	Roles                   []string          `json:"roles,omitempty"`
	Ready                   *bool             `json:"ready,omitempty"`
	Unschedulable           bool              `json:"unschedulable,omitempty"`
	KubeletVersion          string            `json:"kubelet_version,omitempty"`
	ContainerRuntimeVersion string            `json:"container_runtime_version,omitempty"`
	OSImage                 string            `json:"os_image,omitempty"`
	KernelVersion           string            `json:"kernel_version,omitempty"`
	OperatingSystem         string            `json:"operating_system,omitempty"`
	Architecture            string            `json:"architecture,omitempty"`
	ProviderID              string            `json:"provider_id,omitempty"`
	MachineID               string            `json:"machine_id,omitempty"`
	SystemUUID              string            `json:"system_uuid,omitempty"`
	PodCIDRs                []string          `json:"pod_cidrs,omitempty"`
	KubeletPort             int               `json:"kubelet_port,omitempty"`
	Labels                  map[string]string `json:"labels,omitempty"`
	CreatedAt               *time.Time        `json:"created_at,omitempty"`
}

// Namespace is a namespace of the cluster.
type Namespace struct {
	Name                        string            `json:"name"`
	UID                         string            `json:"uid"`
	Phase                       string            `json:"phase,omitempty"`
	Labels                      map[string]string `json:"labels,omitempty"`
	CreatedAt                   *time.Time        `json:"created_at,omitempty"`
	IstioInjection              string            `json:"istio_injection,omitempty"`
	IstioRevision               string            `json:"istio_revision,omitempty"`
	IstioMTLSMode               string            `json:"istio_mtls_mode,omitempty"`
	LinkerdInjection            string            `json:"linkerd_injection,omitempty"`
	LinkerdDefaultInboundPolicy string            `json:"linkerd_default_inbound_policy,omitempty"`
	TLSSecretsReadable          *bool             `json:"tls_secrets_readable,omitempty"`
}

// ContainerPort is a port a container declares.
type ContainerPort struct {
	Name     string `json:"name,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	HostPort int    `json:"host_port,omitempty"`
}

// Container is a container of a pod template: its image and declared ports.
type Container struct {
	Name  string          `json:"name"`
	Image string          `json:"image"`
	Init  bool            `json:"init,omitempty"`
	Ports []ContainerPort `json:"ports,omitempty"`
}

// Workload is a controller and what its pod template declares.
type Workload struct {
	Namespace       string            `json:"namespace"`
	Kind            string            `json:"kind"`
	APIGroup        string            `json:"api_group,omitempty"`
	Name            string            `json:"name"`
	UID             string            `json:"uid,omitempty"`
	ReplicasDesired *int              `json:"replicas_desired,omitempty"`
	ReplicasReady   *int              `json:"replicas_ready,omitempty"`
	Schedule        string            `json:"schedule,omitempty"`
	Containers      []Container       `json:"containers,omitempty"`
	HostNetwork     bool              `json:"host_network,omitempty"`
	ServiceAccount  string            `json:"service_account,omitempty"`
	SecretVolumes   []string          `json:"secret_volumes,omitempty"`
	MeshProxy       string            `json:"mesh_proxy,omitempty"`
	MTLSMode        string            `json:"mtls_mode,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	CreatedAt       *time.Time        `json:"created_at,omitempty"`
}

// Pod is a pod that has an address: evidence for its workload.
type Pod struct {
	Namespace   string      `json:"namespace"`
	Name        string      `json:"name"`
	UID         string      `json:"uid,omitempty"`
	Workload    WorkloadRef `json:"workload"`
	Node        string      `json:"node,omitempty"`
	Addresses   []string    `json:"addresses"`
	HostNetwork bool        `json:"host_network,omitempty"`
	Phase       string      `json:"phase,omitempty"`
	Ready       *bool       `json:"ready,omitempty"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
}

// ServicePort is one port of a Service.
type ServicePort struct {
	Name                string `json:"name,omitempty"`
	Port                int    `json:"port"`
	Protocol            string `json:"protocol"`
	AppProtocol         string `json:"app_protocol,omitempty"`
	TargetPort          string `json:"target_port,omitempty"`
	ResolvedTargetPorts []int  `json:"resolved_target_ports,omitempty"`
	NodePort            int    `json:"node_port,omitempty"`
}

// What backs a Service.
const (
	BackingWorkloads       = "workloads"
	BackingManualEndpoints = "manual_endpoints"
	BackingExternalName    = "external_name"
	BackingNone            = "none"
)

// Service is a Service and what backs it.
type Service struct {
	Namespace             string            `json:"namespace"`
	Name                  string            `json:"name"`
	UID                   string            `json:"uid,omitempty"`
	Type                  string            `json:"type"`
	Headless              bool              `json:"headless,omitempty"`
	ClusterIPs            []string          `json:"cluster_ips,omitempty"`
	ExternalIPs           []string          `json:"external_ips,omitempty"`
	LoadBalancerAddresses []string          `json:"load_balancer_addresses,omitempty"`
	ExternalName          string            `json:"external_name,omitempty"`
	Backing               string            `json:"backing"`
	Workloads             []WorkloadRef     `json:"workloads"`
	EndpointsReady        *int              `json:"endpoints_ready,omitempty"`
	EndpointsNotReady     *int              `json:"endpoints_not_ready,omitempty"`
	Ports                 []ServicePort     `json:"ports"`
	Labels                map[string]string `json:"labels,omitempty"`
	CreatedAt             *time.Time        `json:"created_at,omitempty"`
}

// IngressTLS is one tls entry of an Ingress.
type IngressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secret_name,omitempty"`
}

// IngressPath routes one path to a Service.
type IngressPath struct {
	Path        string `json:"path,omitempty"`
	PathType    string `json:"path_type,omitempty"`
	Service     string `json:"service"`
	ServicePort string `json:"service_port,omitempty"`
}

// IngressRule is one host of an Ingress.
type IngressRule struct {
	Host       string        `json:"host,omitempty"`
	TLS        bool          `json:"tls"`
	SecretName string        `json:"secret_name,omitempty"`
	Paths      []IngressPath `json:"paths,omitempty"`
}

// IngressBackend is an Ingress's default backend.
type IngressBackend struct {
	Service     string `json:"service"`
	ServicePort string `json:"service_port,omitempty"`
}

// Ingress is an Ingress and the TLS it declares.
type Ingress struct {
	Namespace             string          `json:"namespace"`
	Name                  string          `json:"name"`
	UID                   string          `json:"uid,omitempty"`
	ClassName             string          `json:"class_name,omitempty"`
	Controller            string          `json:"controller,omitempty"`
	LoadBalancerAddresses []string        `json:"load_balancer_addresses,omitempty"`
	TLS                   []IngressTLS    `json:"tls,omitempty"`
	Rules                 []IngressRule   `json:"rules,omitempty"`
	DefaultBackend        *IngressBackend `json:"default_backend,omitempty"`
	CreatedAt             *time.Time      `json:"created_at,omitempty"`
}

// GatewayListener is one listener of a Gateway.
type GatewayListener struct {
	Name            string      `json:"name"`
	Hostname        string      `json:"hostname,omitempty"`
	Port            int         `json:"port"`
	Protocol        string      `json:"protocol"`
	TLSMode         string      `json:"tls_mode,omitempty"`
	CertificateRefs []ObjectRef `json:"certificate_refs,omitempty"`
	AttachedRoutes  *int        `json:"attached_routes,omitempty"`
}

// Gateway is a Gateway API Gateway.
type Gateway struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	UID        string            `json:"uid,omitempty"`
	ClassName  string            `json:"class_name,omitempty"`
	Controller string            `json:"controller,omitempty"`
	Addresses  []string          `json:"addresses,omitempty"`
	Listeners  []GatewayListener `json:"listeners,omitempty"`
	CreatedAt  *time.Time        `json:"created_at,omitempty"`
}

// RouteParent is a Gateway a route attaches to.
type RouteParent struct {
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	SectionName string `json:"section_name,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// RouteBackend is where a route sends traffic.
type RouteBackend struct {
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Port      int    `json:"port,omitempty"`
}

// Route is a Gateway API route.
type Route struct {
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
	UID       string         `json:"uid,omitempty"`
	Hostnames []string       `json:"hostnames,omitempty"`
	Parents   []RouteParent  `json:"parents,omitempty"`
	Backends  []RouteBackend `json:"backends,omitempty"`
	CreatedAt *time.Time     `json:"created_at,omitempty"`
}

// IssuerRef names the issuer of a cert-manager object.
type IssuerRef struct {
	Group string `json:"group,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Name  string `json:"name"`
}

// KeyRequest is what a Certificate asks cert-manager to generate. Settings
// only: there is no key here.
type KeyRequest struct {
	Algorithm      string `json:"algorithm,omitempty"`
	Size           int    `json:"size,omitempty"`
	Encoding       string `json:"encoding,omitempty"`
	RotationPolicy string `json:"rotation_policy,omitempty"`
}

// CertManagerCertificate is a cert-manager Certificate.
type CertManagerCertificate struct {
	Namespace   string      `json:"namespace"`
	Name        string      `json:"name"`
	UID         string      `json:"uid,omitempty"`
	SecretName  string      `json:"secret_name,omitempty"`
	IssuerRef   *IssuerRef  `json:"issuer_ref,omitempty"`
	CommonName  string      `json:"common_name,omitempty"`
	DNSNames    []string    `json:"dns_names,omitempty"`
	IPAddresses []string    `json:"ip_addresses,omitempty"`
	URIs        []string    `json:"uris,omitempty"`
	IsCA        bool        `json:"is_ca,omitempty"`
	Usages      []string    `json:"usages,omitempty"`
	Duration    string      `json:"duration,omitempty"`
	RenewBefore string      `json:"renew_before,omitempty"`
	KeyRequest  *KeyRequest `json:"key_request,omitempty"`
	Ready       *Condition  `json:"ready,omitempty"`
	NotBefore   *time.Time  `json:"not_before,omitempty"`
	NotAfter    *time.Time  `json:"not_after,omitempty"`
	RenewalTime *time.Time  `json:"renewal_time,omitempty"`
	Revision    int         `json:"revision,omitempty"`
	CreatedAt   *time.Time  `json:"created_at,omitempty"`
}

// CertManagerIssuer is an Issuer or ClusterIssuer.
type CertManagerIssuer struct {
	Scope        string     `json:"scope"`
	Namespace    string     `json:"namespace,omitempty"`
	Name         string     `json:"name"`
	UID          string     `json:"uid,omitempty"`
	Type         string     `json:"type"`
	ACMEServer   string     `json:"acme_server,omitempty"`
	ACMESolvers  []string   `json:"acme_solvers,omitempty"`
	CASecretName string     `json:"ca_secret_name,omitempty"`
	VaultServer  string     `json:"vault_server,omitempty"`
	VaultPath    string     `json:"vault_path,omitempty"`
	VenafiZone   string     `json:"venafi_zone,omitempty"`
	Ready        *Condition `json:"ready,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
}

// CertManagerRequest is a cert-manager CertificateRequest.
type CertManagerRequest struct {
	Namespace        string     `json:"namespace"`
	Name             string     `json:"name"`
	UID              string     `json:"uid,omitempty"`
	CertificateName  string     `json:"certificate_name,omitempty"`
	IssuerRef        *IssuerRef `json:"issuer_ref,omitempty"`
	IsCA             bool       `json:"is_ca,omitempty"`
	Usages           []string   `json:"usages,omitempty"`
	Duration         string     `json:"duration,omitempty"`
	Approval         string     `json:"approval,omitempty"`
	Ready            *Condition `json:"ready,omitempty"`
	CSR              *CSR       `json:"csr,omitempty"`
	CertificateChain []string   `json:"certificate_chain,omitempty"`
	CACertificates   []string   `json:"ca_certificates,omitempty"`
	CreatedAt        *time.Time `json:"created_at,omitempty"`
}

// CertificateSigningRequest is a certificates.k8s.io signing request.
type CertificateSigningRequest struct {
	Name              string     `json:"name"`
	UID               string     `json:"uid,omitempty"`
	SignerName        string     `json:"signer_name,omitempty"`
	Requestor         string     `json:"requestor,omitempty"`
	Usages            []string   `json:"usages,omitempty"`
	ExpirationSeconds int        `json:"expiration_seconds,omitempty"`
	Approval          string     `json:"approval,omitempty"`
	CSR               *CSR       `json:"csr,omitempty"`
	CertificateChain  []string   `json:"certificate_chain,omitempty"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
}

// TLSSecret is the certificates of one TLS Secret. It has no member for any
// other entry of the Secret.
type TLSSecret struct {
	Namespace              string     `json:"namespace"`
	Name                   string     `json:"name"`
	UID                    string     `json:"uid,omitempty"`
	CreatedAt              *time.Time `json:"created_at,omitempty"`
	CertManagerCertificate string     `json:"cert_manager_certificate,omitempty"`
	Owner                  *ObjectRef `json:"owner,omitempty"`
	CertificateChain       []string   `json:"certificate_chain,omitempty"`
	CACertificates         []string   `json:"ca_certificates,omitempty"`
	UnparsedEntries        []string   `json:"unparsed_entries,omitempty"`
}

// PortMode is a per-port mesh mode.
type PortMode struct {
	Port int    `json:"port"`
	Mode string `json:"mode"`
}

// IstioPeerAuthentication is an Istio PeerAuthentication as written.
type IstioPeerAuthentication struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	UID       string            `json:"uid,omitempty"`
	Scope     string            `json:"scope"`
	Selector  map[string]string `json:"selector,omitempty"`
	Mode      string            `json:"mode"`
	PortModes []PortMode        `json:"port_modes,omitempty"`
}

// IstioDestinationRule is the TLS settings of an Istio DestinationRule.
type IstioDestinationRule struct {
	Namespace    string     `json:"namespace"`
	Name         string     `json:"name"`
	UID          string     `json:"uid,omitempty"`
	Host         string     `json:"host,omitempty"`
	TLSMode      string     `json:"tls_mode,omitempty"`
	PortTLSModes []PortMode `json:"port_tls_modes,omitempty"`
}

// LinkerdServer is a policy.linkerd.io Server.
type LinkerdServer struct {
	Namespace     string            `json:"namespace"`
	Name          string            `json:"name"`
	UID           string            `json:"uid,omitempty"`
	Port          string            `json:"port,omitempty"`
	ProxyProtocol string            `json:"proxy_protocol,omitempty"`
	PodSelector   map[string]string `json:"pod_selector,omitempty"`
}

// LinkerdAuthorizationPolicy is a policy.linkerd.io AuthorizationPolicy.
type LinkerdAuthorizationPolicy struct {
	Namespace               string      `json:"namespace"`
	Name                    string      `json:"name"`
	UID                     string      `json:"uid,omitempty"`
	Target                  *ObjectRef  `json:"target,omitempty"`
	RequiredAuthentications []ObjectRef `json:"required_authentications,omitempty"`
}

// ServiceTarget is the Service a webhook or aggregated API calls.
type ServiceTarget struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Port      int    `json:"port,omitempty"`
}

// AdmissionWebhook is one webhook of a webhook configuration.
type AdmissionWebhook struct {
	Kind             string         `json:"kind"`
	Configuration    string         `json:"configuration"`
	ConfigurationUID string         `json:"configuration_uid,omitempty"`
	Name             string         `json:"name"`
	Service          *ServiceTarget `json:"service,omitempty"`
	URLHost          string         `json:"url_host,omitempty"`
	FailurePolicy    string         `json:"failure_policy,omitempty"`
	CABundle         []string       `json:"ca_bundle"`
}

// APIService is an aggregated API.
type APIService struct {
	Name                  string         `json:"name"`
	UID                   string         `json:"uid,omitempty"`
	Group                 string         `json:"group,omitempty"`
	Version               string         `json:"version,omitempty"`
	Service               *ServiceTarget `json:"service,omitempty"`
	InsecureSkipTLSVerify bool           `json:"insecure_skip_tls_verify"`
	Available             *bool          `json:"available,omitempty"`
	CABundle              []string       `json:"ca_bundle"`
}

// MeshIstio is the mesh-wide view of Istio.
type MeshIstio struct {
	Present       bool     `json:"present"`
	RootNamespace string   `json:"root_namespace,omitempty"`
	MeshMTLSMode  string   `json:"mesh_mtls_mode,omitempty"`
	TrustAnchors  []string `json:"trust_anchors,omitempty"`
}

// MeshLinkerd is the mesh-wide view of Linkerd.
type MeshLinkerd struct {
	Present      bool     `json:"present"`
	Namespace    string   `json:"namespace,omitempty"`
	TrustAnchors []string `json:"trust_anchors,omitempty"`
}

// MeshCilium is Cilium's transparent encryption.
type MeshCilium struct {
	Present        bool   `json:"present"`
	Encryption     string `json:"encryption,omitempty"`
	NodeEncryption *bool  `json:"node_encryption,omitempty"`
}

// Mesh is the mesh-wide view of each mesh the agent knows.
type Mesh struct {
	Istio   *MeshIstio   `json:"istio,omitempty"`
	Linkerd *MeshLinkerd `json:"linkerd,omitempty"`
	Cilium  *MeshCilium  `json:"cilium,omitempty"`
}
