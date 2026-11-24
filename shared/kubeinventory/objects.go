package kubeinventory

// Typed projections of the API objects the collector reads.
//
// Each struct declares only the fields the record needs. encoding/json skips
// every member of an object that the destination struct does not declare
// without building a value for it, so the rest of an object (a container's
// environment, commands and arguments, an object's annotations, a ConfigMap's
// other keys, a Secret's other entries) is never held by this program.
//
// Annotations are never decoded as a map: an object that needs one declares a
// struct naming exactly the annotations it reads. Labels are decoded as a map
// because selectors are matched against them; what is sent is filtered through
// the label allowlist (labels.go).

import (
	"encoding/json"
	"strconv"
	"time"
)

type ownerRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

type meta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	CreationTimestamp *time.Time        `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []ownerRef        `json:"ownerReferences"`
}

// controller is the owner reference marked as the controller, or nil.
func (m meta) controller() *ownerRef {
	for i := range m.OwnerReferences {
		if c := m.OwnerReferences[i].Controller; c != nil && *c {
			return &m.OwnerReferences[i]
		}
	}
	return nil
}

type object struct {
	Metadata meta `json:"metadata"`
}

// intOrString is a Kubernetes IntOrString, kept as text.
type intOrString string

func (v *intOrString) UnmarshalJSON(data []byte) error {
	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		*v = intOrString(strconv.FormatInt(n, 10))
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*v = intOrString(s)
	return nil
}

type condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func findCondition(conds []condition, kind string) *condition {
	for i := range conds {
		if conds[i].Type == kind {
			return &conds[i]
		}
	}
	return nil
}

// ---- /version ----

type versionObject struct {
	Major      string `json:"major"`
	Minor      string `json:"minor"`
	GitVersion string `json:"gitVersion"`
	Platform   string `json:"platform"`
}

// ---- core ----

type namespaceObject struct {
	Metadata struct {
		meta
		Annotations struct {
			LinkerdInject        string `json:"linkerd.io/inject"`
			LinkerdInboundPolicy string `json:"config.linkerd.io/default-inbound-policy"`
		} `json:"annotations"`
	} `json:"metadata"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type nodeObject struct {
	Metadata struct {
		meta
		Annotations struct {
			KubeadmCRISocket string `json:"kubeadm.alpha.kubernetes.io/cri-socket"`
		} `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		PodCIDR       string   `json:"podCIDR"`
		PodCIDRs      []string `json:"podCIDRs"`
		ProviderID    string   `json:"providerID"`
		Unschedulable bool     `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		Addresses []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"addresses"`
		Conditions      []condition `json:"conditions"`
		DaemonEndpoints struct {
			KubeletEndpoint struct {
				Port int `json:"Port"`
			} `json:"kubeletEndpoint"`
		} `json:"daemonEndpoints"`
		NodeInfo struct {
			MachineID               string `json:"machineID"`
			SystemUUID              string `json:"systemUUID"`
			KernelVersion           string `json:"kernelVersion"`
			OSImage                 string `json:"osImage"`
			ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
			KubeletVersion          string `json:"kubeletVersion"`
			OperatingSystem         string `json:"operatingSystem"`
			Architecture            string `json:"architecture"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

// containerSpec is a container's name, image and declared ports. Nothing else
// of a container is declared here, so nothing else is decoded.
type containerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ports []struct {
		Name          string `json:"name"`
		ContainerPort int    `json:"containerPort"`
		HostPort      int    `json:"hostPort"`
		Protocol      string `json:"protocol"`
	} `json:"ports"`
}

// podSpec is the part of a pod spec the record reads.
type podSpec struct {
	NodeName           string          `json:"nodeName"`
	HostNetwork        bool            `json:"hostNetwork"`
	ServiceAccountName string          `json:"serviceAccountName"`
	Containers         []containerSpec `json:"containers"`
	InitContainers     []containerSpec `json:"initContainers"`
	Volumes            []struct {
		Secret *struct {
			SecretName string `json:"secretName"`
		} `json:"secret"`
		Projected *struct {
			Sources []struct {
				Secret *struct {
					Name string `json:"name"`
				} `json:"secret"`
			} `json:"sources"`
		} `json:"projected"`
	} `json:"volumes"`
}

type podObject struct {
	Metadata meta    `json:"metadata"`
	Spec     podSpec `json:"spec"`
	Status   struct {
		Phase  string `json:"phase"`
		PodIP  string `json:"podIP"`
		PodIPs []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
		StartTime  *time.Time  `json:"startTime"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type podTemplate struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec podSpec `json:"spec"`
}

// workloadObject serves Deployments, StatefulSets, DaemonSets and CronJobs.
type workloadObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Replicas    *int        `json:"replicas"`
		Schedule    string      `json:"schedule"`
		Template    podTemplate `json:"template"`
		JobTemplate struct {
			Spec struct {
				Template podTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas          *int `json:"readyReplicas"`
		DesiredNumberScheduled *int `json:"desiredNumberScheduled"`
		NumberReady            *int `json:"numberReady"`
	} `json:"status"`
}

type serviceObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Type         string            `json:"type"`
		ClusterIP    string            `json:"clusterIP"`
		ClusterIPs   []string          `json:"clusterIPs"`
		ExternalIPs  []string          `json:"externalIPs"`
		ExternalName string            `json:"externalName"`
		Selector     map[string]string `json:"selector"`
		Ports        []struct {
			Name        string      `json:"name"`
			Port        int         `json:"port"`
			Protocol    string      `json:"protocol"`
			AppProtocol string      `json:"appProtocol"`
			TargetPort  intOrString `json:"targetPort"`
			NodePort    int         `json:"nodePort"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer loadBalancerStatus `json:"loadBalancer"`
	} `json:"status"`
}

type loadBalancerStatus struct {
	Ingress []struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	} `json:"ingress"`
}

func (s loadBalancerStatus) addresses() []string {
	var out []string
	for _, i := range s.Ingress {
		if i.IP != "" {
			out = append(out, i.IP)
		}
		if i.Hostname != "" {
			out = append(out, i.Hostname)
		}
	}
	return out
}

type endpointSliceObject struct {
	Metadata  meta `json:"metadata"`
	Endpoints []struct {
		Addresses  []string `json:"addresses"`
		Conditions struct {
			Ready *bool `json:"ready"`
		} `json:"conditions"`
		TargetRef *struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"targetRef"`
	} `json:"endpoints"`
	Ports []struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	} `json:"ports"`
}

// A ConfigMap is read only by name, and only into a struct naming the keys
// wanted from it.
type istioRootConfigMap struct {
	Data struct {
		RootCert string `json:"root-cert.pem"`
	} `json:"data"`
}

type linkerdTrustConfigMap struct {
	Data struct {
		Bundle string `json:"ca-bundle.crt"`
	} `json:"data"`
}

type ciliumConfigMap struct {
	Data struct {
		EnableWireguard string `json:"enable-wireguard"`
		EnableIPsec     string `json:"enable-ipsec"`
		EncryptNode     string `json:"encrypt-node"`
	} `json:"data"`
}

// tlsSecretObject is a Secret of type kubernetes.io/tls as this program sees
// it: its metadata and the two certificate entries.
//
// The Secret's "tls.key" entry is on the wire, because Kubernetes cannot be
// asked to leave it out. It is not declared here, so the JSON decoder steps
// over its bytes and no Go value ever holds them: nothing can parse, hash, log
// or send what was never decoded. Do not add a field to Data, and do not
// replace Data with a map.
type tlsSecretObject struct {
	Metadata struct {
		meta
		Annotations struct {
			CertificateName string `json:"cert-manager.io/certificate-name"`
		} `json:"annotations"`
	} `json:"metadata"`
	Type string `json:"type"`
	Data struct {
		TLSCrt []byte `json:"tls.crt"`
		CACrt  []byte `json:"ca.crt"`
	} `json:"data"`
}

// ---- networking ----

type ingressBackend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Name   string `json:"name"`
			Number int    `json:"number"`
		} `json:"port"`
	} `json:"service"`
}

func (b ingressBackend) target() (service, port string) {
	if b.Service == nil {
		return "", ""
	}
	port = b.Service.Port.Name
	if port == "" && b.Service.Port.Number != 0 {
		port = strconv.Itoa(b.Service.Port.Number)
	}
	return b.Service.Name, port
}

type ingressObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		IngressClassName string          `json:"ingressClassName"`
		DefaultBackend   *ingressBackend `json:"defaultBackend"`
		TLS              []struct {
			Hosts      []string `json:"hosts"`
			SecretName string   `json:"secretName"`
		} `json:"tls"`
		Rules []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Path     string         `json:"path"`
					PathType string         `json:"pathType"`
					Backend  ingressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
	Status struct {
		LoadBalancer loadBalancerStatus `json:"loadBalancer"`
	} `json:"status"`
}

type ingressClassObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Controller string `json:"controller"`
	} `json:"spec"`
}

type serviceCIDRObject struct {
	Spec struct {
		CIDRs []string `json:"cidrs"`
	} `json:"spec"`
}

type gatewayClassObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		ControllerName string `json:"controllerName"`
	} `json:"spec"`
}

type gatewayObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		GatewayClassName string `json:"gatewayClassName"`
		Listeners        []struct {
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			TLS      *struct {
				Mode            string `json:"mode"`
				CertificateRefs []struct {
					Group     *string `json:"group"`
					Kind      string  `json:"kind"`
					Namespace string  `json:"namespace"`
					Name      string  `json:"name"`
				} `json:"certificateRefs"`
			} `json:"tls"`
		} `json:"listeners"`
	} `json:"spec"`
	Status struct {
		Addresses []struct {
			Value string `json:"value"`
		} `json:"addresses"`
		Listeners []struct {
			Name           string `json:"name"`
			AttachedRoutes int    `json:"attachedRoutes"`
		} `json:"listeners"`
	} `json:"status"`
}

type routeObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Hostnames  []string `json:"hostnames"`
		ParentRefs []struct {
			Namespace   string `json:"namespace"`
			Name        string `json:"name"`
			SectionName string `json:"sectionName"`
			Port        int    `json:"port"`
		} `json:"parentRefs"`
		Rules []struct {
			BackendRefs []struct {
				Kind      string `json:"kind"`
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
				Port      int    `json:"port"`
			} `json:"backendRefs"`
		} `json:"rules"`
	} `json:"spec"`
}

// ---- cert-manager ----

type issuerRefObject struct {
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

type cmCertificateObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		SecretName  string          `json:"secretName"`
		IssuerRef   issuerRefObject `json:"issuerRef"`
		CommonName  string          `json:"commonName"`
		DNSNames    []string        `json:"dnsNames"`
		IPAddresses []string        `json:"ipAddresses"`
		URIs        []string        `json:"uris"`
		IsCA        bool            `json:"isCA"`
		Usages      []string        `json:"usages"`
		Duration    string          `json:"duration"`
		RenewBefore string          `json:"renewBefore"`
		// PrivateKey is cert-manager's name for the settings of the key it
		// will generate (algorithm, size, rotation). It holds no key.
		PrivateKey *struct {
			Algorithm      string `json:"algorithm"`
			Size           int    `json:"size"`
			Encoding       string `json:"encoding"`
			RotationPolicy string `json:"rotationPolicy"`
		} `json:"privateKey"`
	} `json:"spec"`
	Status struct {
		Conditions  []condition `json:"conditions"`
		NotBefore   *time.Time  `json:"notBefore"`
		NotAfter    *time.Time  `json:"notAfter"`
		RenewalTime *time.Time  `json:"renewalTime"`
		Revision    int         `json:"revision"`
	} `json:"status"`
}

type cmIssuerObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		ACME *struct {
			Server  string `json:"server"`
			Solvers []struct {
				HTTP01 *struct{} `json:"http01"`
				DNS01  *struct{} `json:"dns01"`
			} `json:"solvers"`
		} `json:"acme"`
		CA *struct {
			SecretName string `json:"secretName"`
		} `json:"ca"`
		SelfSigned *struct{} `json:"selfSigned"`
		Vault      *struct {
			Server string `json:"server"`
			Path   string `json:"path"`
		} `json:"vault"`
		Venafi *struct {
			Zone string `json:"zone"`
		} `json:"venafi"`
	} `json:"spec"`
	Status struct {
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type cmRequestObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		IssuerRef issuerRefObject `json:"issuerRef"`
		Request   []byte          `json:"request"`
		IsCA      bool            `json:"isCA"`
		Usages    []string        `json:"usages"`
		Duration  string          `json:"duration"`
	} `json:"spec"`
	Status struct {
		Conditions  []condition `json:"conditions"`
		Certificate []byte      `json:"certificate"`
		CA          []byte      `json:"ca"`
	} `json:"status"`
}

type csrObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Request           []byte   `json:"request"`
		SignerName        string   `json:"signerName"`
		Username          string   `json:"username"`
		Usages            []string `json:"usages"`
		ExpirationSeconds int      `json:"expirationSeconds"`
	} `json:"spec"`
	Status struct {
		Conditions  []condition `json:"conditions"`
		Certificate []byte      `json:"certificate"`
	} `json:"status"`
}

// ---- meshes ----

type mtlsMode struct {
	Mode string `json:"mode"`
}

type peerAuthenticationObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Selector *struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
		MTLS          *mtlsMode           `json:"mtls"`
		PortLevelMTLS map[string]mtlsMode `json:"portLevelMtls"`
	} `json:"spec"`
}

type destinationRuleObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Host          string `json:"host"`
		TrafficPolicy *struct {
			TLS               *mtlsMode `json:"tls"`
			PortLevelSettings []struct {
				Port struct {
					Number int `json:"number"`
				} `json:"port"`
				TLS *mtlsMode `json:"tls"`
			} `json:"portLevelSettings"`
		} `json:"trafficPolicy"`
	} `json:"spec"`
}

type linkerdServerObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Port          intOrString `json:"port"`
		ProxyProtocol string      `json:"proxyProtocol"`
		PodSelector   *struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"podSelector"`
	} `json:"spec"`
}

type linkerdRef struct {
	Group     string `json:"group"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type linkerdAuthorizationPolicyObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		TargetRef                  *linkerdRef  `json:"targetRef"`
		RequiredAuthenticationRefs []linkerdRef `json:"requiredAuthenticationRefs"`
	} `json:"spec"`
}

// ---- admission and aggregation ----

type serviceReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Port      int    `json:"port"`
}

type webhookConfigurationObject struct {
	Metadata meta `json:"metadata"`
	Webhooks []struct {
		Name          string `json:"name"`
		FailurePolicy string `json:"failurePolicy"`
		ClientConfig  struct {
			URL      string            `json:"url"`
			Service  *serviceReference `json:"service"`
			CABundle []byte            `json:"caBundle"`
		} `json:"clientConfig"`
	} `json:"webhooks"`
}

type apiServiceObject struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Group                 string            `json:"group"`
		Version               string            `json:"version"`
		Service               *serviceReference `json:"service"`
		InsecureSkipTLSVerify bool              `json:"insecureSkipTLSVerify"`
		CABundle              []byte            `json:"caBundle"`
	} `json:"spec"`
	Status struct {
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}
