package kubeinventory

import "encoding/json"

// Splitting a collection into parts (docs/design/kubernetes-inventory.md,
// "Parts"). A job result is limited in size and a large cluster does not fit
// one, so the lists are dealt out over as many documents as it takes. Part 0
// carries everything that is not a list; a row is never split.

// DefaultMaxPartBytes is the size a part is kept under unless a job says
// otherwise, and the bounds a job may set.
const (
	DefaultMaxPartBytes = 8 << 20
	MinMaxPartBytes     = 1 << 20
	MaxMaxPartBytes     = 24 << 20
	maxParts            = 4096
)

// listField is one list of the record: how many rows src has, and how to move
// row i of src onto the end of dst's list.
type listField struct {
	rows func(src *Inventory) int
	size func(src *Inventory, i int) int
	move func(dst, src *Inventory, i int)
}

func field[T any](get func(*Inventory) *[]T) listField {
	return listField{
		rows: func(src *Inventory) int { return len(*get(src)) },
		size: func(src *Inventory, i int) int {
			b, _ := json.Marshal((*get(src))[i])
			return len(b) + 1
		},
		move: func(dst, src *Inventory, i int) { *get(dst) = append(*get(dst), (*get(src))[i]) },
	}
}

// listFields is every list of the record. TestSplitCoversEveryList fails when
// a list is added to Inventory and not here.
var listFields = []listField{
	field(func(v *Inventory) *[]Node { return &v.Nodes }),
	field(func(v *Inventory) *[]Namespace { return &v.Namespaces }),
	field(func(v *Inventory) *[]Workload { return &v.Workloads }),
	field(func(v *Inventory) *[]Pod { return &v.Pods }),
	field(func(v *Inventory) *[]Service { return &v.Services }),
	field(func(v *Inventory) *[]Ingress { return &v.Ingresses }),
	field(func(v *Inventory) *[]Gateway { return &v.Gateways }),
	field(func(v *Inventory) *[]Route { return &v.Routes }),
	field(func(v *Inventory) *[]CertManagerCertificate { return &v.CertManagerCertificates }),
	field(func(v *Inventory) *[]CertManagerIssuer { return &v.CertManagerIssuers }),
	field(func(v *Inventory) *[]CertManagerRequest { return &v.CertManagerRequests }),
	field(func(v *Inventory) *[]CertificateSigningRequest { return &v.CertificateSigningRequests }),
	field(func(v *Inventory) *[]TLSSecret { return &v.TLSSecrets }),
	field(func(v *Inventory) *[]IstioPeerAuthentication { return &v.IstioPeerAuthentications }),
	field(func(v *Inventory) *[]IstioDestinationRule { return &v.IstioDestinationRules }),
	field(func(v *Inventory) *[]LinkerdServer { return &v.LinkerdServers }),
	field(func(v *Inventory) *[]LinkerdAuthorizationPolicy { return &v.LinkerdAuthorizationPolicies }),
	field(func(v *Inventory) *[]Kubelet { return &v.Kubelets }),
	field(func(v *Inventory) *[]AdmissionWebhook { return &v.AdmissionWebhooks }),
	field(func(v *Inventory) *[]APIService { return &v.APIServices }),
	field(func(v *Inventory) *[]Certificate { return &v.Certificates }),
	field(func(v *Inventory) *[]TraefikIngressRoute { return &v.TraefikIngressRoutes }),
	field(func(v *Inventory) *[]TraefikTLSOption { return &v.TraefikTLSOptions }),
	field(func(v *Inventory) *[]TraefikTLSStore { return &v.TraefikTLSStores }),
}

// partOverhead is room left in every part for the job-result envelope and the
// list names and brackets around the rows.
const partOverhead = 4096

// Split returns the collection as parts of at most maxBytes each when encoded
// (a single row larger than that still travels, alone). inv is not changed.
func Split(inv *Inventory, maxBytes int) []*Inventory {
	if maxBytes < MinMaxPartBytes || maxBytes > MaxMaxPartBytes {
		maxBytes = DefaultMaxPartBytes
	}
	first := *inv
	clearLists(&first)
	head, _ := json.Marshal(first)

	parts := []*Inventory{&first}
	used, rows := len(head)+partOverhead, 0
	for _, f := range listFields {
		for i := 0; i < f.rows(inv); i++ {
			n := f.size(inv, i)
			if used+n > maxBytes && rows > 0 && len(parts) < maxParts {
				parts = append(parts, &Inventory{
					SchemaVersion: inv.SchemaVersion, CollectionID: inv.CollectionID, CollectedAt: inv.CollectedAt,
					Cluster: Cluster{ID: inv.Cluster.ID},
				})
				used, rows = partOverhead, 0
			}
			f.move(parts[len(parts)-1], inv, i)
			used += n
			rows++
		}
	}
	for i, p := range parts {
		p.Part = Part{Index: i, Count: len(parts)}
	}
	return parts
}

func clearLists(v *Inventory) {
	v.Nodes, v.Namespaces, v.Workloads, v.Pods, v.Services = nil, nil, nil, nil, nil
	v.Ingresses, v.Gateways, v.Routes = nil, nil, nil
	v.CertManagerCertificates, v.CertManagerIssuers, v.CertManagerRequests = nil, nil, nil
	v.CertificateSigningRequests, v.TLSSecrets = nil, nil
	v.IstioPeerAuthentications, v.IstioDestinationRules = nil, nil
	v.LinkerdServers, v.LinkerdAuthorizationPolicies = nil, nil
	v.Kubelets, v.AdmissionWebhooks, v.APIServices, v.Certificates = nil, nil, nil, nil
	v.TraefikIngressRoutes, v.TraefikTLSOptions, v.TraefikTLSStores = nil, nil, nil
}
