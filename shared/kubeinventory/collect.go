package kubeinventory

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Defaults of the job parameters.
const (
	DefaultMaxItemsPerClass = 100000
	DefaultTimeout          = 10 * time.Minute
	kubeSystem              = "kube-system"
)

// Options are one collection's settings.
type Options struct {
	// Classes limits the collection to these classes; empty means all. The
	// cluster class is always collected.
	Classes []string
	// SkipKubeletProbe turns off the handshake with each node's kubelet.
	SkipKubeletProbe bool
	// OmitCertificatePEM leaves certificate_pem out of certificate entries.
	OmitCertificatePEM bool
	// ExtraLabelKeys are label keys reported beyond the built-in allowlist.
	ExtraLabelKeys []string
	// MaxItemsPerClass bounds one list; zero means DefaultMaxItemsPerClass.
	MaxItemsPerClass int
	// ReadTLSSecrets enables listing Secrets of type kubernetes.io/tls. It is
	// set from the agent's own configuration in the cluster and from nowhere
	// else: ParseParameters never sets it.
	ReadTLSSecrets bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// ErrClusterIdentity is returned when the cluster's id cannot be read. A
// collection that cannot say which cluster it describes is not sent.
var ErrClusterIdentity = errors.New("the cluster's identity could not be read")

type collector struct {
	c      *Client
	opts   Options
	inv    *Inventory
	certs  *certTable
	labels labelFilter
	wanted map[string]bool
	max    int

	nodes      []nodeObject
	namespaces []namespaceObject
	istio      *istioPolicies
	// podWorkload maps namespace/pod to the pod's workload.
	podWorkload map[string]WorkloadRef
	workloads   map[workloadKey]*workloadState
}

// Collect reads the cluster once and returns the whole collection as one
// document (part 0 of 1). Split cuts it into parts for sending. It returns an
// error only when the cluster's identity cannot be read; every other failure
// is a class's answer in Sections.
func Collect(ctx context.Context, c *Client, opts Options) (*Inventory, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	k := &collector{
		c: c, opts: opts,
		certs:       newCertTable(!opts.OmitCertificatePEM),
		labels:      newLabelFilter(opts.ExtraLabelKeys),
		wanted:      map[string]bool{},
		max:         opts.MaxItemsPerClass,
		podWorkload: map[string]WorkloadRef{},
		workloads:   map[workloadKey]*workloadState{},
	}
	if k.max <= 0 {
		k.max = DefaultMaxItemsPerClass
	}
	for _, class := range Classes {
		k.wanted[class] = len(opts.Classes) == 0 || contains(opts.Classes, class)
	}
	k.wanted[ClassCluster] = true

	k.inv = &Inventory{
		SchemaVersion: SchemaVersion,
		CollectionID:  uuid.NewString(),
		Part:          Part{Index: 0, Count: 1},
		CollectedAt:   start.UTC().Truncate(time.Second),
		Collector:     &Collector{TLSSecrets: tlsSecretsNotEnable, AgentNamespace: cleanName(c.Namespace())},
		Sections:      map[string]Section{},
		Mesh:          &Mesh{},
	}
	if opts.ReadTLSSecrets {
		k.inv.Collector.TLSSecrets = tlsSecretsEnabled
	}

	if err := k.collectIdentity(ctx); err != nil {
		return nil, err
	}
	k.collectNodes(ctx)
	k.collectCluster(ctx)
	k.collectNamespaces()
	k.collectIstio(ctx)
	k.collectWorkloads(ctx)
	k.collectIngresses(ctx)
	k.collectGateways(ctx)
	k.collectCertManager(ctx)
	k.collectCSRs(ctx)
	k.collectTLSSecrets(ctx)
	k.collectLinkerd(ctx)
	k.collectCilium(ctx)
	k.collectAdmission(ctx)
	k.collectAPIServices(ctx)
	k.collectKubelets(ctx)
	k.collectAPIServer()

	k.inv.Sections[ClassControlPlaneFiles] = Section{
		Status: StatusUnsupported, Reason: ReasonNotCollected,
		Message: "etcd, scheduler and controller-manager certificates are files on control-plane nodes, which this release does not read.",
	}
	k.dropUnrequested()
	k.inv.Certificates = k.certs.all()
	k.inv.DurationMS = now().Sub(start).Milliseconds()
	return k.inv, nil
}

// reads reports whether a class's objects must be read: it was asked for, or
// a class that was asked for is built from it.
func (k *collector) reads(class string) bool {
	if k.wanted[class] {
		return true
	}
	switch class {
	case ClassNodes:
		return true // the cluster's node count, ranges and distribution
	case ClassWorkloads, ClassPods, ClassServices:
		return k.wanted[ClassWorkloads] || k.wanted[ClassPods] || k.wanted[ClassServices]
	case ClassMeshIstio:
		return k.wanted[ClassWorkloads] || k.wanted[ClassNamespaces]
	}
	return false
}

// answer records a class's answer from the errors of the reads it is built
// from. The first error that is not nil decides; count is the rows sent.
func (k *collector) answer(class string, count int, errs ...error) {
	s := Section{Status: StatusOK, Count: intPtr(count)}
	for _, err := range errs {
		if err == nil {
			continue
		}
		s = sectionFor(err)
		if count > 0 {
			s.Count = intPtr(count)
		}
		break
	}
	k.inv.Sections[class] = s
}

func sectionFor(err error) Section {
	s := Section{Status: StatusFailed, Reason: ReasonAPIError, Message: message(err.Error())}
	switch status := statusOf(err); {
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		s.Reason = ReasonNotPermitted
	case status == http.StatusNotFound:
		s.Status, s.Reason = StatusUnsupported, ReasonNotInstalled
		s.Message = "The cluster does not serve this API."
	case errors.Is(err, ErrItemLimit):
		s.Reason = ReasonItemLimit
		s.Message = "The class holds more rows than the collection's limit; the rows read are sent."
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		s.Reason = ReasonTimeout
	}
	return s
}

// notFoundIsNone turns "the cluster does not serve this" into "there are
// none", for a resource whose absence does not make its class unsupported.
func notFoundIsNone(err error) error {
	if statusOf(err) == http.StatusNotFound {
		return nil
	}
	return err
}

func (k *collector) dropUnrequested() {
	notRequested := Section{Status: StatusUnsupported, Reason: ReasonNotRequested}
	inv := k.inv
	for _, class := range Classes {
		if k.wanted[class] {
			continue
		}
		inv.Sections[class] = notRequested
		switch class {
		case ClassNodes:
			inv.Nodes = nil
		case ClassNamespaces:
			inv.Namespaces = nil
		case ClassWorkloads:
			inv.Workloads = nil
		case ClassPods:
			inv.Pods = nil
		case ClassServices:
			inv.Services = nil
		case ClassMeshIstio:
			inv.IstioPeerAuthentications, inv.IstioDestinationRules, inv.Mesh.Istio = nil, nil, nil
		}
	}
}

// ---- cluster identity, nodes, namespaces ----

func (k *collector) collectIdentity(ctx context.Context) error {
	var err error
	k.namespaces, err = list[namespaceObject](ctx, k.c, resNamespaces, "", nil, k.max)
	for _, ns := range k.namespaces {
		if ns.Metadata.Name == kubeSystem {
			k.inv.Cluster.ID = cleanUID(ns.Metadata.UID)
		}
	}
	if k.inv.Cluster.ID == "" {
		if err != nil {
			return fmt.Errorf("%w: %s", ErrClusterIdentity, message(err.Error()))
		}
		return fmt.Errorf("%w: the %s namespace was not in the answer", ErrClusterIdentity, kubeSystem)
	}
	k.answer(ClassNamespaces, len(k.namespaces), err)
	return nil
}

func (k *collector) collectNodes(ctx context.Context) {
	var err error
	k.nodes, err = list[nodeObject](ctx, k.c, resNodes, "", nil, k.max)
	for _, n := range k.nodes {
		row := Node{
			Name: cleanName(n.Metadata.Name), UID: cleanUID(n.Metadata.UID),
			Unschedulable:           n.Spec.Unschedulable,
			KubeletVersion:          clip(n.Status.NodeInfo.KubeletVersion, 64),
			ContainerRuntimeVersion: clip(n.Status.NodeInfo.ContainerRuntimeVersion, 128),
			OSImage:                 clip(n.Status.NodeInfo.OSImage, 256),
			KernelVersion:           clip(n.Status.NodeInfo.KernelVersion, 128),
			OperatingSystem:         clip(n.Status.NodeInfo.OperatingSystem, 32),
			Architecture:            clip(n.Status.NodeInfo.Architecture, 32),
			ProviderID:              clip(n.Spec.ProviderID, 512),
			MachineID:               clip(n.Status.NodeInfo.MachineID, 128),
			SystemUUID:              clip(n.Status.NodeInfo.SystemUUID, 128),
			PodCIDRs:                cleanCIDRs(nodePodCIDRs(n), 8),
			KubeletPort:             cleanPort(n.Status.DaemonEndpoints.KubeletEndpoint.Port),
			Labels:                  k.labels.pick(n.Metadata.Labels),
			CreatedAt:               utc(n.Metadata.CreationTimestamp),
		}
		if row.Name == "" || row.UID == "" {
			continue
		}
		for _, a := range limit(n.Status.Addresses, 32) {
			switch a.Type {
			case "InternalIP", "ExternalIP", "Hostname", "InternalDNS", "ExternalDNS":
				row.Addresses = append(row.Addresses, NodeAddress{Type: a.Type, Address: clip(a.Address, 253)})
			}
		}
		for label := range n.Metadata.Labels {
			if role, ok := strings.CutPrefix(label, "node-role.kubernetes.io/"); ok && role != "" {
				row.Roles = append(row.Roles, clip(role, 63))
			}
		}
		sort.Strings(row.Roles)
		row.Roles = limit(row.Roles, 16)
		if c := findCondition(n.Status.Conditions, "Ready"); c != nil {
			row.Ready = boolPtr(c.Status == "True")
		}
		k.inv.Nodes = append(k.inv.Nodes, row)
	}
	k.answer(ClassNodes, len(k.inv.Nodes), err)
}

func nodePodCIDRs(n nodeObject) []string {
	if len(n.Spec.PodCIDRs) > 0 {
		return n.Spec.PodCIDRs
	}
	if n.Spec.PodCIDR != "" {
		return []string{n.Spec.PodCIDR}
	}
	return nil
}

func (k *collector) collectCluster(ctx context.Context) {
	cl := &k.inv.Cluster
	version, versionErr := k.c.getVersion(ctx)
	if version != nil {
		cl.KubernetesVersion = clip(version.GitVersion, 64)
		cl.VersionMajor = clip(version.Major, 8)
		cl.VersionMinor = clip(version.Minor, 8)
		cl.Platform = clip(version.Platform, 64)
	}
	cl.Distribution = distribution(cl.KubernetesVersion, k.nodes)
	if s := k.inv.Sections[ClassNodes]; s.Status == StatusOK {
		cl.NodeCount = intPtr(len(k.nodes))
	}
	cl.CACertificates = k.certs.add(k.c.caCerts)

	var podCIDRs []string
	for _, n := range k.nodes {
		podCIDRs = append(podCIDRs, cleanCIDRs(nodePodCIDRs(n), 8)...)
	}
	cl.PodCIDRs = limit(sortedUnique(podCIDRs), 4096)

	// Only clusters that serve the ServiceCIDR API say what their Service
	// range is; elsewhere it is left out rather than guessed.
	cidrs, cidrErr := list[serviceCIDRObject](ctx, k.c, resServiceCIDRs, "", nil, 64)
	var serviceCIDRs []string
	for _, c := range cidrs {
		serviceCIDRs = append(serviceCIDRs, cleanCIDRs(c.Spec.CIDRs, 16)...)
	}
	cl.ServiceCIDRs = limit(sortedUnique(serviceCIDRs), 16)
	k.answer(ClassCluster, 1, versionErr, notFoundIsNone(cidrErr))
}

// distribution names the Kubernetes distribution where the version string or
// the nodes say so.
func distribution(gitVersion string, nodes []nodeObject) string {
	v := strings.ToLower(gitVersion)
	switch {
	case strings.Contains(v, "+rke2"):
		return "rke2"
	case strings.Contains(v, "+k3s"):
		return "k3s"
	case strings.Contains(v, "-eks-"):
		return "eks"
	case strings.Contains(v, "-gke."):
		return "gke"
	}
	kubeadm := false
	for _, n := range nodes {
		labels := n.Metadata.Labels
		switch {
		case labels["node.openshift.io/os_id"] != "":
			return "openshift"
		case labels["kubernetes.azure.com/cluster"] != "":
			return "aks"
		case labels["eks.amazonaws.com/nodegroup"] != "" || labels["eks.amazonaws.com/compute-type"] != "":
			return "eks"
		case labels["cloud.google.com/gke-nodepool"] != "":
			return "gke"
		}
		if n.Metadata.Annotations.KubeadmCRISocket != "" {
			kubeadm = true
		}
	}
	if kubeadm {
		return "kubeadm"
	}
	return "unknown"
}

func (k *collector) collectNamespaces() {
	for _, ns := range k.namespaces {
		row := Namespace{
			Name: cleanName(ns.Metadata.Name), UID: cleanUID(ns.Metadata.UID),
			Labels:    k.labels.pick(ns.Metadata.Labels),
			CreatedAt: utc(ns.Metadata.CreationTimestamp),
		}
		if row.Name == "" || row.UID == "" {
			continue
		}
		if p := ns.Status.Phase; p == "Active" || p == "Terminating" {
			row.Phase = p
		}
		row.IstioInjection = injection(ns.Metadata.Labels["istio-injection"])
		if rev := ns.Metadata.Labels["istio.io/rev"]; rev != "" {
			row.IstioRevision = clip(rev, 63)
			row.IstioInjection = "enabled"
		}
		row.LinkerdInjection = injection(ns.Metadata.Annotations.LinkerdInject)
		row.LinkerdDefaultInboundPolicy = clip(ns.Metadata.Annotations.LinkerdInboundPolicy, 64)
		k.inv.Namespaces = append(k.inv.Namespaces, row)
	}
}

func injection(v string) string {
	switch v {
	case "enabled", "ingress":
		return "enabled"
	case "disabled":
		return "disabled"
	}
	return "unset"
}

func (k *collector) namespaceObject(name string) *namespaceObject {
	for i := range k.namespaces {
		if k.namespaces[i].Metadata.Name == name {
			return &k.namespaces[i]
		}
	}
	return nil
}

// ---- workloads, pods, Services ----

type workloadKey struct{ namespace, kind, name string }

type workloadState struct {
	row *Workload
	// podLabels are the labels selectors are matched against: the pod
	// template's, or a pod's own for a workload described from its pods.
	podLabels map[string]string
	proxy     string
}

func podKey(namespace, name string) string { return namespace + "/" + name }

func (k *collector) collectWorkloads(ctx context.Context) {
	if !k.reads(ClassWorkloads) {
		return
	}
	var errs []error
	for _, src := range []struct {
		res   Resource
		kind  string
		group string
	}{
		{resDeployments, "Deployment", "apps"}, {resStatefulSets, "StatefulSet", "apps"},
		{resDaemonSets, "DaemonSet", "apps"}, {resCronJobs, "CronJob", "batch"},
	} {
		objs, err := list[workloadObject](ctx, k.c, src.res, "", nil, k.max)
		errs = append(errs, err)
		for _, o := range objs {
			k.addController(src.kind, src.group, o)
		}
	}
	replicaSets, err := list[object](ctx, k.c, resReplicaSets, "", nil, k.max)
	errs = append(errs, err)
	jobs, err := list[object](ctx, k.c, resJobs, "", nil, k.max)
	errs = append(errs, err)
	owners := map[string]*ownerRef{} // "ReplicaSet/ns/name" -> its controller
	for _, o := range replicaSets {
		owners["ReplicaSet/"+podKey(o.Metadata.Namespace, o.Metadata.Name)] = o.Metadata.controller()
	}
	for _, o := range jobs {
		owners["Job/"+podKey(o.Metadata.Namespace, o.Metadata.Name)] = o.Metadata.controller()
	}

	pods, podErr := list[podObject](ctx, k.c, resPods, "", nil, k.max)
	for _, p := range pods {
		k.addPod(p, owners)
	}

	states := make([]*workloadState, 0, len(k.workloads))
	for _, st := range k.workloads {
		states = append(states, st)
	}
	sort.Slice(states, func(i, j int) bool {
		a, b := states[i].row, states[j].row
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	for _, st := range states {
		st.row.MeshProxy = st.proxy
		st.row.MTLSMode = k.workloadMTLSMode(st)
		k.inv.Workloads = append(k.inv.Workloads, *st.row)
	}
	// A workload row can be wrong when the pods could not be read (the mesh
	// proxy is seen on pods), so the pods' error counts against both.
	k.answer(ClassWorkloads, len(k.inv.Workloads), append(errs, podErr)...)
	k.answer(ClassPods, len(k.inv.Pods), podErr, errs[4], errs[5])

	k.collectServices(ctx, podErr)
}

func (k *collector) addController(kind, group string, o workloadObject) {
	name, ns := cleanName(o.Metadata.Name), cleanName(o.Metadata.Namespace)
	if name == "" || ns == "" {
		return
	}
	template := o.Spec.Template
	row := &Workload{
		Namespace: ns, Kind: kind, APIGroup: group, Name: name, UID: cleanUID(o.Metadata.UID),
		Labels: k.labels.pick(o.Metadata.Labels), CreatedAt: utc(o.Metadata.CreationTimestamp),
	}
	switch kind {
	case "CronJob":
		template = o.Spec.JobTemplate.Spec.Template
		row.Schedule = clip(o.Spec.Schedule, 128)
	case "DaemonSet":
		row.ReplicasDesired, row.ReplicasReady = o.Status.DesiredNumberScheduled, o.Status.NumberReady
	default:
		row.ReplicasDesired, row.ReplicasReady = o.Spec.Replicas, o.Status.ReadyReplicas
		if row.ReplicasDesired == nil {
			row.ReplicasDesired = intPtr(1)
		}
		if row.ReplicasReady == nil {
			row.ReplicasReady = intPtr(0)
		}
	}
	describePodSpec(row, template.Spec)
	k.workloads[workloadKey{ns, kind, name}] = &workloadState{row: row, podLabels: template.Metadata.Labels, proxy: "none"}
}

// describePodSpec copies what the record takes from a pod spec: images,
// declared ports, host networking, the service account and the names of
// mounted Secrets.
func describePodSpec(row *Workload, spec podSpec) {
	add := func(specs []containerSpec, init bool) {
		for _, c := range specs {
			name := cleanName(c.Name)
			if name == "" || c.Image == "" {
				continue
			}
			out := Container{Name: name, Image: clip(c.Image, 1024), Init: init}
			for _, p := range limit(c.Ports, 256) {
				if port := cleanPort(p.ContainerPort); port != 0 {
					out.Ports = append(out.Ports, ContainerPort{
						Name: clip(p.Name, 63), Port: port, Protocol: cleanProtocol(p.Protocol), HostPort: cleanPort(p.HostPort),
					})
				}
			}
			row.Containers = append(row.Containers, out)
		}
	}
	add(spec.Containers, false)
	add(spec.InitContainers, true)
	row.Containers = limit(row.Containers, 128)
	row.HostNetwork = spec.HostNetwork
	row.ServiceAccount = cleanName(spec.ServiceAccountName)
	var secrets []string
	for _, v := range spec.Volumes {
		if v.Secret != nil {
			secrets = append(secrets, cleanName(v.Secret.SecretName))
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil {
					secrets = append(secrets, cleanName(src.Secret.Name))
				}
			}
		}
	}
	row.SecretVolumes = limit(sortedUnique(secrets), 256)
}

// resolveWorkload finds the workload a pod belongs to through its owner
// references. group is the API group of that workload's kind.
func resolveWorkload(p podObject, owners map[string]*ownerRef) (ref WorkloadRef, group string) {
	self := WorkloadRef{Kind: "Pod", Name: p.Metadata.Name}
	owner := p.Metadata.controller()
	if owner == nil {
		return self, ""
	}
	// A ReplicaSet or Job is usually itself owned: by a Deployment, a CronJob,
	// or another project's controller.
	if owner.Kind == "ReplicaSet" || owner.Kind == "Job" {
		if parent := owners[owner.Kind+"/"+podKey(p.Metadata.Namespace, owner.Name)]; parent != nil {
			owner = parent
		}
	}
	kind, name := cleanKind(owner.Kind), cleanName(owner.Name)
	if kind == "" || name == "" {
		return self, ""
	}
	return WorkloadRef{Kind: kind, Name: name}, groupOf(owner.APIVersion)
}

func (k *collector) addPod(p podObject, owners map[string]*ownerRef) {
	ns, name := cleanName(p.Metadata.Namespace), cleanName(p.Metadata.Name)
	if ns == "" || name == "" {
		return
	}
	ref, group := resolveWorkload(p, owners)
	key := workloadKey{ns, ref.Kind, ref.Name}
	st := k.workloads[key]
	if st == nil {
		// No controller the agent lists owns this pod: the workload is
		// described from the pod itself.
		row := &Workload{Namespace: ns, Kind: ref.Kind, APIGroup: group, Name: ref.Name}
		if ref.Kind == "Pod" {
			row.UID = cleanUID(p.Metadata.UID)
			row.Labels = k.labels.pick(p.Metadata.Labels)
			row.CreatedAt = utc(p.Metadata.CreationTimestamp)
		}
		describePodSpec(row, p.Spec)
		st = &workloadState{row: row, podLabels: p.Metadata.Labels, proxy: "none"}
		k.workloads[key] = st
	}
	for _, c := range append(append([]containerSpec{}, p.Spec.Containers...), p.Spec.InitContainers...) {
		switch c.Name {
		case "istio-proxy":
			st.proxy = "istio"
		case "linkerd-proxy":
			st.proxy = "linkerd"
		}
	}
	k.podWorkload[podKey(ns, name)] = ref

	ips := make([]string, 0, len(p.Status.PodIPs)+1)
	for _, ip := range p.Status.PodIPs {
		ips = append(ips, ip.IP)
	}
	if len(ips) == 0 && p.Status.PodIP != "" {
		ips = append(ips, p.Status.PodIP)
	}
	ips = cleanIPs(ips, 8)
	// A pod that has finished, or has no address yet, answers nothing.
	if len(ips) == 0 || p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" {
		return
	}
	row := Pod{
		Namespace: ns, Name: name, UID: cleanUID(p.Metadata.UID), Workload: ref,
		Node: cleanName(p.Spec.NodeName), Addresses: ips, HostNetwork: p.Spec.HostNetwork,
		StartedAt: utc(p.Status.StartTime),
	}
	switch p.Status.Phase {
	case "Pending", "Running", "Unknown":
		row.Phase = p.Status.Phase
	}
	if c := findCondition(p.Status.Conditions, "Ready"); c != nil {
		row.Ready = boolPtr(c.Status == "True")
	}
	k.inv.Pods = append(k.inv.Pods, row)
}

func (k *collector) collectServices(ctx context.Context, podErr error) {
	services, svcErr := list[serviceObject](ctx, k.c, resServices, "", nil, k.max)
	slices, sliceErr := list[endpointSliceObject](ctx, k.c, resEndpointSlices, "", nil, k.max)

	type backing struct {
		refs            map[WorkloadRef]bool
		ready, notReady int
		ports           map[string]map[int]bool
		manual          bool
	}
	byService := map[string]*backing{}
	for _, s := range slices {
		svc := s.Metadata.Labels["kubernetes.io/service-name"]
		if svc == "" {
			continue
		}
		key := podKey(s.Metadata.Namespace, svc)
		b := byService[key]
		if b == nil {
			b = &backing{refs: map[WorkloadRef]bool{}, ports: map[string]map[int]bool{}}
			byService[key] = b
		}
		for _, e := range s.Endpoints {
			if e.Conditions.Ready == nil || *e.Conditions.Ready {
				b.ready++
			} else {
				b.notReady++
			}
			if e.TargetRef != nil && e.TargetRef.Kind == "Pod" {
				ns := e.TargetRef.Namespace
				if ns == "" {
					ns = s.Metadata.Namespace
				}
				if ref, ok := k.podWorkload[podKey(ns, e.TargetRef.Name)]; ok && ns == s.Metadata.Namespace {
					b.refs[ref] = true
					continue
				}
			}
			b.manual = true
		}
		for _, p := range s.Ports {
			if port := cleanPort(p.Port); port != 0 {
				if b.ports[p.Name] == nil {
					b.ports[p.Name] = map[int]bool{}
				}
				b.ports[p.Name][port] = true
			}
		}
	}
	if k.inv.Cluster.APIEndpoints == nil {
		k.inv.Cluster.APIEndpoints = apiEndpoints(slices)
	}

	for _, s := range services {
		ns, name := cleanName(s.Metadata.Namespace), cleanName(s.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := Service{
			Namespace: ns, Name: name, UID: cleanUID(s.Metadata.UID), Type: "ClusterIP",
			ExternalIPs:           cleanIPs(s.Spec.ExternalIPs, 32),
			LoadBalancerAddresses: limit(clipAll(s.Status.LoadBalancer.addresses(), 253), 32),
			Workloads:             []WorkloadRef{}, Ports: []ServicePort{},
			Labels: k.labels.pick(s.Metadata.Labels), CreatedAt: utc(s.Metadata.CreationTimestamp),
		}
		switch s.Spec.Type {
		case "NodePort", "LoadBalancer", "ExternalName":
			row.Type = s.Spec.Type
		}
		clusterIPs := s.Spec.ClusterIPs
		if len(clusterIPs) == 0 && s.Spec.ClusterIP != "" {
			clusterIPs = []string{s.Spec.ClusterIP}
		}
		row.Headless = s.Spec.ClusterIP == "None"
		row.ClusterIPs = cleanIPs(clusterIPs, 4)

		b := byService[podKey(s.Metadata.Namespace, s.Metadata.Name)]
		refs := map[WorkloadRef]bool{}
		if b != nil {
			refs = b.refs
			row.EndpointsReady, row.EndpointsNotReady = intPtr(b.ready), intPtr(b.notReady)
		}
		if len(refs) == 0 && len(s.Spec.Selector) > 0 {
			// Nothing is running behind it right now (scaled to zero, or not
			// yet started): the selector still says whose Service it is.
			for key, st := range k.workloads {
				if key.namespace == s.Metadata.Namespace && selects(s.Spec.Selector, st.podLabels) {
					refs[WorkloadRef{Kind: key.kind, Name: key.name}] = true
				}
			}
		}
		for ref := range refs {
			row.Workloads = append(row.Workloads, ref)
		}
		sort.Slice(row.Workloads, func(i, j int) bool {
			if row.Workloads[i].Kind != row.Workloads[j].Kind {
				return row.Workloads[i].Kind < row.Workloads[j].Kind
			}
			return row.Workloads[i].Name < row.Workloads[j].Name
		})
		row.Workloads = limit(row.Workloads, 256)
		switch {
		case row.Type == "ExternalName":
			row.Backing = BackingExternalName
			row.ExternalName = clip(s.Spec.ExternalName, 253)
			row.Workloads = []WorkloadRef{}
		case len(row.Workloads) > 0:
			row.Backing = BackingWorkloads
		case b != nil && (b.manual || b.ready+b.notReady > 0):
			row.Backing = BackingManualEndpoints
		default:
			row.Backing = BackingNone
		}

		for _, p := range limit(s.Spec.Ports, 256) {
			port := cleanPort(p.Port)
			if port == 0 {
				continue
			}
			sp := ServicePort{
				Name: clip(p.Name, 63), Port: port, Protocol: cleanProtocol(p.Protocol),
				AppProtocol: clip(p.AppProtocol, 253), TargetPort: clip(string(p.TargetPort), 63), NodePort: cleanPort(p.NodePort),
			}
			if b != nil {
				for n := range b.ports[p.Name] {
					sp.ResolvedTargetPorts = append(sp.ResolvedTargetPorts, n)
				}
				sort.Ints(sp.ResolvedTargetPorts)
				sp.ResolvedTargetPorts = limit(sp.ResolvedTargetPorts, 64)
			}
			row.Ports = append(row.Ports, sp)
		}
		k.inv.Services = append(k.inv.Services, row)
	}
	// Attribution is built from the endpoints and the pods, so a Service list
	// read without them is not a clean answer.
	k.answer(ClassServices, len(k.inv.Services), svcErr, sliceErr, podErr)
}

// apiEndpoints are the endpoints of the default/kubernetes Service: where the
// API server itself listens.
func apiEndpoints(slices []endpointSliceObject) []APIEndpoint {
	var out []APIEndpoint
	for _, s := range slices {
		if s.Metadata.Namespace != "default" || s.Metadata.Labels["kubernetes.io/service-name"] != "kubernetes" {
			continue
		}
		for _, p := range s.Ports {
			port := cleanPort(p.Port)
			if port == 0 {
				continue
			}
			for _, e := range s.Endpoints {
				for _, addr := range cleanIPs(e.Addresses, 16) {
					out = append(out, APIEndpoint{Address: addr, Port: port})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return limit(out, 64)
}

// ---- Ingress and Gateway ----

func (k *collector) collectIngresses(ctx context.Context) {
	if !k.reads(ClassIngresses) {
		return
	}
	ingresses, err := list[ingressObject](ctx, k.c, resIngresses, "", nil, k.max)
	classes, classErr := list[ingressClassObject](ctx, k.c, resIngressClasses, "", nil, k.max)
	controllers := map[string]string{}
	for _, c := range classes {
		controllers[c.Metadata.Name] = c.Spec.Controller
	}
	for _, in := range ingresses {
		ns, name := cleanName(in.Metadata.Namespace), cleanName(in.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := Ingress{
			Namespace: ns, Name: name, UID: cleanUID(in.Metadata.UID),
			ClassName:             cleanName(in.Spec.IngressClassName),
			Controller:            clip(controllers[in.Spec.IngressClassName], 253),
			LoadBalancerAddresses: limit(clipAll(in.Status.LoadBalancer.addresses(), 253), 32),
			CreatedAt:             utc(in.Metadata.CreationTimestamp),
		}
		for _, t := range limit(in.Spec.TLS, 256) {
			row.TLS = append(row.TLS, IngressTLS{Hosts: nonNil(limit(clipAll(t.Hosts, 253), 256)), SecretName: cleanName(t.SecretName)})
		}
		for _, r := range limit(in.Spec.Rules, 512) {
			rule := IngressRule{Host: clip(r.Host, 253)}
			for _, t := range row.TLS {
				if hostCovered(t.Hosts, r.Host) {
					rule.TLS, rule.SecretName = true, t.SecretName
					break
				}
			}
			if r.HTTP != nil {
				for _, p := range limit(r.HTTP.Paths, 256) {
					svc, port := p.Backend.target()
					if svc = cleanName(svc); svc == "" {
						continue
					}
					rule.Paths = append(rule.Paths, IngressPath{Path: clip(p.Path, 1024), PathType: clip(p.PathType, 32), Service: svc, ServicePort: clip(port, 63)})
				}
			}
			row.Rules = append(row.Rules, rule)
		}
		if in.Spec.DefaultBackend != nil {
			if svc, port := in.Spec.DefaultBackend.target(); cleanName(svc) != "" {
				row.DefaultBackend = &IngressBackend{Service: svc, ServicePort: clip(port, 63)}
			}
		}
		k.inv.Ingresses = append(k.inv.Ingresses, row)
	}
	k.answer(ClassIngresses, len(k.inv.Ingresses), err, classErr)
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// hostCovered reports whether a tls entry's hosts cover host, by exact name or
// by a wildcard for the first label.
func hostCovered(hosts []string, host string) bool {
	if host == "" {
		return false
	}
	for _, h := range hosts {
		if strings.EqualFold(h, host) {
			return true
		}
		if suffix, ok := strings.CutPrefix(h, "*"); ok {
			if i := strings.IndexByte(host, '.'); i > 0 && strings.EqualFold(host[i:], suffix) {
				return true
			}
		}
	}
	return false
}

func (k *collector) collectGateways(ctx context.Context) {
	if !k.reads(ClassGateways) {
		return
	}
	gateways, err := list[gatewayObject](ctx, k.c, resGateways, "", nil, k.max)
	if statusOf(err) == http.StatusNotFound {
		k.answer(ClassGateways, 0, err)
		return
	}
	classes, classErr := list[gatewayClassObject](ctx, k.c, resGatewayClasses, "", nil, k.max)
	controllers := map[string]string{}
	for _, c := range classes {
		controllers[c.Metadata.Name] = c.Spec.ControllerName
	}
	for _, g := range gateways {
		ns, name := cleanName(g.Metadata.Namespace), cleanName(g.Metadata.Name)
		if ns == "" || name == "" {
			continue
		}
		row := Gateway{
			Namespace: ns, Name: name, UID: cleanUID(g.Metadata.UID),
			ClassName:  cleanName(g.Spec.GatewayClassName),
			Controller: clip(controllers[g.Spec.GatewayClassName], 253),
			CreatedAt:  utc(g.Metadata.CreationTimestamp),
		}
		for _, a := range limit(g.Status.Addresses, 32) {
			row.Addresses = append(row.Addresses, clip(a.Value, 253))
		}
		attached := map[string]int{}
		for _, l := range g.Status.Listeners {
			attached[l.Name] = l.AttachedRoutes
		}
		for _, l := range limit(g.Spec.Listeners, 64) {
			lname, port := cleanName(l.Name), cleanPort(l.Port)
			if lname == "" || port == 0 {
				continue
			}
			out := GatewayListener{Name: lname, Hostname: clip(l.Hostname, 253), Port: port, Protocol: clip(l.Protocol, 64)}
			if n, ok := attached[l.Name]; ok && n >= 0 {
				out.AttachedRoutes = intPtr(n)
			}
			if l.TLS != nil {
				switch l.TLS.Mode {
				case "Passthrough":
					out.TLSMode = "Passthrough"
				default:
					out.TLSMode = "Terminate"
				}
				for _, r := range limit(l.TLS.CertificateRefs, 64) {
					ref := ObjectRef{Kind: cleanKind(r.Kind), Namespace: cleanName(r.Namespace), Name: cleanName(r.Name)}
					if r.Group != nil {
						ref.Group = cleanGroup(*r.Group)
					}
					if ref.Kind == "" {
						ref.Kind = "Secret"
					}
					if ref.Name != "" {
						out.CertificateRefs = append(out.CertificateRefs, ref)
					}
				}
			}
			row.Listeners = append(row.Listeners, out)
		}
		k.inv.Gateways = append(k.inv.Gateways, row)
	}

	errs := []error{err, classErr}
	for _, src := range []struct {
		res  Resource
		kind string
	}{{resHTTPRoutes, "HTTPRoute"}, {resGRPCRoutes, "GRPCRoute"}, {resTLSRoutes, "TLSRoute"}, {resTCPRoutes, "TCPRoute"}} {
		routes, err := list[routeObject](ctx, k.c, src.res, "", nil, k.max)
		// A cluster serves only the route kinds its Gateway API channel has.
		errs = append(errs, notFoundIsNone(err))
		for _, r := range routes {
			ns, name := cleanName(r.Metadata.Namespace), cleanName(r.Metadata.Name)
			if ns == "" || name == "" {
				continue
			}
			row := Route{
				Kind: src.kind, Namespace: ns, Name: name, UID: cleanUID(r.Metadata.UID),
				Hostnames: limit(clipAll(r.Spec.Hostnames, 253), 64), CreatedAt: utc(r.Metadata.CreationTimestamp),
			}
			for _, p := range limit(r.Spec.ParentRefs, 32) {
				if pn := cleanName(p.Name); pn != "" {
					row.Parents = append(row.Parents, RouteParent{Namespace: cleanName(p.Namespace), Name: pn, SectionName: cleanName(p.SectionName), Port: cleanPort(p.Port)})
				}
			}
			for _, rule := range r.Spec.Rules {
				for _, b := range rule.BackendRefs {
					if bn := cleanName(b.Name); bn != "" {
						row.Backends = append(row.Backends, RouteBackend{Kind: cleanKind(b.Kind), Namespace: cleanName(b.Namespace), Name: bn, Port: cleanPort(b.Port)})
					}
				}
			}
			row.Backends = limit(row.Backends, 256)
			k.inv.Routes = append(k.inv.Routes, row)
		}
	}
	k.answer(ClassGateways, len(k.inv.Gateways)+len(k.inv.Routes), errs...)
}
