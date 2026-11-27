# Kubernetes inventory

Status: the protocol schema
([`schemas/managed/v1/defs/kubernetes-inventory.json`](../../schemas/managed/v1/defs/kubernetes-inventory.json))
and the collector (`shared/kubeinventory`, the `kubernetes_inventory` job and
`device-agent kubernetes-inventory`) are in this repository, with the
container images of both agents ([`../verify-release.md`](../verify-release.md),
"Container images") and the manifest that deploys them
([`deploy/kubernetes/`](../../deploy/kubernetes/)). Installing and running
them: [`../device-agent/KUBERNETES.md`](../device-agent/KUBERNETES.md).

## What it is

A device agent that runs **inside** a Kubernetes cluster reads what the
cluster's own API says about its cryptography and returns it as one typed
record: which workloads and Services exist and what ports they declare, where
TLS is configured on Ingress and Gateway listeners, what cert-manager issues
and whether it is healthy, what the service mesh enforces, which certificates
the control plane and the admission webhooks present.

The record says what is **declared**. What actually **answers** on each port
is a sensor's work: a sensor deployed beside the agent scans the Services and
pods this record names. The record is therefore also the list of things to
scan, which is why every Service, pod address and declared port in it is
attributed to a cluster, a namespace and a workload.

It is a new device-agent job type, `kubernetes_inventory`, and the same
collector as a standalone command (`device-agent kubernetes-inventory`) that
writes the record to a file with no platform involved.

## What it is not, in this release

- No DaemonSet, no node filesystem, no container filesystem, no image layers.
  Certificates that exist only as files on a node (etcd, scheduler,
  controller-manager) are reported as not collected, never as absent.
- No passive capture in the cluster.
- No collection from outside the cluster. There is no kubeconfig, token or API
  server address in a job or in the agent's configuration; the agent uses the
  service account of the pod it runs in and nothing else.
- No watch. The agent reads on request and holds no live mirror of the cluster.
- No Helm chart. One plain manifest deploys both agents.

## Rules

1. **Posture, never key material.** No private key reaches the record, a log
   or a variable. The record has no member that could hold one (see "How the
   schema keeps keys out").
2. **Read-only, by name.** The collector calls `get` and `list`, on a fixed
   list of resources (below). No wildcard, no `watch`, no write verb, no
   `pods/exec`, `pods/log`, `nodes/proxy` or any other subresource. The
   manifest's role grants exactly that list and a test holds the two together.
3. **Typed projections.** Each API object is decoded into a struct that
   declares only the fields the record needs, so the rest of the object is
   never held: no environment variables, commands or arguments of a container,
   no annotations (other than the few named below), no ConfigMap data except
   the certificate bundles and settings named below, no Secret data except
   certificates.
4. **Three answers per class.** `ok`, `failed` or `unsupported`, for every
   class, every time. An empty list means "none exist" only under `ok`.
5. **Attribution.** A pod address or a Service address means nothing on its
   own: the same ranges exist in every cluster that kept its defaults. The
   record carries the cluster's id in every part, and a collection whose
   cluster id cannot be read fails as a whole instead of sending rows nobody
   can place.
6. **The agent connects only to the API server and to kubelets.** It makes TLS
   handshakes with the API server (the connection it already has) and with
   each node's kubelet port, and with nothing else. The kubelet handshake is
   verified against the cluster CA like any other and sends nothing; a kubelet
   whose certificate does not verify is still recorded, from the certificates
   the failed handshake reports. Ingress hosts, Gateway
   listeners, Services and pods are scanned by the sensor.

## How it runs

The agent advertises the capability `kubernetes_inventory_v1` only when it
runs in a cluster (a mounted service-account token and the API server
environment are present). A platform queues `kubernetes_inventory` jobs only
for an agent that negotiated it; an agent that did not answers such a job with
`unsupported_command`, like any job type it does not run.

The job carries **no credentials**; a job of this type with a sealed
credentials envelope is invalid and is refused. Its parameters
([`defs/kubernetes-inventory-parameters.json`](../../schemas/managed/v1/defs/kubernetes-inventory-parameters.json))
are all optional:

| Parameter | Default | Meaning |
|---|---|---|
| `classes` | all | Collect only these classes; the rest answer `unsupported`, `not_requested` |
| `probe_kubelets` | true | Handshake with each node's kubelet port |
| `include_certificate_pem` | true | Send each certificate's PEM, not only its parsed fields |
| `extra_label_keys` | none | Label keys to report beyond the built-in allowlist (at most 32) |
| `max_items_per_class` | 100,000 | Stop reading a class after this many rows; the class then answers `failed`, `item_limit` |
| `max_part_bytes` | 8 MiB | Size at which the result is split into parts |
| `timeout_seconds` | 600 | Whole-job time limit |
| `traefik` | false | Also read Traefik's CRDs and answer the `traefik` section (see "Traefik") |

Parameters that would name another cluster or supply a credential
(`kubeconfig`, `token`, `api_server`, …) make the job invalid. No parameter
turns on reading TLS Secrets; see below.

How often to collect is the platform's decision: it queues the job on its
interval. The agent keeps no schedule of its own for this.

## What the collector reads

| API group | Resources | Verbs | For |
|---|---|---|---|
| (non-resource) | `/version` | get | Kubernetes version |
| core | `namespaces`, `nodes`, `pods`, `services` | list | Cluster id (the `kube-system` namespace UID), nodes, workload attribution, Services |
| core | `configmaps`, only those named `istio-ca-root-cert`, `linkerd-identity-trust-roots`, `cilium-config` | get | Mesh trust anchors, Cilium encryption settings |
| `apps` | `deployments`, `statefulsets`, `daemonsets`, `replicasets` | list | Workloads; ReplicaSets only to find a pod's Deployment |
| `batch` | `cronjobs`, `jobs` | list | Workloads; Jobs only to find a pod's CronJob |
| `discovery.k8s.io` | `endpointslices` | list | Which pods back a Service, and the port numbers actually used |
| `networking.k8s.io` | `ingresses`, `ingressclasses`, `servicecidrs` | list | Ingress TLS, the controller behind a class, the Service range |
| `gateway.networking.k8s.io` | `gatewayclasses`, `gateways`, `httproutes`, `grpcroutes`, `tlsroutes`, `tcproutes` | list | Gateway listeners and what routes to them |
| `cert-manager.io` | `certificates`, `certificaterequests`, `issuers`, `clusterissuers` | list | cert-manager |
| `certificates.k8s.io` | `certificatesigningrequests` | list | Cluster certificate signing |
| `security.istio.io` | `peerauthentications` | list | Istio mTLS mode |
| `networking.istio.io` | `destinationrules` | list | Istio client-side TLS mode |
| `policy.linkerd.io` | `servers`, `authorizationpolicies` | list | Linkerd policy |
| `admissionregistration.k8s.io` | `validatingwebhookconfigurations`, `mutatingwebhookconfigurations` | list | Webhook CA bundles |
| `apiregistration.k8s.io` | `apiservices` | list | Aggregated API CA bundles |
| `traefik.io`, `traefik.containo.us` | `ingressroutes`, `ingressroutetcps`, `tlsoptions`, `tlsstores` | list | Traefik edge TLS; only with the job parameter `traefik` |
| core, **only with the opt-in role** | `secrets` | list | Certificates in TLS Secrets |

The cluster CA bundle is the one the kubelet mounts into the agent's own pod
with its service account; no ConfigMap is read for it. `list` is the only verb
used on anything that is not one of the three named ConfigMaps or `/version`.
The table in the code that the collector cannot step outside is
`shared/kubeinventory/calls.go`.

A group the cluster does not serve (no cert-manager, no Gateway API, no mesh)
answers `404`; the class reads `unsupported`, `not_installed`. A `403` reads
`failed`, `not_permitted`. The collector does not use API discovery to decide.

From `cilium-config` three settings are read (WireGuard on, IPsec on, node
encryption on) and nothing else of it.
From a namespace's annotations only the Linkerd injection and default inbound
policy are read. From a pod template only container names, images, declared
ports, the service account name, host networking, and the names of Secrets
mounted as volumes.

## TLS Secrets: two facts about Kubernetes RBAC

Kubernetes authorises by resource and verb. Two consequences shape this
feature and the documentation must not blur them:

- **Permission to read a Secret is permission to read its key.** There is no
  rule that returns `tls.crt` and withholds `tls.key`.
- **There is no metadata-only or type-only permission.** Listing Secrets'
  names, types or ages needs the same `list` permission that returns their
  contents, and a role cannot be limited to Secrets of type
  `kubernetes.io/tls`.

So:

- **By default the agent has no permission on Secrets and never calls the
  Secrets API**, not even to ask whether it may. The class `tls_secrets`
  answers `unsupported`, `not_enabled`. The record still names every Secret
  that something *refers to*: an Ingress TLS entry, a Gateway listener, a
  cert-manager Certificate or issuer, a workload volume. It cannot give the
  type or age of a Secret, and it cannot list Secrets nothing refers to.
  Certificates still arrive without Secret access from cert-manager's
  CertificateRequests (which hold the issued certificate and no key), from
  signing requests, CA bundles and the control-plane handshakes, and from the
  sensor's scan of everything that serves one.
- **Reading TLS Secrets is turned on by the cluster's administrators**, by
  applying the opt-in role and setting one environment variable on the device
  agent's Deployment. A platform cannot turn it on: there is no job parameter
  for it. The opt-in role can be bound cluster-wide, or namespace by
  namespace; each namespace row then says whether its Secrets were readable.
- **With it on, the role permits reading every Secret where it is bound. The
  agent asks only for TLS ones**: it lists with the field selector
  `type=kubernetes.io/tls`, so the API server sends no other Secret. It
  decodes each into a struct that declares `tls.crt` and `ca.crt` and no other
  entry, so the bytes of `tls.key` are skipped by the JSON decoder and never
  become a value in the program; they are not parsed, hashed, logged or
  compared. A test serves a Secret with a known key and proves the key is in
  no part of the result.

## The record

One collection is one document, sent as the `kubernetes_inventory` member of
a device-agent job result. The schema is closed at every level.

**Header (every part):** `schema_version` (1), `collection_id`, `part`
(`index`, `count`), `collected_at`, and `cluster.id`.

**Part 0 also carries:**

- `cluster`: `id` (the UID of the `kube-system` namespace, stable for the
  cluster's life), Kubernetes version, `distribution` (`eks`, `aks`, `gke`,
  `rke2`, `k3s`, `openshift`, `kubeadm`, `unknown`), node count, the cluster
  CA bundle (fingerprints), the API server's endpoints, the pod ranges and the
  Service ranges.
- `collector`: whether reading TLS Secrets is enabled in this deployment.
- `sections`: the answer of each class (below).
- `mesh`: for Istio, Linkerd and Cilium, whether it is present, its trust
  anchors, the mesh-wide mTLS mode or encryption setting.
- `api_server`: the handshake with the API server.

**Lists, which may continue across parts:**

| List | One row is | Attribution and main fields |
|---|---|---|
| `nodes` | a node | name, uid, addresses, roles, kubelet and runtime version, OS image, kernel, architecture, provider id, machine id, system UUID, pod ranges, kubelet port, labels |
| `namespaces` | a namespace | name, uid, labels, Istio and Linkerd injection, the Istio mTLS mode in force, whether its TLS Secrets were readable |
| `workloads` | a controller (Deployment, StatefulSet, DaemonSet, CronJob), a Job or ReplicaSet nothing owns, a pod nothing owns (`Pod`), a static pod (`Node`), or another controller's kind | namespace, kind, name, uid, replicas, containers (name, image, declared ports), host networking, service account, mounted Secret names, mesh proxy, mTLS mode in force, labels |
| `pods` | a pod that has an address | namespace, name, **workload** (kind and name, required), node, addresses, host networking, phase |
| `services` | a Service | namespace, name, type, cluster and external addresses, **backing** (`workloads`, `manual_endpoints`, `external_name`, `none`) and **workloads** (required), ready and not-ready endpoint counts, ports (port, protocol, declared target, the target port numbers in use, node port) |
| `ingresses` | an Ingress | namespace, name, class and controller, load-balancer addresses, TLS entries (hosts, Secret name), rules (host, whether TLS covers it, paths to Service and port) |
| `gateways` | a Gateway | namespace, name, class and controller, addresses, listeners (hostname, port, protocol, TLS mode, certificate references) |
| `routes` | an HTTPRoute, GRPCRoute, TLSRoute or TCPRoute | namespace, name, hostnames, parent Gateways, backend Services |
| `cert_manager_certificates` | a Certificate | namespace, name, the Secret it writes, issuer reference, names, usages, duration, renew-before, the key it asks for (algorithm, size, rotation), Ready condition, validity, renewal time |
| `cert_manager_issuers` | an Issuer or ClusterIssuer | scope, name, type (`acme`, `ca`, `self_signed`, `vault`, `venafi`, `unknown`), ACME server and solver types, CA Secret name, Vault server and path, Ready condition |
| `cert_manager_requests` | a CertificateRequest | namespace, name, its Certificate, approval, what the request asks for, the issued chain and CA (fingerprints) |
| `certificate_signing_requests` | a cluster CertificateSigningRequest | name, signer, requestor, usages, approval, what the request asks for, the issued chain |
| `tls_secrets` | a TLS Secret (opt-in only) | namespace, name, age, owner, the chain in `tls.crt` and the certificates in `ca.crt` (fingerprints) |
| `istio_peer_authentications`, `istio_destination_rules` | an Istio policy | namespace, name, scope, selector, mode, per-port modes |
| `linkerd_servers`, `linkerd_authorization_policies` | a Linkerd policy | namespace, name, port or target, required authentications |
| `kubelets` | a handshake with one node's kubelet | node, address, port, outcome, TLS version, cipher suite, chain, whether it chains to the cluster CA |
| `admission_webhooks` | one webhook of a webhook configuration | configuration, name, the Service or host it calls, failure policy, CA bundle |
| `api_services` | an aggregated API | name, the Service behind it, whether TLS verification is skipped, CA bundle |
| `traefik_ingress_routes` | an IngressRoute or IngressRouteTCP (`traefik` only) | kind, API group, namespace, name, entry points, routes (redacted match, hosts, Services), TLS (Secret name, options reference, effective options, store, certificate resolver, domains, passthrough) |
| `traefik_tls_options` | a TLSOption (`traefik` only) | API group, namespace, name, minimum and maximum version, cipher suites, curves, client authentication (type, CA Secret names), SNI strictness, ALPN protocols |
| `traefik_tls_stores` | a TLSStore (`traefik` only) | API group, namespace, name, default certificate Secret name, certificate Secret names |
| `certificates` | one distinct certificate | the fields of the one certificate format ([`defs/certificate.json`](../../schemas/managed/v1/defs/certificate.json)), keyed by `fingerprint_sha256` |

**Certificates appear once.** Every other row names a certificate by its
SHA-256 fingerprint, in chain order where there is a chain. What uses a
certificate is read from the rows that name it; a certificate no row names
cannot occur.

**A Secret has no row unless TLS Secrets are read.** It is known by name
through `secret_name` on an Ingress TLS entry or a Certificate,
`certificate_refs` on a Gateway listener, `ca_secret_name` on an issuer,
`secret_volumes` on a workload, and with `traefik` the `secret_name` of an
IngressRoute's TLS, a TLSStore's `default_certificate_secret` and
`certificate_secrets`, and a TLSOption's `client_auth.secret_names`.

### Attribution

- **Cluster:** `cluster.id`, required in every part.
- **Namespace:** required on every namespaced row.
- **Workload:** a pod's `workload` is required and names a row of `workloads`
  in the pod's namespace (when a job asks for `pods` without `workloads`, the
  reference is still there and the rows are not). The agent resolves it through owner references (a
  pod's ReplicaSet to its Deployment, a pod's Job to its CronJob). A pod
  nothing owns is its own workload of kind `Pod`; a static pod belongs to a
  workload of kind `Node`; a pod owned by a controller the agent does not list
  belongs to a workload of that controller's kind, described from the pod.
- **Service to workload:** resolved from the Service's endpoints to pods to
  their workloads. A Service with no workload behind it says which kind of
  nothing: `external_name`, `manual_endpoints` (addresses someone wrote by
  hand, the `default/kubernetes` Service among them) or `none`.
- **Declared ports:** a container port belongs to its workload row; a Service
  port belongs to its Service row, which names its workloads.
- **Host-network pods** carry `host_network: true`: their address is the
  node's, not one from the pod range.

### Mesh mTLS mode

The agent reports the policies as written and also the mode in force, so that
a reader need not re-implement a mesh's precedence rules: for Istio, a
workload-selecting PeerAuthentication, else the namespace's, else the mesh's
(root namespace), else permissive. Values: `strict`, `permissive`, `disabled`,
`not_meshed` (no mesh proxy on the workload, or no mesh in the cluster),
`unknown`. Port-level overrides are reported on the policy and do not change
the workload's mode.

## The answer of each class

`sections` has one entry for each of: `cluster`, `nodes`, `namespaces`,
`workloads`, `pods`, `services`, `ingresses`, `gateways` (with routes),
`cert_manager`, `certificate_signing_requests`, `tls_secrets`, `mesh_istio`,
`mesh_linkerd`, `mesh_cilium`, `api_server_certificate`,
`kubelet_certificates`, `control_plane_node_certificates`,
`admission_webhooks`, `api_services`.

| `status` | Means | `reason` |
|---|---|---|
| `ok` | Read in full. An empty list is a fact | none |
| `failed` | It should have been readable and was not. Rows read before the failure are sent; nothing may be concluded from what is missing | `not_permitted`, `api_error`, `timeout`, `item_limit`, `unreachable` |
| `unsupported` | Not in this cluster, not given to this deployment, or not collected by this release | `not_installed`, `not_enabled`, `not_requested`, `not_collected_in_this_release` |

`sections` has a `traefik` entry only when the job asked for Traefik (see
"Traefik"); it is not a class and cannot be named in `classes`.

`control_plane_node_certificates` always answers `unsupported`,
`not_collected_in_this_release`: it stands for the etcd, scheduler and
controller-manager certificates, which are files on control-plane nodes.

A job fails as a whole (`success: false`) only when the cluster id cannot be
read, the agent is not running in a cluster, or the job is invalid.

## Traefik

Traefik's routing and TLS are its own CRDs, which no other member can hold,
and the record is closed, so an agent that sent them unasked would have its
result refused by a platform that does not know them. They are therefore
read only when the job parameters carry `"traefik": true` (job parameters
are open, so an older agent ignores the parameter and sends no `traefik`
section). Without the parameter no Traefik API is called and the record is
byte for byte what it was before; a test holds that. A missing `traefik`
section means the agent was not asked or does not collect it, never "none".

- **What is read.** `list` on `ingressroutes`, `ingressroutetcps`,
  `tlsoptions` and `tlsstores`, in `traefik.io/v1alpha1` and in the legacy
  `traefik.containo.us/v1alpha1`; all eight every time. Each row says its
  `api_group`, because the same namespace and name can exist in both: two
  objects. No Secret is read: Secrets are named (`secret_name`, a store's
  `default_certificate_secret` and `certificate_secrets`, a TLSOption's
  `client_auth.secret_names`) as an Ingress's are. Middlewares,
  ServersTransports and IngressRouteUDPs are not read; fields of the read
  objects that the record does not name (middlewares on a route, a
  TLSOption's `caFiles`, a store's generated-certificate settings) are not
  decoded.
- **The answer.** `ok`; `unsupported`, `not_installed` when neither group
  serves IngressRoutes (a 404 on any other of the eight is "none"); `failed`,
  `not_permitted` on a 403 on any of them; `failed`, `item_limit` or
  `api_error` as for any class. `count` is routes, options and stores
  together.
- **The rule is redacted.** A route's `match` is free text that commonly
  carries shared secrets (``Header(`X-Api-Key`, `...`)``,
  ``Query(`token`, `...`)``, `ClientIP` lists), so it is tokenised and rebuilt:
  matcher names, `&&`, `||`, `!` and grouping are kept; the quoted arguments
  of `Host`, `HostSNI`, `HostRegexp`, `HostSNIRegexp`, `Path`, `PathPrefix`,
  `PathRegexp`, `Method` and `ALPN` are kept; of `Header`, `HeaderRegexp`,
  `Headers`, `HeadersRegexp`, `Query` and `QueryRegexp` only the first
  argument, the key name; every other literal, including all arguments of a
  matcher the agent does not know, becomes `[REDACTED]`. Backtick and
  double-quoted literals (with escapes) are read, in Traefik v2 and v3
  syntax. A rule that cannot be tokenised safely is sent with no `match` at
  all. Redaction comes before the 1024-character cut.
- **Hosts.** A route's `hosts` are the literal arguments of `Host(...)` and
  `HostSNI(...)` in its rule, lower case and sorted, only where they are
  certain: none for a rule with a negation or a host regular expression, an
  `||` inside parentheses, or a top-level alternative that names no host
  (``HostSNI(`*`)`` has none). Hosts are read from the whole rule.
- **Effective TLS options**, resolved by the agent as Traefik documents it:
  the TLSOption the route's `tls.options` names (`source: referenced`; its
  namespace is the route's when the reference names none); else the one
  TLSOption named `default`, in whatever namespace (`source: default`); else
  Traefik's built-in options (`source: traefik_builtin`), which is also what
  Traefik uses when more than one TLSOption is named `default`
  (`default_conflict: true`). The same namespace's `default` served under both
  groups counts once. A reference in Traefik's cross-provider form
  (`name@provider`) is carried as `name` and `provider` with no namespace: the
  option lives outside the cluster's API. A passthrough route has no
  effective options (Traefik does not terminate its TLS). When the TLSOptions
  could not be read, a route that references none has no effective options
  rather than a guess.
  `referenced` says what the route names, not that Traefik serves it: Traefik
  registers any TLSOption named `default` as the global default, so a
  reference to a TLSOption named `default` in a namespace may not resolve as
  written; and Traefik refuses a cross-namespace `options` or `store`
  reference unless `allowCrossNamespace` is set in its static configuration,
  which the agent cannot see. `default_conflict` counts TLSOptions named
  `default` from both API groups, and Traefik v3 no longer reads
  `traefik.containo.us`, so a stale legacy `default` can set it on a v3
  cluster.
- **Not visible to the API**, and so not in the record: TLS options, stores
  and certificates set in Traefik's static or file configuration (including
  the `defaultTLSResourcesNamespace` restriction on where the `default`
  option may live), certificates a certificate resolver obtained (the record
  says which resolver, not the certificate), and Ingresses annotated for
  Traefik (they are in `ingresses`). What is shown is what the cluster's API
  declares.

## Parts

A device-agent job result is limited in size, and a large cluster does not
fit one: fifty thousand pods and ten thousand certificates with their PEM are
several tens of megabytes. So the agent splits a collection into parts of at
most `max_part_bytes` and posts each as its own job result with the same
`job_id`, in order.

- Each part validates on its own and names `collection_id`, `part.index`,
  `part.count` and `cluster.id`.
- Part 0 carries everything that is not a list.
- A list may continue across parts; a row is never split.
- The job is complete when the part with `index == count - 1` has arrived.
- A reader must not treat anything as removed until it holds every part. If a
  later part never arrives, or a result with `success: false` follows, the
  parts already received describe an incomplete collection and are to be
  discarded.

A small cluster is one part: `{"index": 0, "count": 1}`.

## How the schema keeps keys out

- Every object is closed, so a Secret's `data`, a pod's `env` or anything else
  the schema does not name is an error, not a passenger.
- Every string is bounded. The only long one is `certificate_pem`, whose
  pattern admits exactly one `CERTIFICATE` block.
- The only maps are label maps, whose values are held to Kubernetes label
  syntax (63 characters, no whitespace).
- The members with "key" in their name describe a key (`key_algorithm`,
  `key_size`, `key_usage`, `extended_key_usage`, `key_exchange_group`,
  `key_request`); a test pins that list.

`internal/testsupport/protocolschema` holds these as tests over the schema
itself, beside fixtures of results that must be refused (a private key in
`certificate_pem`, a Secret's data, an unattributed pod or Service, a class
without an answer). The schema is the second line; the first is the collector,
which never decodes a key in the first place.

## Standalone

`device-agent kubernetes-inventory` runs the same collector in a pod and
writes the same record, as one `kubernetes_inventory` record of the standalone
output format ([`../standalone.md`](../standalone.md)). It takes no
kubeconfig.

## Tests

- Schema: every fixture against its schema; the structural guards above.
- Collector (`shared/kubeinventory`): a synthetic cluster served by an
  in-process API server (`kubetest`), holding everything the collector must
  leave behind; every collection validated against the schema; attribution of
  every pod and Service; each class's three answers; the `tls.key` test; that
  no projection can hold an open value; that every request is a declared call
  and every declared call is made; splitting into parts. The fixtures are
  written by hand, not recorded from real clusters. Traefik: without the
  parameter no Traefik call and an identical record; the current group, the
  legacy group, both; not installed, forbidden, item limit; option
  resolution; host parsing.
- Job (`internal/deviceagent/devices`): the dispatch, the refusals (credentials,
  another cluster, not negotiated, not in a cluster), parts.
- Manifest (`shared/kubeinventory/manifest_test.go`): the role in
  `deploy/kubernetes/vista-agents.yaml` compared with the calls the collector
  makes, in both directions (a call the role does not grant fails, a grant
  nothing calls fails), no wildcard, no subresource, no verb but `get` and
  `list`; the opt-in role grants `list secrets` and nothing else; the sensor
  is bound to nothing; both pods run as an unprivileged user on a read-only
  root with no capability.
- A real cluster (`scripts/test-kubernetes.sh`, the `kubernetes` job of the
  pull-request gate): the images built from the checkout, in a kind cluster,
  under the restricted Pod Security Standard; what the API server says each
  service account may and may not do; a collection made in a pod by the
  device agent's service account, validated against the schema, with and
  without the TLS Secrets opt-in, and with Traefik asked for (kind has none,
  so it answers not installed); removal. It does not cover enrollment with
  a platform, a scan job, or any distribution but kind's kubeadm.
