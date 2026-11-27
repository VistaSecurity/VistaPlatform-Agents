# The agents in a Kubernetes cluster

Two agents, deployed together into a cluster from one manifest:

- the **device agent** reads the cluster's own API and reports what the
  cluster *declares* about its cryptography: workloads and their ports,
  Services, TLS on Ingress and Gateway listeners, cert-manager, service-mesh
  mTLS policy, and the certificates of the control plane and the admission
  webhooks;
- the **sensor** scans what the cluster *runs*: the platform turns the device
  agent's inventory into scan jobs, and the sensor reports what actually
  answers on each port and with which protocol, cipher suites and certificate.

Both report to your Vista Platform. Nothing here contacts anything else.

This page covers installing them, exactly what is read and what never is, the
optional reading of TLS Secrets, verifying the images, and removing it all.
The record the device agent returns is described in
[`../design/kubernetes-inventory.md`](../design/kubernetes-inventory.md).

## What you need

- A cluster you administer (`kubectl` with rights to create a namespace and a
  ClusterRole), with `linux/amd64` or `linux/arm64` nodes. The manifest uses
  the Pod Security admission labels of Kubernetes 1.25 and later; it is tested
  on Kubernetes 1.34.
- A default StorageClass (or one you name): each agent keeps its identity on a
  64 MiB volume.
- A Vista Platform the cluster's pods can reach over HTTPS, and from its
  console (**Discovery → Sensors & Agents**) two registration keys: one for a
  device agent, one for a sensor.
- The images of the release you are installing, by digest (below).

Your platform's console may offer this manifest already filled in. What
follows is the same thing by hand.

## Install

**1. Verify the release and take the image references from it.** A tagged
release pushes the two images to `ghcr.io/vistasecurity/` and lists their
digests in its signed `agents-release.json`
([`../verify-release.md`](../verify-release.md), "Container images"):

```sh
TAG=v6.2.0     # example: the release you are installing
gh release download "$TAG" --repo VistaSecurity/VistaPlatform-Agents \
  --pattern agents-release.json --pattern agents-release.json.sigstore.json
cosign verify-blob --bundle agents-release.json.sigstore.json \
  --certificate-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  agents-release.json
jq -r '.images[] | .registry.reference' agents-release.json
```

**2. Fill in the manifest.** From a checkout of this repository at that tag:

```sh
node scripts/render-kubernetes-manifest.mjs --release agents-release.json \
  --platform-url https://vista.example.com > vista-agents.yaml
```

or edit [`deploy/kubernetes/vista-agents.yaml`](../../deploy/kubernetes/vista-agents.yaml)
yourself: the two `image:` lines (use the `...@sha256:...` references from
step 1, never a tag alone) and the Secret at the end.

**3. Put in the two registration keys.** In the Secret at the end of
`vista-agents.yaml`, replace the values marked `REPLACE`:

| Key | Value |
|---|---|
| `platform-url` | your platform's address, `https://...` |
| `device-agent-registration-key` | the device agent's registration key |
| `sensor-registration-key` | the sensor's registration key |
| `platform-ca-fingerprint` | only if your platform's certificate is signed by a private CA: the SHA-256 fingerprint of that CA's certificate. Otherwise leave it empty |

A registration key is used once, at the agent's first start. After that the
agent's identity (a private key it generated itself, and the certificate the
platform issued for it) is on its volume, with the configuration file that
names it (`agent-config.yaml` or `sensor-config.yaml`, mode 0600), and the
registration key is of no use to anyone. A replaced pod (a restart, an upgrade,
a node drain) reads that file and is the same agent; it does not present the
key again. You may then delete the two keys from the Secret. If the platform
refuses the stored identity (the agent was deleted in the console), the pod
keeps running and its heartbeats fail; it does not try the spent key. To
enroll it again, delete its PersistentVolumeClaim (which holds the old
identity), put a new key in the Secret, and apply the manifest again.

**4. Read what you are about to grant, then apply.** The whole of it is the
`ClusterRole` in the file, and it is short enough to read:

```sh
kubectl apply -f vista-agents.yaml
kubectl -n vista-agents get pods
kubectl -n vista-agents logs deployment/vista-device-agent
kubectl -n vista-agents logs deployment/vista-sensor
```

Both agents appear under **Discovery → Sensors & Agents** within a minute or
two. The platform then asks the device agent for an inventory on its own
schedule and sends the sensor its scans.

**If a pod does not stay up**, its log says why in the first lines:

| The log says | Do this |
|---|---|
| Registration was REJECTED: the key is invalid, expired or already used | Generate a new key in the console, put it in the Secret, `kubectl -n vista-agents rollout restart deployment/<name>` |
| certificate signed by unknown authority | Your platform uses a private CA: set `platform-ca-fingerprint` |
| cannot store its enrollment | The volume is not writable by user 65532. Nothing was sent; the key is still good |
| the pod is `Pending` | The PersistentVolumeClaim is unbound: the cluster has no default StorageClass. Add `storageClassName` to the two claims |

## What the device agent reads

It uses the service account `vista-agents/vista-device-agent`, which is bound
to one ClusterRole. That role is everything the agent can do in your cluster:

| It may | On |
|---|---|
| `list` | namespaces, nodes, pods, services |
| `list` | deployments, statefulsets, daemonsets, replicasets, cronjobs, jobs |
| `list` | endpointslices, ingresses, ingressclasses, servicecidrs |
| `list` | Gateway API: gatewayclasses, gateways, httproutes, grpcroutes, tlsroutes, tcproutes |
| `list` | cert-manager: certificates, certificaterequests, issuers, clusterissuers |
| `list` | certificatesigningrequests |
| `list` | Istio peerauthentications and destinationrules; Linkerd servers and authorizationpolicies |
| `list` | validatingwebhookconfigurations, mutatingwebhookconfigurations, apiservices |
| `get` | three ConfigMaps by name: `istio-ca-root-cert`, `linkerd-identity-trust-roots`, `cilium-config` |
| `get` | `/version` |

A rule for something your cluster does not have (no cert-manager, no mesh)
matches nothing.

From each object the agent keeps a fixed list of fields and discards the
rest before anything is stored or sent. What it sends:

- names, namespaces, kinds, UIDs and creation times;
- container **images** and **declared ports**; the service account name;
  whether a pod uses the host network; the **names** of Secrets a pod mounts;
- Service types, addresses and ports, and which workloads are behind each;
- Ingress and Gateway hosts, whether TLS is configured and which Secret is
  named;
- cert-manager issuers' kinds and addresses, Certificates' names, lifetimes,
  key algorithm and size settings, and whether each is Ready;
- mesh mTLS policies and modes;
- **certificates** (public): those cert-manager issued, those in signing
  requests, webhook and aggregated-API CA bundles, mesh trust anchors, the
  cluster CA, and the ones the API server and the kubelets present;
- a short, fixed list of labels (`app.kubernetes.io/*`, `app`, `k8s-app`,
  topology and architecture labels, mesh injection labels). The platform can
  ask for more label keys by name; nothing else of your labels leaves the
  cluster;
- node facts: addresses, kubelet and runtime versions, OS image, kernel,
  provider id, machine id.

It also makes TLS handshakes, with two things only: the API server (the
connection it already has) and each node's kubelet port. Those handshakes are
verified against the cluster CA and send nothing. It does not scan your
Services or pods; the sensor does.

## What is never read

- **Secrets.** The default role does not mention them, and the agent does not
  call the Secrets API. (See "Reading TLS Secrets" for the opt-in.)
- **Private keys**, in any form, with or without the opt-in.
- **Environment variables, commands and arguments** of containers.
- **Annotations**, except a few it asks for by name: Linkerd's injection and
  inbound-policy settings on a namespace, the two markers kubeadm leaves on a
  node and on the API server's pod (used to recognise a kubeadm cluster, not
  sent), and, with the TLS Secrets opt-in, the name of the cert-manager
  Certificate a Secret belongs to.
- **ConfigMaps**, other than the three named above; from `cilium-config` only
  three encryption settings.
- **Logs**, and anything reached through `exec`, `attach`, `port-forward` or
  `nodes/proxy`.
- **Node and container filesystems, and image contents.** Certificates that
  exist only as files on a node (etcd, the scheduler, the controller manager)
  are reported as "not collected", never as absent.

The agent holds **no write permission of any kind** and cannot `watch`.

You can check the role against a live cluster at any time:

```sh
SA=system:serviceaccount:vista-agents:vista-device-agent
kubectl auth can-i --list --as "$SA"
kubectl auth can-i list secrets --all-namespaces --as "$SA"     # no
kubectl auth can-i create pods -n default --as "$SA"            # no
```

Every answer the platform shows for your cluster is one of three: read,
could not be read, or not available in this cluster. If you remove a rule
from the role, that part reads "could not be read: not permitted"; it does not
silently read as empty.

## What the sensor can do

In the Kubernetes API: **nothing**. Its service account has no token mounted
and no binding.

On the network: it opens connections to the addresses the platform's scan
jobs name (your Services and pods) and reports what answers. It does **not**
capture traffic: the image is built without packet capture, opens no
interface, and needs no capability. Passive capture in a cluster would need a
privileged pod on every node and is not part of this. Nor does it report its
own host, as a sensor on a machine does: its host is its pod, which would
otherwise appear in the inventory as a server, a new one after every pod
replacement.

Two things change what the sensor can see, and both are reported as what
they are rather than as "no TLS":

- **A default-deny NetworkPolicy** makes a namespace look silent. To have it
  scanned, apply
  [`networkpolicy-allow-sensor.yaml`](../../deploy/kubernetes/networkpolicy-allow-sensor.yaml)
  in that namespace: it admits the sensor's pods and nothing else.

  ```sh
  kubectl -n <namespace> apply -f deploy/kubernetes/networkpolicy-allow-sensor.yaml
  ```

- **A service mesh in strict mode** answers with the sidecar's certificate,
  not the application's.

To install the device agent alone, delete the sensor's Deployment, service
account and PersistentVolumeClaim from the manifest before applying it. You
get what the cluster declares, without the check of what actually answers.

## How the pods run

Both, as the manifest sets them and as the namespace's `restricted` Pod
Security label enforces:

- user and group 65532, never root; no privilege escalation; every Linux
  capability dropped; the default seccomp profile;
- a read-only root filesystem. The only writable paths are the agent's own
  volume (`/var/lib/vista`, its identity) and an in-memory `/tmp`;
- no host network, host PID, host path or privileged container;
- no listening port. Neither agent accepts a connection; every connection is
  one it opens. [`networkpolicy-agents.yaml`](../../deploy/kubernetes/networkpolicy-agents.yaml)
  (optional) denies all traffic into the namespace to make that a rule.

The images hold one static executable each and no shell, package manager or
operating system files, so there is nothing in them to `exec` into and
nothing to patch but the agent.

## Reading TLS Secrets (optional, off by default)

Without it you already get every certificate that is *served* (the sensor
sees it), every certificate cert-manager issued, and the names of the Secrets
that Ingresses, Gateways, issuers and pods refer to. What you do not get is
certificates that are stored in a Secret and used by nothing the sensor can
reach.

To add those, a cluster administrator applies one more file:

```sh
kubectl apply -f deploy/kubernetes/tls-secrets-opt-in.yaml
kubectl -n vista-agents rollout restart deployment/vista-device-agent
```

**Understand what this grants before you apply it.** Kubernetes cannot grant
"the certificate but not the key", nor "only Secrets of type
`kubernetes.io/tls`". Permission to list Secrets is permission to read every
Secret, private keys included, wherever the role is bound. What limits the
agent is the agent itself:

- it asks the API server for Secrets of type `kubernetes.io/tls` only, with a
  field selector, so no other Secret is sent to it;
- it decodes the `tls.crt` and `ca.crt` entries and nothing else. The
  `tls.key` entry is never decoded into a value, so it cannot be parsed,
  hashed, logged or sent;
- the record it returns has no place to put a key.

That is a property of this code, which is open and tested (a test serves a
Secret with a known key and proves the key is nowhere in the result). It is
not a property your cluster can enforce. If your policy is that no
third-party workload may hold permission to read Secrets, do not apply this
file.

To limit it to some namespaces, delete the `ClusterRoleBinding` from the file
and bind the role per namespace instead:

```sh
kubectl -n <namespace> create rolebinding vista-device-agent-tls-secrets \
  --clusterrole=vista-device-agent-tls-secrets \
  --serviceaccount=vista-agents:vista-device-agent
```

The platform then shows, per namespace, whether its TLS Secrets could be
read. (The agent first asks for all namespaces, is refused, and asks each
namespace in turn, so your audit log will show one refused request per
collection for the cluster and for each namespace that is not bound.)

Only the cluster can turn this on. The platform cannot: there is no job
parameter for it, and the agent does not call the Secrets API unless the
setting in that file is present in its own environment. The platform shows
which mode each agent reports.

To turn it off: `kubectl delete -f deploy/kubernetes/tls-secrets-opt-in.yaml`
and restart the deployment.

## Verifying the images

Described in full in [`../verify-release.md`](../verify-release.md),
"Container images". In short:

- take the image digests from an `agents-release.json` whose signature you
  verified (step 1 above), and refer to the images by digest;
- each image in the registry is signed by digest with the same identity as
  the release:

  ```sh
  cosign verify ghcr.io/vistasecurity/vista-device-agent@sha256:<digest> \
    --certificate-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$TAG" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- if your clusters may not pull from `ghcr.io`, each release also carries the
  same images as files (`vista-device-agent_<version>_linux.oci.tar`,
  `vista-sensor_<version>_linux.oci.tar`), signed like every other file of
  the release, to copy into a registry of your own. The digest does not
  change.

A cluster policy that admits only signed images checks the identity and
issuer shown above.

## One collection by hand, without a platform

The same collector runs once and writes what it would send, with no platform
involved: a way to see exactly what leaves the cluster before you enroll
anything. Run it as a Job under the device agent's service account, with the
same security settings as the Deployment:

```yaml
apiVersion: batch/v1
kind: Job
metadata: {name: inventory-once, namespace: vista-agents}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: vista-device-agent
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: collect
          image: <the device agent image>
          args: ["kubernetes-inventory", "--format", "jsonl", "--quiet"]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
          volumeMounts: [{name: tmp, mountPath: /tmp}]
      volumes: [{name: tmp, emptyDir: {}}]
```

```sh
kubectl apply -f inventory-once.yaml
kubectl -n vista-agents wait --for=condition=complete job/inventory-once
kubectl -n vista-agents logs job/inventory-once > cluster.jsonl
jq 'select(.kind == "kubernetes_inventory") | .data.sections' cluster.jsonl
kubectl -n vista-agents delete job inventory-once
```

The flags and the output are in [`../standalone.md`](../standalone.md) and
[`../standalone-output.md`](../standalone-output.md).

## Upgrading

Change the two `image:` references to the new release's digests and apply the
manifest again. Each agent keeps its identity (it is on its volume); do not
change the registration keys. Apply the new release's manifest as a whole
rather than only the images: a release that reads something new says so in
its role.

## Removing

```sh
kubectl delete -f deploy/kubernetes/tls-secrets-opt-in.yaml --ignore-not-found
kubectl delete -f vista-agents.yaml
```

That removes the namespace (with both agents, their volumes and the Secret),
the ClusterRole and its binding. If you applied
`networkpolicy-allow-sensor.yaml` in other namespaces, remove it there:

```sh
kubectl delete networkpolicy --all-namespaces --field-selector metadata.name=allow-vista-sensor-scan
```

Nothing else was created: no CustomResourceDefinition, no webhook, no
DaemonSet, nothing on your nodes.

What the platform already recorded about the cluster stays there until you
archive it; delete the two agents in the console (**Discovery → Sensors &
Agents**) so they are not shown as offline.

## What this does not do yet

- Look inside containers, images or node filesystems.
- Capture traffic in the cluster.
- Read a cluster from outside it: the agent describes the cluster it runs in,
  and takes no kubeconfig.
- Install from a Helm chart.
