#!/usr/bin/env bash
# Run the agents in a real Kubernetes cluster (kind) and check what only a
# real API server can show: that the manifest applies under the "restricted"
# Pod Security Standard, that the role it grants is enough for the collector
# and grants nothing else that was asked of it, and that the collection the
# agent's image produces in a pod is a valid one.
#
#   scripts/test-kubernetes.sh
#
# Needs docker, kind, kubectl, go, node, jq and openssl. It builds the images
# from this checkout (nothing is pulled but kind's node image), creates a
# cluster named vista-agents-test-<pid>, and deletes it when it ends; set
# KEEP_CLUSTER=1 to keep it for a look around. KIND_NODE_IMAGE picks the node
# image (default: kind's own).
#
# What it does not show: enrollment with a platform, a scan job, or anything
# about a managed cluster (EKS, AKS, GKE) or a distribution other than kind's
# kubeadm.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
for tool in docker kind kubectl go node jq openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "test-kubernetes.sh: $tool is not installed" >&2; exit 2; }
done

cluster="vista-agents-test-$$"
work=$(mktemp -d)
ns=vista-agents
k() { kubectl --context "kind-$cluster" "$@"; }
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- test-kubernetes.sh failed (exit $status); cluster state:" >&2
    k -n "$ns" get pods,jobs,pvc -o wide >&2 2>/dev/null || true
    k -n "$ns" get events --sort-by=.lastTimestamp 2>/dev/null | tail -20 >&2 || true
  fi
  if [ "${KEEP_CLUSTER:-}" = 1 ]; then
    echo "keeping cluster $cluster (kind delete cluster --name $cluster)" >&2
  else
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "Build the images from this checkout"
arch=$(go env GOARCH)
scripts/build.sh device-agent "linux-$arch" container
scripts/build.sh sensor "linux-$arch" container
node scripts/dev-images.mjs --out "$work" --arch "$arch" --repository localhost/vista --version dev
agent_image=localhost/vista/vista-device-agent:dev
sensor_image=localhost/vista/vista-sensor:dev

step "Create the cluster"
create=(kind create cluster --name "$cluster" --wait 180s)
[ -z "${KIND_NODE_IMAGE:-}" ] || create+=(--image "$KIND_NODE_IMAGE")
"${create[@]}"
kind load image-archive "$work/vista-device-agent.oci.tar" --name "$cluster"
kind load image-archive "$work/vista-sensor.oci.tar" --name "$cluster"
k version -o json | jq -r '"server " + .serverVersion.gitVersion'

step "Apply the manifest (the namespace enforces the restricted Pod Security Standard)"
node scripts/render-kubernetes-manifest.mjs --device-agent-image "$agent_image" --sensor-image "$sensor_image" \
  --platform-url https://platform.invalid > "$work/vista-agents.yaml"
k apply -f "$work/vista-agents.yaml"
k apply -f deploy/kubernetes/networkpolicy-agents.yaml
k -n default apply -f deploy/kubernetes/networkpolicy-allow-sensor.yaml

step "What the API server says each service account may do"
agent_sa="system:serviceaccount:$ns:vista-device-agent"
sensor_sa="system:serviceaccount:$ns:vista-sensor"
can() { k auth can-i --as "$1" "${@:2}" 2>/dev/null || true; }
expect() { # expect yes|no SA args...
  got=$(can "$2" "${@:3}")
  [ "$got" = "$1" ] || fail "can-i ${*:3} as $2: $got, want $1"
  echo "  $1: ${2##*:} ${*:3}"
}
for r in namespaces nodes pods services deployments.apps statefulsets.apps daemonsets.apps replicasets.apps cronjobs.batch jobs.batch \
         endpointslices.discovery.k8s.io ingresses.networking.k8s.io certificatesigningrequests.certificates.k8s.io \
         validatingwebhookconfigurations.admissionregistration.k8s.io apiservices.apiregistration.k8s.io; do
  expect yes "$agent_sa" list "$r" --all-namespaces
done
expect yes "$agent_sa" get configmap/cilium-config -n kube-system
expect yes "$agent_sa" get /version
for denied in "list secrets --all-namespaces" "get secret/x -n kube-system" "list configmaps --all-namespaces" "get configmap/kubeadm-config -n kube-system" \
              "watch pods --all-namespaces" "get pods -n kube-system" "create pods -n $ns" "delete pods -n $ns" "create pods/exec -n kube-system" "get pods/log -n kube-system" \
              "get nodes/proxy" "patch deployments.apps -n $ns" "list roles.rbac.authorization.k8s.io --all-namespaces" "impersonate serviceaccounts -n $ns" \
              "create tokenreviews.authentication.k8s.io" "list persistentvolumes" "list networkpolicies.networking.k8s.io --all-namespaces"; do
  # shellcheck disable=SC2086 # a list of words
  expect no "$agent_sa" $denied
done
for denied in "list pods --all-namespaces" "list namespaces" "list secrets -n $ns" "get configmap/cilium-config -n kube-system" "list nodes"; do
  # shellcheck disable=SC2086
  expect no "$sensor_sa" $denied
done

# One collection, as a Job that runs the agent's image as the agent's service
# account with the Deployment's security settings. The output is the Job's log.
collect() { # collect NAME EXTRA_ENV_VALUE
  cat <<JOB | k apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: {name: $1, namespace: $ns}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: vista-device-agent
      enableServiceLinks: false
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: collect
          image: $agent_image
          args: ["kubernetes-inventory", "--format", "jsonl", "--quiet"]
          env: [{name: VISTA_KUBERNETES_READ_TLS_SECRETS, value: "$2"}]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
          volumeMounts: [{name: tmp, mountPath: /tmp}]
      volumes: [{name: tmp, emptyDir: {}}]
JOB
  if ! k -n "$ns" wait --for=condition=complete "job/$1" --timeout=180s >/dev/null; then
    k -n "$ns" logs "job/$1" --tail=40 >&2 || true
    fail "the collection job $1 did not complete"
  fi
  k -n "$ns" logs "job/$1" > "$work/$1.jsonl"
  jq -e -s 'map(select(.kind == "kubernetes_inventory")) | length == 1' "$work/$1.jsonl" >/dev/null || fail "$1: no kubernetes_inventory record in the output"
}

step "Collect with the default role"
collect inventory-default false
VISTA_KIND_INVENTORY="$work/inventory-default.jsonl" go test -count=1 -run 'TestKindCollection' ./shared/kubeinventory/

step "Collect with the opt-in role: a TLS Secret's certificate, never its key"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=stored.example.test" \
  -keyout "$work/tls.key" -out "$work/tls.crt" >/dev/null 2>&1
k -n default create secret tls stored-not-served --cert "$work/tls.crt" --key "$work/tls.key" >/dev/null
k -n default create secret generic not-a-certificate --from-literal=password=opaque-secret-value >/dev/null
k apply -f deploy/kubernetes/tls-secrets-opt-in.yaml
expect yes "$agent_sa" list secrets --all-namespaces
expect no "$agent_sa" get secret/stored-not-served -n default
expect no "$sensor_sa" list secrets --all-namespaces
collect inventory-opt-in true
VISTA_KIND_INVENTORY="$work/inventory-opt-in.jsonl" VISTA_KIND_TLS_KEY="$work/tls.key" VISTA_KIND_TLS_CERT="$work/tls.crt" \
  go test -count=1 -run 'TestKindCollection' ./shared/kubeinventory/
# With the role still bound but the setting off, the agent does not use it.
collect inventory-role-without-setting false
jq -e -s 'map(select(.kind == "kubernetes_inventory"))[0].data | .sections.tls_secrets.reason == "not_enabled" and (.tls_secrets // [] | length) == 0' \
  "$work/inventory-role-without-setting.jsonl" >/dev/null || fail "TLS Secrets were read without the setting"

step "Both agents start under the manifest's security settings"
# There is no platform here, so neither can enroll; what is shown is that the
# pods are admitted, start as the image's user on a read-only root, find their
# data volume writable, and get as far as trying to register.
deadline=$((SECONDS + 180))
for app in vista-device-agent vista-sensor; do
  until k -n "$ns" logs "deployment/$app" --tail=200 2>/dev/null | grep -qi 'regist'; do
    [ "$SECONDS" -lt "$deadline" ] || { k -n "$ns" describe pod -l "app.kubernetes.io/name=$app" | tail -30 >&2; fail "$app did not start"; }
    sleep 3
  done
  logs=$(k -n "$ns" logs "deployment/$app" --tail=200 2>/dev/null || true)
  if echo "$logs" | grep -qiE 'cannot store its enrollment|read-only file system|permission denied'; then
    echo "$logs" | tail -20 >&2; fail "$app could not use its data volume"
  fi
  echo "  $app started and tried to register"
done
k -n "$ns" logs deployment/vista-sensor --tail=200 | grep -q 'Passive capture is off' || true
uid=$(k -n "$ns" get pods -l app.kubernetes.io/name=vista-sensor -o json | jq -r '.items[0].spec.securityContext.runAsUser')
[ "$uid" = 65532 ] || fail "the sensor pod runs as $uid"
[ "$(k -n "$ns" get pods -l app.kubernetes.io/name=vista-sensor -o json | jq -r '.items[0].spec.automountServiceAccountToken')" = false ] || fail "the sensor pod mounts a service-account token"

step "Removal leaves nothing behind"
k delete -f deploy/kubernetes/tls-secrets-opt-in.yaml >/dev/null
k delete -f "$work/vista-agents.yaml" --wait=true --timeout=120s >/dev/null
left=$(k get clusterrole,clusterrolebinding -o name | grep -c vista- || true)
[ "$left" = 0 ] || fail "$left cluster-scoped object(s) named vista- remain"
k get namespace "$ns" >/dev/null 2>&1 && fail "namespace $ns remains"

printf '\ntest-kubernetes.sh: passed\n'
