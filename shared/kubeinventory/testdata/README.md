# Collector fixtures

`full/` is a synthetic cluster, written by hand in the shape of Kubernetes API
list answers: it was not recorded from a real cluster. The directory tree
mirrors API paths (`api/v1/pods.json` is served at `/api/v1/pods`) and is served
by `kubetest`.

It carries on purpose what the collector must leave behind: container
environment, commands and arguments, annotations, other ConfigMap keys, Secrets
that are not TLS Secrets, and a private key in every TLS Secret. Every such
value ends in `-secret-value`, and the tests fail if that text reaches a result.

Certificates, keys and ports are placeholders (`{{CERT:name}}`, `{{KEY:name}}`,
`{{CSR:name}}`, `{{PEM:name}}`, `{{PORT:name}}`) filled with material generated
when a test runs. Addresses are documentation ranges; names are
`example.test`.
