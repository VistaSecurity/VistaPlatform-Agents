# Managed protocol, version 1

The passive sensor and the device interrogation agent talk to a Vista Platform
control plane over one written contract: **managed protocol version 1**. This
page says what that contract is, what an operator sees when an agent and a
platform do not share it, and how it is tested.

The message schemas are in [`schemas/managed/v1/`](../schemas/managed/v1/)
(JSON Schema 2020-12), one per message, with the certificate entry and the
discovery envelope under `defs/` and the platform's vocabularies under
`enums/`. Synthetic examples of every message, and of the answers an agent must
refuse, are in [`fixtures/managed/v1/`](../fixtures/managed/v1/).

What an agent sends is closed: a field its schema does not name is an error,
so an agent cannot drift from the published contract unnoticed. What the
platform answers is open to fields an agent does not know, which it ignores;
the fields an agent acts on are typed, and the rules below (a protocol object,
no private key, sealed credentials, the scan plan as the only job shape) are
enforced whatever else an answer carries.

## The shape of it

- **HTTPS and JSON, agent to platform only.** The platform never connects to an
  agent. TLS 1.2 or later; the agent verifies the platform against the anchor
  its operator approved at setup and never disables verification.
- **Enrollment with a key that never leaves the host.** The agent generates its
  key pair, proposes its id, and sends a certificate signing request with the
  single-use registration key. The platform signs the request and answers with
  the client certificate, the platform CA, a per-agent secret and, when it has
  a dedicated agent endpoint, that endpoint's URL. There is no enrollment
  without a CSR and the platform never generates or returns an agent's private
  key: an answer carrying one is refused.
- **Mutual TLS on every later call.** The agent presents the certificate it was
  issued; the platform checks it is that agent's current certificate.
- **Heartbeats carry desired state.** The heartbeat answer carries the
  configuration the agent should run, the sensor's commands (including
  discovery jobs) and the networks the tenant owns, which the sensor checks
  before it probes anything.
- **Discovery jobs are scan plans.** A sensor discovery job carries a per-target
  scan plan; it is the only job shape. The older "protocols × ports" payload is
  not part of version 1 and is refused.
- **Credentials travel sealed.** A device-agent job's credentials are an
  envelope: AES-256-GCM under a key derived from the job id and the agent's
  secret. The agent refuses a plaintext credentials map and derives no key
  without its agent secret.
- **Results keep the formats the platform reads.** Certificates ride in the one
  certificate format (`defs/certificate.json`); a sensor discovery is the
  metadata envelope (`defs/envelope.json`). Everything a device collector
  returns has passed the agent's projection allowlists and redaction before it
  is sent: the agents collect posture, never key material.
- **Certificate rotation** happens when the client certificate has under 30 days
  left: a fresh key, a new certificate, a new agent secret, and the old
  certificate is revoked.

## Version and capabilities

Every request names the protocol in a header:

    Vista-Agent-Protocol: 1

The registration request also carries the agent's kind and offer:

    "agent_kind": "sensor",
    "protocol": {"version": 1, "capabilities": ["identity_dns_v1", "scan_plan_v1", "verify_certificate_v1"]}

Every registration, heartbeat and job answer names the platform's protocol in
the same object, with the capabilities the platform will use with this agent.
An answer without a body (the device agent's empty job poll, `204`) carries
them in the header: `Vista-Agent-Protocol: 1; capabilities=device_discovery`.

The agent keeps the intersection of its capabilities and the platform's.
Capabilities are additive: an unknown one is ignored by both sides. Work whose
capability was not negotiated, and any command or job type the agent does not
run, is acknowledged as refused with the code `unsupported_command`; nothing is
run.

The integer is a major version. Additive features are capabilities; a new
major version is a new schema directory (`v2/`), and `v1/` is never changed
incompatibly once released. Matching release numbers of an agent and a
platform are not evidence that they work together; only the tested pairs
published with each platform release are.

## When an agent and a platform do not share version 1

Both sides fail closed. Nothing is guessed.

**The platform refuses the agent** with `426 Upgrade Required`:

    {"code": "agent_protocol_unsupported", "agent_protocol": 2, "supported": [1],
     "message": "This agent speaks managed protocol 2; this platform (version X) supports 1. Install the agent version listed under Discovery -> Sensors & Agents."}

No job is handed out and nothing is ingested. The console shows the agent as
incompatible rather than offline.

**The agent refuses the platform** when an answer names no protocol (a platform
that predates version 1), names another version, or is a 426. It then runs no
job, submits no result and applies no configuration, and logs one line:

    platform speaks managed protocol 2; this agent supports 1; nothing will be collected until the agent or the platform is changed

The next heartbeat it can send carries that line as `protocol_error`, and the
agent keeps heartbeating, so a platform that is changed to version 1 is picked
up on its next answer without a restart.

**At enrollment** the same refusal, or an answer that breaks version 1 (a
private key in it, or no agent secret), stops the agent with exit status 78
(`EX_CONFIG`). The installers' service units do not restart on 78, so the agent
does not hammer the platform with a key it cannot use. What to do: install the
agent version the platform lists under **Discovery → Sensors & Agents**, or
upgrade the platform, and generate a new registration key if the old one was
spent.

## How it is tested

In this repository, with no platform and no network:

- `internal/testsupport/protocolschema` validates every fixture against its
  schema: each `valid*` and `refused*` fixture must validate, each `invalid*`
  fixture must not, every schema needs a valid fixture, every fixture needs a
  schema, and a `$ref` that leaves `schemas/managed/v1/` does not compile.
- `internal/testsupport/fakeplatform` is an in-process platform for tests: it
  enrolls agents with a CA generated at test time, requires mTLS afterwards,
  hands out commands and jobs, takes results and rotates certificates. It
  validates everything an agent sends against the schemas and, while it
  behaves, everything it answers; it can be told to misbehave (no protocol,
  version 2, 426, a private key or no secret in the enrollment answer,
  unsealed credentials). The agents' real clients are tested against it for
  every flow and every refusal.

Both run in `go test ./...`, which the pull-request gate runs.

The platform's side of the contract is tested privately: the platform vendors
a pinned copy of these schemas and holds its own handlers to them, and the
exact released agent binaries are qualified against fresh platform deployments
before a pairing is published. The fake platform here stands in for none of
that.
