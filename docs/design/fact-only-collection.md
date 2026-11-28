# Fact-only collection for the v7 policy model

**Status:** AG7-F1 implemented; database and dead-model follow-ups remain
deferred. This change is intended for a fresh Vista Platform 7.0 deployment
paired with v7 agents. It does not define a 6.x upgrade bridge or authorize an
agent tag or release.

## Decision

Agents collect and identify evidence. Vista Platform policy tests judge that
evidence. Producers therefore emit protocol versions, algorithms, key sizes,
certificate fields and OT mechanisms without weak/strong, compliant/failing
or numeric-risk verdicts.

AG7-F1 removes these judgments at their source:

- certificate `cert_weak_signature` and `cert_weak_public_key` labels;
- passive TLS IEC 62351 compliant booleans, aggregate verdict, reason list and
  port-based applicability inference;
- the DNP3 and OPC UA generic `security` grade.

The standalone writer keeps an exact-key defensive scrub for retired fields so
legacy or mixed-version records cannot reintroduce them. The scrub preserves
`iec62351_applicable`, because that marker is a fact when the MMS/ICCP decoder
positively identifies the application protocol. It removes a legacy
`security: "weak"` value rather than rewriting it as `present` and inventing a
replacement strength.

## Evidence retained

| Domain | Retained facts | Boundary |
|---|---|---|
| TLS | negotiated version, cipher suite, key exchange/group, offered versions and ciphers | An IP port, including 443 or 8443, does not prove IEC 62351 applicability. |
| Certificates | signature algorithm, key algorithm, key size, fingerprint, chain order, validity, validation, SCT and OCSP facts | A missing field is not a passing threshold. Platform policy owns algorithm and size requirements. |
| DNP3 | `sa_active`, `sa_version`, `mac_algorithm_id`, `mac_algorithm_name`, `plaintext_dnp3`, transport | Secure Authentication proves an authentication mechanism was observed. It does not prove encryption or confidentiality. `sa_active=false` describes the decoded session, not an estate-wide absence. |
| OPC UA | full and short SecurityPolicy URI, OPN/HEL/ACK phase facts, sender certificate | A SecurityPolicy URI does not reveal `MessageSecurityMode`. Encryption remains unknown until the agent observes `SignAndEncrypt` or separate transport encryption evidence. |
| MMS/ICCP/S7 | decoded protocol and `iec62351_applicable=true` for MMS/ICCP | S7 and generic TLS do not inherit applicability from a port. |

## Managed and standalone seams

Managed sensor discovery uses `schemas/managed/v1/discovery-batch.schema.json`.
Its `raw_metadata` remains open, while the envelope keeps top-level protocol,
version, cipher and key-size facts. Standalone capture uses the same discovery
records and passes them through `shared/agentoutput`.

Vista Platform stores the discovery envelope and raw metadata, promotes typed
protocol and cryptographic facts during discovery processing, and persists
certificate details independently. No active policy evaluator requires the
removed certificate, IEC or OT grade fields. Companion Platform work must use
the retained facts rather than restore producer judgments.

## Companion Platform requirements

The Platform v7 OT measurement work must keep authentication and
confidentiality separate:

- DNP3 SA may support an authentication test. It must never satisfy an
  encryption test merely because `sa_active` is true.
- DNP3 MAC/version strength is a policy predicate over the exact retained
  facts.
- OPC UA policy tests may inspect the exact SecurityPolicy URI, while
  encryption stays not assessed without MessageSecurityMode or transport TLS
  evidence.
- affirmative plaintext evidence may fail a requirement; missing evidence is
  not assessed.

The companion Platform seams are the OT measurement shapes and policy
registry under `services/compliance-engine`, together with end-to-end storage
tests for `crypto_implementations.raw_data`. Platform's policy-judged v7 design
and release plan remain the authoritative assessment contract.

## Deferred packages

AG7-F2 removes the database collector's `risk_score` while retaining database
TLS, at-rest, password-method and redacted configuration facts. It must be
paired with a truthful Platform materialization seam that distinguishes
observed false from unknown.

AG7-F3 deletes unused numeric risk/compliance sensor model types after
coordination with the assigned dead-code owner. AG7-F1 does not modify those
files.

No package here publishes an agent tag, pairs a release, or deploys a partial
fact/judgment model.

## Verification

AG7-F1 is held by focused discovery, capture and standalone-output tests:

- generic TLS preserves negotiated facts and emits no IEC verdict or
  port-derived applicability;
- MMS/ICCP retains factual applicability through the existing decoder tests;
- DNP3 retains plaintext and exact SA/MAC facts without a generic grade;
- OPC UA retains full and short policy URI without a generic grade;
- standalone output preserves `iec62351_applicable` and exact evidence while
  scrubbing only retired judgment fields.

The repository gate is `make check`, which pins the exact Go version from
`go.mod` and runs with `GOWORK=off`.
