# Managed protocol v1 fixtures

Synthetic examples of every message in `schemas/managed/v1/`, one directory per
message (named after the schema without `.schema.json`):

| File name | Meaning | Checked by the schema test |
|---|---|---|
| `valid*.json` | a message as protocol 1 sends it | must validate |
| `refused*.json` | well-formed, and an agent must refuse it (an unknown command or job type, a 426) | must validate; the client tests prove the refusal |
| `invalid*.json` | breaks protocol 1 (no protocol object, version 2, a legacy payload, unsealed credentials, a private key) | must not validate |

Content rules: documentation addresses only (RFC 5737, RFC 3849), the
`00:00:5e:00:53:xx` documentation MAC range, `example.test` names, made-up
UUIDs. PEM blocks here are placeholders, not certificates or keys; the tests
that need real ones generate them at run time. Nothing here was captured from a
network.

See [`docs/managed-protocol.md`](../../../docs/managed-protocol.md).
