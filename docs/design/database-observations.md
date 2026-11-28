# Fact-only database observations for Vista Platform 7

**Status:** AG7-F2 implementation contract. This work is paired with Vista
Platform VP7-DB. Neither repository may ship this slice alone, and neither
repository publishes a tag or release as part of this work.

## Purpose

The database collector measures a SQL session and a bounded set of server
settings. It does not judge those facts. `risk_score`, weak/strong labels and
compliant/noncompliant labels are removed at the source. Platform policy tests
own all judgment.

The existing generic asset metadata is insufficient for managed collection:
Platform stores it as discovery detail but does not materialize it into
`database_encryption_states`. AG7-F2 therefore adds a typed
`database_observations` result field. The companion Platform implementation
validates it against the authenticated job and writes the same canonical store
as the in-cluster collector.

## Contract

One database job emits at most one observation in v7. The wire remains an
array with `maxItems: 1` so the schema can reject oversized input; support for
multiple instances in one job is deferred and is not implied by the array.

Each measured fact is a closed typed value with one state:

- `measured`: `value` is required, including an observed `false`;
- `unknown`: the collector has no answer and did not receive a query failure;
- `query_error`: the collector attempted the measurement and the query failed;
- `unsupported`: this engine or collector cannot make the measurement.

For the last three states, `value` is forbidden. Missing evidence is never
zero-coerced. A query failure also produces a bounded, redacted collection
warning so operators can distinguish permission, unsupported query, timeout
and other errors without receiving a DSN, credential or raw server error.

The v7 observation fields are server version, session TLS in use, negotiated
TLS version, session cipher, TLS enforcement, broad at-rest encryption state,
encryption method/algorithm and password-encryption default. Names state their
scope: `session_tls_in_use` describes the collector's SQL session. It never
claims that the server requires TLS. `password_encryption_default` describes
the configured default for newly set passwords. It never claims every stored
password uses that method.

The payload carries engine and port only as target assertions. It carries no
tenant id or asset id. Platform derives tenant, asset, engine, host and port
from the authenticated job and rejects an observation whose engine or port
does not equal that target. The agent cannot choose a different database
instance by changing its result. Managed v1 emits an empty `instance_name`;
Platform rejects a non-empty value until a future job contract explicitly
authorizes multiple instances.

Bounds are part of the contract: one observation; port 1-65535; host and
instance name at most 255 characters; version at most 512; algorithm/method
and TLS strings at their Platform column limits; no more than the documented
raw-setting keys; primitive raw-setting values only; and at most 16 KiB of raw
settings after JSON encoding. Unknown fields, unknown engines, invalid state /
value combinations and unallowlisted raw settings are rejected.

## Raw settings and redaction

Raw settings are a factual, bounded diagnostic projection, not the query
response. PostgreSQL retains only version, session TLS facts and the enumerated
`pg_settings` names used by the collector. MySQL retains only version,
session-TLS facts and an explicit variable allowlist that includes
`require_secure_transport`; the collector does not issue a wildcard settings
query.

The collector filters keys, bounds values and then applies `redact.Map` before
building the observation. Vista Platform repeats allowlist, bound and
redaction checks at ingest. DSNs, SQL error text, credentials, certificate or
private-key paths, and arbitrary vendor variables are never emitted.

## Measurement limits

PostgreSQL session TLS comes from the current backend's `pg_stat_ssl` row. The
former `sslinfo` functions were optional, and `SELECT ssl_cipher(), version()`
did not measure a TLS version. `pg_settings.ssl` is configuration, not
enforcement. This slice does not parse `pg_hba.conf` and cannot observe storage
or filesystem encryption; enforcement and broad at-rest state are
`unsupported`. `password_encryption` is retained only as the password default.

MySQL session TLS comes from current-session status and is separate from
`have_ssl` / `have_openssl` capability and the configured `tls_version` list.
`require_secure_transport` measures enforcement when available. Default table,
InnoDB and binlog encryption settings describe defaults or components, not
every existing table. They remain named raw facts; broad at-rest state stays
unknown unless a bounded instance-wide measurement is added. MySQL password
hashing is not measured by this collector.

Neither engine path collects the database server certificate. A successful
login describes one collector session at one time, not every application
connection or every instance in an estate.

The collector emits a generic TLS crypto asset only when the current session
is measured as using TLS. A false, unknown, query-error or unsupported session
state emits only the typed database observation; it never invents a generic
`SQL` protocol asset or treats missing evidence as plaintext.

## Identity, replay and freshness (Platform companion)

The canonical instance is `(tenant, job asset, lower(engine), effective port,
trimmed, case-preserved instance name)`. Database instance names can be
case-sensitive. The effective port is the job's explicit port or
the engine default; AG7-F2 must honor `DeviceInfo.Port` in its DSN. Hostname is
mutable display data and is not identity. The current collectors do not
enumerate database/catalog names; the PostgreSQL login database is not an
instance name.

Platform keeps facts in `database_encryption_states` and durable receipt
identities in a receipt table. Receipt uniqueness is observation/job plus the
canonical instance. Receipt insertion and the conditional current-state
upsert occur in one transaction. This is required because a single
`last_observation_id` cannot reject A, B, replay A. The current row also orders
distinct observations by server-owned job start/create time, with job id as a
deterministic tie break, so a first-time late older result cannot replace a
newer one.

Receipts have no automatic retention in this slice. They are removed only with
their tenant. A future compactor must first define a durable replay watermark;
deleting receipts by age would silently weaken the guarantee and is forbidden.

A query error clears the current nullable value and records `query_error`.
That changes current evidence; it does not erase the last policy judgment.
Under the v7 result contract, an evaluator unable to evaluate records a
cannot-evaluate attempt and retains the prior pass/fail finding with its
freshness label. Only a subject with no prior judgment is not assessed. Policy
measurement codes and registry rows are a separate coordinated change.

That later measurement family must include every eligible current canonical
database instance in its subject population even when a fact is unknown,
unsupported or failed to query. Unknown/unsupported produce a not-assessed
reason; query error produces the cannot-evaluate overlay while retaining a
prior contributing failure. Filtering non-measured instances out would make
an incomplete collection look like an empty complete population. A coordinated
M-DB extension must add a typed `database_instance` subject with asset context
and filters before these four measurement codes can be registered. E1 remains
bounded to its existing subject types and 40 registry codes.

## AG7-F3 dead sensor model closure

The former `internal/sensor/models/asset.go` types (`Asset`,
`CryptoImplementation`, `RiskSummary`, `AssetFilters`, and `AssetsResponse`)
had no consumer: repository-wide symbol and qualified-import searches found
only declarations and self-reference in that file. AG7-F3 removes the entire
dead file. Live sensor wire types remain in `discovery.go`; the full build and
test gate protects that boundary.

## Rejections

Managed ingest rejects an observation when the job is not an authenticated
database interrogation, the job has no asset, engine or port differs from the
target, the array has more than one item, a bound is exceeded, a measured fact
lacks a value, a non-measured fact carries one, or raw settings violate their
engine allowlist. Rejection is visible in processing status and never degrades
to generic metadata ingestion as database assessment evidence.

## Acceptance shared by both repositories

- JSON schema accepts measured false and rejects every invalid state/value,
  bound, identity and raw-setting case above.
- Managed and standalone output retain session/configuration facts and contain
  no source `risk_score` or replacement verdict.
- PostgreSQL and MySQL tests distinguish session TLS from capability,
  configuration and enforcement; query failures are not false.
- Non-default target ports are used in the connection and result assertion.
- Platform tests prove A, B, replay A leaves B; concurrent duplicate receipt
  processing writes once; and receipt identity keeps two canonical instances
  independent even though the v7 managed wire admits one per job.
- Managed and in-cluster paths produce the same current row, preserve tenant
  isolation, and reject an agent-selected engine/port/asset.
- A current query error stores NULL plus `query_error`; later policy work proves
  cannot-evaluate retains the labelled prior finding.
- Agents `make check` and Platform's focused, integration and standards gates
  pass with Go exactly 1.26.11.
