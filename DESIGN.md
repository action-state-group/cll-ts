# cll-ts design

Status: implementation contract for the initial TypeScript release.

## Purpose and ownership

`cll-ts` is an embeddable ESM-first TypeScript Checkpointed Local Log aligned
with the IETF CLL draft and the `checkpointed-local-log` 0.1.0 reference
package. It owns the MMR, proofs, checkpoint signing, exact-byte persistence,
and durable witness delivery with an application-neutral ordered entry
projection. Its AAC ledger binding owns admission
verification and gapless local sequence allocation. It does not own application
effects, outboxes, producer signer authorization, policy, guards, folds, agent
status, or viewers.

## Source baseline

| Repository               | Synchronized revision                      | Use                                                           |
| ------------------------ | ------------------------------------------ | ------------------------------------------------------------- |
| `cll-go`                 | `262de9704385303bcd2a9522e90bcd7a60b2786c` | Required store, ledger, CLL, checkpoint, and witness behavior |
| `capsule-emit-go`        | `280596e03070d6c3333224313fd6aa20b0cb992a` | Current Capsule and Producer Envelope boundary                |
| `agent-action-capsule`   | `7e112c8b877ad79d4d2a53be7b522a63470a2b1d` | Frozen format-4 verification and envelope corpora             |
| `capsule-emit`           | `40b592192e19622ff7a8c82674eb7caddb52e8db` | Released 0.7.0 producer and compatibility surface             |
| `checkpointed-local-log` | `f0f60baec7b19a2288de18283ffb715da0cdcd9c` | Released 0.1.0 CLL/MMR, checkpoint, and commitment vectors    |
| `capsule-ledger`         | `1a48c2adfd6018b1a5153824b4b389f8e7471fb7` | Python ledger semantics and excluded control-plane boundary   |
| `capsule-anchor`         | `8207b79ce2dd3eb1fce105d52162959e1d5aa680` | Current `/checkpoints` route and receipt contract             |

These revisions record the implementation baseline. CI interoperability jobs
intentionally test the current change against each peer repository's `main`.

## Parity matrix

| Go capability                            | TypeScript API                                          | Wire or durable behavior                                                                                                                                                              | Required coverage                                                                  | Intentional exclusion                      |
| ---------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------ |
| `ledger.Store`                           | `Store`                                                 | One narrow async interface for records, CLL state, and witness state                                                                                                                  | Shared backend contract                                                            | SQL handles and backend internals          |
| `Service.Append`                         | `LedgerService.append`                                  | Explicit signed/unsigned admission, exact bytes, atomic Capsule plus valid envelopes, gapless sequence                                                                                | Valid, invalid, duplicate, mode conflict, concurrency                              | Signer authorization                       |
| `Service.AddEnvelope`                    | `LedgerService.addEnvelope`                             | Verify and deduplicate exact envelope bytes without allocating sequence or MMR leaf                                                                                                   | Multiple signers and duplicate add                                                 | Authenticity upgrade                       |
| `Service.Audit`                          | `LedgerService.audit`                                   | All-or-nothing whole-ledger verification under a positive caller bound; rejects if any record lies beyond it; preserves attribution and store-level chain findings                    | Invalid and exceeded bounds, decode failure, missing parent, concurrent supersedes | Unbounded operator scans                   |
| `NewAACVerifier` and registry extensions | `verifyClass1` and `LedgerService` `registryExtensions` | Pinned complete baseline plus additive application values; preserves informational findings                                                                                           | Baseline drift and extension-copy tests                                            | Host replacement of mandatory verification |
| `Get`/`Scan`/`ScanIDs`                   | `get`/`scan`/`scanIds` plus `scanEntries`               | Exact AAC lookup plus application-neutral ordered CLL entry projection                                                                                                                | Empty, bounds, ordering, defensive copies                                          | Prefix lookup                              |
| JSONL store                              | `JsonlStore.open`                                       | Exclusive writer, fsync per complete line, restart replay, torn-tail truncation only                                                                                                  | Restart, partial tail, earlier corruption, lock                                    | Multi-process writers                      |
| SQLite store                             | `SqliteStore.open`                                      | WAL, foreign keys, immediate transactions, log-scoped uniqueness                                                                                                                      | Persistence and two-handle allocation                                              | Distributed sequencing                     |
| MySQL store                              | `MysqlStore.open`                                       | Metadata row lock, parameterized transactions, log-scoped uniqueness                                                                                                                  | MySQL 8 Testcontainer and concurrent allocation                                    | Provisioning databases                     |
| Example backend                          | `MemoryStore`                                           | Complete contract in memory for extension guidance                                                                                                                                    | Shared contract                                                                    | Production durability claim                |
| MMR                                      | `MmrTree`                                               | Go/Python leaf, parent, and peak-bagging domains                                                                                                                                      | Python KAT, multi-peak roots, malformed inputs                                     | Envelope association leaves                |
| Inclusion proof                          | `MmrTree.inclusionProof`, `verifyInclusion`             | Exact DataTrails layout: local mountain siblings, one already-bagged right-hand-peaks element only when a right peak exists, then left peaks in reversed position order nearest-first | Go/DataTrails proof vectors plus positive and tampered cases                       | Peak-accumulator proof formats             |
| Consistency proof                        | `consistencyProof`, `verifyConsistency`                 | Bridges prior and current peak commitments                                                                                                                                            | Non-first checkpoint vectors                                                       | Witness-side MMR validation claim          |
| Checkpoint                               | `signCheckpoint`                                        | Canonical JSON projection plus canonical COSE_Sign1 checkpoint record                                                                                                                 | Python/Go byte and parse vectors                                                   | Private-key discovery                      |
| Checkpoint runner                        | `CheckpointRunner.runOnce/run`                          | Durable indexing cursor, entry/age cadence, atomic pending witness rows, restart checks                                                                                               | Crash/restart, retry, stale cursor                                                 | Package-init background work               |
| `/checkpoints` client                    | `CapsuleAnchorClient.submit`                            | Raw COSE body, current route, bounded response, `legacy` entry hash scheme                                                                                                            | Request shape, 4xx, 429, 5xx, timeout                                              | Enrolled JSON submitter profile            |
| Delivery runner                          | `WitnessDeliveryRunner.runOnce/run`                     | Per-witness oldest-first durable retries and offline verification                                                                                                                     | success, rejection, timeout, retry, permanent failure                              | Trust-on-first-use                         |
| Receipt verifier                         | `ReceiptVerifier.verify`                                | Pinned Ed25519 authority and RFC 9162 inclusion proof                                                                                                                                 | Positive/tampered/pinned-key cases                                                 | Fetching trust material from server        |

## Store interface

`Store` is the public behavior contract for every backend. It contains:

- `append`, `addEnvelope`, `get`, `scan`, `scanIds`, `scanEntries`, and
  `findChainGaps`;
- `loadCll`, `commitCll`, `pendingWitnesses`, `getWitness`, and
  `commitWitness`;
- `close`.

The interface accepts already verified immutable DTOs and returns explicit
`inserted` or `idempotent` outcomes. Typed `LedgerError` codes distinguish
not-found, invalid input, immutable conflict, corruption, closed store, retryable
contention, and admission rejection.

Rebaseline is a separate optional Go interface and is not part of the required
storage contract or this first TypeScript release. `LedgerService.audit` and
mandatory `verifyClass1` admission sit above `Store`. The shipped durable
backends extend `MemoryStore` to reuse validation, idempotency, sequence
allocation, defensive copying, and CLL compare-and-swap behavior; a backend
implemented independently must reproduce those `Store` semantics.

The portable identifier rule is 1 to 191 UTF-8 bytes containing only
`A-Za-z0-9._:/-`. Shared hard limits match Go: Capsule 1 MiB, Producer Envelope
4,096 bytes, 64 envelopes per Capsule, 32 witnesses, signed checkpoint record
64 KiB, witness receipt 2 MiB, default scan
100, maximum scan or audit 1,000, and durable witness error text 4,096 bytes.
Checkpoint signing, parsing, and restart re-verification use the same 64 KiB
encoded-record limit.

## Admission and persistence invariants

- Capsule bytes are retained exactly and deduplicated by verified Capsule ID.
- A changed byte representation or admission mode is an immutable conflict.
- Signed admission considers explicit envelopes plus a well-formed embedded
  hexadecimal `signature`/`key_id` pair. An embedded candidate is valid only
  when `key_id` decodes to the same raw public key authenticated by the
  envelope's protected `kid`. Invalid candidates are ignored, but at least one
  must verify. Every distinct valid candidate is stored atomically.
- Unsigned admission rejects explicit envelopes and ignores embedded fields.
- A later envelope never changes authenticity, sequence, or CLL state.
- Successful new appends allocate contiguous 1-based sequences.
- All returned byte arrays are copies.
- Record, envelope, witness, and cadence times use JavaScript `Date` and persist
  in UTC at millisecond precision. A caller-provided RFC3339Nano checkpoint
  string preserves up to nine fractional digits in the signed record.

## Backend representation

JSONL stores complete version-3 events. It holds a non-blocking operating-system
advisory `flock` for the store lifetime, matching Go's immediate second-writer
rejection and kernel cleanup after process death. A lease or stale-timeout lock
is not equivalent and is not used. Relational stores use normalized
metadata keys and exact binary columns, with verification metadata serialized
as deterministic JSON. CLL nodes are insert-only and position-addressed.

SQLite write paths use `BEGIN IMMEDIATE`. MySQL locks the one metadata row for
the active `log_id` with `SELECT ... FOR UPDATE`. Every SQL value is bound as a
parameter. Result iterators and transactions are always closed through
`finally` paths.

Each relational read rebuilds one in-memory view from a single database
snapshot. SQLite wraps its metadata, record, envelope, node, and witness
queries in one read transaction. MySQL uses one connection and an explicit
`REPEATABLE READ` transaction for the same five queries. This prevents a
concurrent checkpoint from combining old metadata with new node rows. Durable
decode failures, orphaned envelope rows, and metadata/node-count disagreement
are reported as `LedgerError("corrupt")`. A MySQL store instance also serializes
its reads and writes so a refresh cannot replace the shared in-memory view
between a mutation and its persistence callback.

## CLL and MMR

The generic leaf-domain decision is fixed to 32-byte record identities. Fixed
width preserves leaf/interior domain separation while retaining existing
vectors:

```text
leaf   = SHA256(0x00 || entry_value_32)
parent = SHA256(be64(parent_position + 1) || left || right)
root   = bag peaks right-to-left with SHA256(right || left)
```

The AAC binding sets `entry_value_32 = bytes.fromhex(capsule_id)`, preserving every
existing Go/Python vector. `mmr_size` counts all MMR nodes. The empty root is 32
zero bytes. Producer Envelopes never become leaves. Changing the generic rule
or an application profile's entry encoding requires a new log profile, not a
backend edit.

## Checkpoint wire contract

The persisted developer projection is canonical JCS JSON with `v`, `kind`,
`log_id`, `mmr_size`, `root`, `prev_size`, `prev_root`, `key_id`, and
`timestamp`.

The witness body is a canonical tagged COSE_Sign1 with exactly four protected
headers and an empty unprotected map. The headers are EdDSA `alg`, content type
`application/cll-checkpoint+cbor`, raw 32-byte Ed25519 `kid`, and CWT claims.
CWT issuer is `log_id`; subject is exactly `<log_id>#<mmr_size>`.

The canonical CBOR payload has required keys `kind`, `log_size`, `commitment`,
`prev_size`, `prev_commitment`, and `issued_at`, plus optional `cadence` and
`consistency_proof`. Its `kind` is `cll-checkpoint`, distinct from the JSON
projection's `mmr_checkpoint`. `commitment` and `prev_commitment` are byte
strings containing definite-length canonical CBOR arrays of 32-byte peak byte
strings in tallest-first order. `prev_commitment` is always present and is an
empty byte string for the first checkpoint.

Every non-first checkpoint carries `consistency_proof` with exact keys
`size_a`, `size_b`, `old_peaks`, `witness`, and `new_peaks`. The TypeScript
signer emits every map in canonical order with definite lengths. Verification
byte-compares canonical claims and nested commitments. It accepts semantically
exact, definite-length protected-header maps in any ordering because the pinned
Go COSE decoder preserves their authenticated raw bytes and the real
`capsule-anchor` leg-1 checkpoint uses a non-canonical protected-header order.
The protected bytes remain covered by the checkpoint signature. Stored
checkpoints are fully reverified before restart extension.
Both the canonical JSON `timestamp` and CBOR `issued_at` use Go's UTC
RFC3339Nano rendering: whole seconds omit the fraction and non-zero fractions
trim trailing zeroes. The decoder accepts and authenticates the Python
profile's optional `cadence` claim. The public signer emits it when supplied;
the built-in checkpoint runner does not supply it.

Defaults are 100 newly indexed Capsules or 15 minutes since the durable first
uncheckpointed record. Empty and unchanged logs are silent. Hosts explicitly
start and stop runners, and notifications are only a latency optimization.

## Current external witness contract

The default client sends raw checkpoint COSE bytes to `POST /checkpoints` with
`Content-Type: application/cll-checkpoint+cbor`. The synchronized service also
accepts `application/cll-checkpoint+json`, but only for specifically enrolled
`json-ed25519` submitters. That deployment-specific route is intentionally not
part of the general ledger client.

The general COSE `/checkpoints` path currently returns
`entry_hash_scheme: "legacy"`. Its entry hash is
`SHA256(bytes.fromhex(SHA256(canonical_checkpoint_projection)))`. The newer
`sig_structure` scheme applies to direct COSE statement registration paths,
not this checkpoint-digest callout.

The witness verifies checkpoint signature and stamps that checkpoint. It does
not validate MMR construction, `prev_root`, or consistency proofs. Local
verification owns those claims.

## Toolchain and dependencies

- Node.js 24 LTS, npm, TypeScript 7 strict mode, Vitest 4, and tsup.
- `capsule-emit-ts/aac` supplies exported strict JSON, vintage/current
  Capsule-ID, `verifyClass1`, and `verifyStore` primitives. The ledger uses
  these directly, not the emitter's format-4-only `verifyCapsule` wrapper.
- `capsule-emit-ts` supplies Producer Envelope verification.
- `cborg` supplies bounded deterministic CBOR primitives.
- `better-sqlite3` supplies explicit embedded transactions.
- `mysql2` supplies promise-based parameterized MySQL access.
- a small native `flock` adapter supplies the JSONL cross-process writer lock.
- `@testcontainers/mysql` supplies the MySQL 8 integration environment.

Package initialization performs no I/O and starts no background work.
Witness clients bound response text, and delivery runners truncate every
persisted non-success error to 4,096 UTF-8 bytes before `commitWitness`. An
oversized server error therefore cannot prevent attempt and backoff progress.

## CI and acceptance

CI runs formatting, strict typecheck, lint, unit/integration tests, coverage,
the frozen AAC and Producer Envelope corpora, Go/Python format-4 fixtures, MMR
KATs, checkpoint vectors, SQLite persistence/concurrency, and MySQL 8 through
Testcontainers. Docker unavailability fails CI but may skip only the explicitly
marked local MySQL suite.

Passing TypeScript tests alone is insufficient. Release parity requires exact
Capsule IDs, JCS bytes, Producer Envelope bytes, MMR roots/proofs, checkpoint
wire bytes where frozen, and correct current witness requests.

## Operational boundaries

- A `CheckpointRunner` serializes `runOnce` calls within one instance. Separate
  runner instances rely on the Store CLL compare-and-swap over both MMR size and
  prior checkpoint identity. A stale runner therefore cannot replace the
  checkpoint head or skip its consistency link, and pending witness rows are
  not overwritten. Duplicate signing work before the losing CAS is not
  prevented. Hosts that require exactly-once signing must elect one runner per
  log.
- `WitnessDeliveryRunner` requires a caller-supplied verifier for each receipt.
  A missing or failing verifier is persisted as a permanent failure without
  trusted receipt metadata.
- TypeScript JSONL v3 and Go JSONL v3 are distinct implementation journals.
  Executable bidirectional experiments reject each other's record-bearing
  files. Direct on-disk migration is not supported.
- SQLite and MySQL rebuild an in-memory view of the selected log on reads and
  transaction starts. Complexity is linear in stored records, envelopes, MMR
  nodes, and witnesses. The normalized schema establishes correctness and
  recovery boundaries, not a high-throughput performance claim.
- `LedgerService.audit` returns `{result}` for a decoded record or `{error}` for
  an isolated decode failure. It verifies all decoded records together to keep
  store-level findings.

## Deliberately out of scope

- Python guards, holds, folds, policies, agent status, viewers, bundles, and
  command-line control plane, including Python key-revocation findings;
- application outboxes, business profiles, effect execution, and signer
  authorization;
- multi-primary JSONL, pruning, compaction, automatic trust discovery, witness
  operation, and envelope-association transparency;
- claims that an external witness verified MMR correctness or application
  truth.
