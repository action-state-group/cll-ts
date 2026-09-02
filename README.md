# cll-ts

An embeddable TypeScript Checkpointed Local Log (CLL). It maintains an MMR,
signs checkpoint COSE statements, verifies proofs and receipts, and durably
retries independent witness deliveries.

The CLL entry boundary is application-neutral. The included AAC binding verifies
Capsule admission, allocates contiguous local sequence numbers, preserves exact
Capsule and Producer Envelope bytes, and projects each verified Capsule ID into
one CLL leaf. Capsules are a use case of the local log, not its definition.

## Install

Node.js 24 or newer is required. The package is not yet published to npm. Its
current development dependency points to a sibling `capsule-emit-ts` checkout.

```sh
git clone https://github.com/ethanyzhang/capsule-emit-ts.git
git clone https://github.com/ethanyzhang/cll-ts.git
cd capsule-emit-ts && npm ci && npm run build
cd ../cll-ts && npm ci && npm run build
```

## End to end: producer, ledger, checkpoint, and witness

The producer key signs the independent Producer Envelope. The checkpoint key
signs the local CLL checkpoint. A separately provisioned witness authority key
verifies the external receipt. These are three distinct trust roles.

```ts
import { randomBytes } from "node:crypto";
import { createEd25519Identity, seal } from "capsule-emit-ts";
import {
  CapsuleAnchorClient,
  CheckpointRunner,
  LedgerService,
  ReceiptVerifier,
  SqliteStore,
  WitnessDeliveryRunner,
} from "cll-ts";

const logId = "example-investigations";
const witnessId = "production-witness";
const producerIdentity = createEd25519Identity(randomBytes(32));
const checkpointIdentity = createEd25519Identity(randomBytes(32));

// Provision this from independent witness trust material in production.
declare const pinnedWitnessAuthorityPublicKey: Uint8Array;

const store = SqliteStore.open("ledger.sqlite", logId);
try {
  const ledger = new LedgerService(store, {
    "effect.type": new Set(["example.publish"]),
  });
  const produced = seal({
    capsule: {
      actionId: "investigation/123",
      actionType: "fyi",
      operator: "example-org",
      developer: "example-agent@v1",
      timestamp: new Date("2026-09-02T12:00:00Z"),
    },
    payload: { issue: 123, finding: "example" },
    identity: producerIdentity,
  });

  const record = await ledger.append("signed", produced.payload, [
    produced.envelope,
  ]);
  console.log(`stored seq=${record.seq} capsule_id=${record.capsuleId}`);

  // Cadence 1 is illustrative so one append immediately produces a checkpoint.
  const checkpointRunner = new CheckpointRunner(store, {
    logId,
    identity: checkpointIdentity,
    witnessIds: [witnessId],
    entryCadence: 1,
  });
  const checkpoint = await checkpointRunner.runOnce();
  if (checkpoint === undefined)
    throw new Error("checkpoint runner made no progress");

  const anchor = new CapsuleAnchorClient(
    witnessId,
    new URL("https://witness.example"),
  );
  const verifier = new ReceiptVerifier(pinnedWitnessAuthorityPublicKey);
  const deliveryRunner = new WitnessDeliveryRunner(
    store,
    new Map([[witnessId, anchor]]),
    { verifiers: new Map([[witnessId, verifier]]) },
  );
  const delivered = await deliveryRunner.runOnce();
  if (delivered !== 1) throw new Error("checkpoint was not delivered");

  const state = await store.loadCll();
  const witness = await store.getWitness(witnessId, state.checkpointSize!);
  if (witness?.receipt === undefined || witness.permanent) {
    throw new Error("witness receipt is not verified");
  }
} finally {
  await store.close();
}
```

The call path is:

```text
seal
  -> Capsule + independent Producer Envelope
LedgerService.append
  -> verified durable AAC record with a gapless local sequence
CheckpointRunner.runOnce
  -> generic entry projection + durable MMR checkpoint + pending witness row
WitnessDeliveryRunner.runOnce
  -> POST /checkpoints + offline pinned-key receipt verification
```

No import starts a timer, background task, or network call. Hosts explicitly own
runner lifecycle and cancellation.

## Storage

Choose one included AAC ledger backend:

```ts
import { JsonlStore, MysqlStore, SqliteStore } from "cll-ts";

const jsonl = await JsonlStore.open("./example-log.jsonl");
const sqlite = SqliteStore.open("./ledger.sqlite", "example-log");
declare const mysqlUri: string;
const mysql = await MysqlStore.open(mysqlUri, "example-log");
```

JSONL holds a non-blocking operating-system `flock` for its lifetime and fsyncs
each complete version-3 event. SQLite uses WAL and immediate write transactions.
MySQL locks the log metadata row with `SELECT ... FOR UPDATE`.

The TypeScript JSONL v3 journal is not the Go backend's on-disk schema despite
sharing a version number. Direct file migration in either direction is not
supported; migrate through the public data model or an explicit converter.

SQLite and MySQL use normalized record, envelope, MMR-node, and witness tables.
They currently reconstruct the selected log's in-memory view on reads and
transaction starts, so those reads are linear in stored records, envelopes,
nodes, and witnesses. The schemas provide transactional parity and multi-handle
correctness, not a high-throughput query claim.

`MemoryStore` is the in-memory contract implementation. An independently
implemented `Store` must preserve admission, idempotency, ordering, defensive
copy, CLL compare-and-swap, and witness-merge semantics.

## Generic CLL entry boundary

`CllEntry` carries a dense 1-based `seq`, an exact 32-byte record identity in
`value`, and a valid `appendedAt` timestamp.
`CllSource.scanEntries(after, limit)` is the narrow projection consumed by the
checkpoint runner. The AAC stores implement it by decoding each verified
lowercase Capsule ID into 32 leaf bytes. A different application can implement
`CheckpointStore` with its own ordered record identity without importing AAC
types.

The MMR leaf rule is:

```text
leaf = SHA256(0x00 || entry_value_32)
```

The fixed width preserves leaf/interior domain separation while retaining the
existing Python and Go vectors. Application profiles own the 32-byte record
identity; the CLL owns ordering, commitment, checkpointing, and witness
continuity. `verifyInclusionValue` verifies generic entries, while
`verifyInclusion` remains the AAC Capsule-ID compatibility helper.

## Runner lifecycle and receipt trust

Use `run(signal)` when the host wants library-owned polling, or `runOnce()` when
an external scheduler owns cadence:

```ts
const abort = new AbortController();
const running = Promise.all([
  checkpointRunner.run(abort.signal),
  deliveryRunner.run(abort.signal),
]);

// During host shutdown:
abort.abort();
await running;
```

Aborting the signal stops the polling interval and resolves the run promise.
Concurrent `run` calls on one runner are rejected. Receipt verifiers are
caller-injected pinned trust. A missing or failing verifier produces a permanent,
fail-closed delivery outcome; unverified receipt bytes are never persisted as a
trusted success.

## Audit and interoperability

`LedgerService.audit(bound)` returns one result per durable record. Decodable
records are verified together so chain and other store-level findings are
preserved; an isolated decode failure is returned on that record as `error`.

CI runs formatting, strict typecheck, lint, coverage, frozen AAC and Producer
Envelope corpora, Go/Python format-4 fixtures, MMR and checkpoint vectors,
SQLite persistence/concurrency, and MySQL 8 through Testcontainers. Passing
TypeScript unit tests alone is not treated as interoperability proof.

## Development

```sh
npm install
npm run check
npm run build
```

The MySQL integration suite starts a MySQL 8.4 Testcontainer and requires Docker.

## License

Apache-2.0.
