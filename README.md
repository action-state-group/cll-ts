# capsule-ledger-ts

An embeddable TypeScript Checkpointed Local Log. It maintains the MMR, signs
checkpoint COSE statements, verifies proofs and receipts, and durably retries
independent witness deliveries. Its current ledger binding verifies AAC
admission, allocates contiguous local sequence numbers, and preserves exact
Capsule and Producer Envelope bytes.

Production stores are available for JSONL, SQLite, and MySQL 8. `MemoryStore`
is the in-memory contract implementation. The shipped durable stores extend it
to reuse validation, idempotency, sequence allocation, and CLL CAS behavior.
An independent backend implements the exported `Store` interface and must
preserve those same semantics.

```ts
import { LedgerService, SqliteStore } from "capsule-ledger-ts";

const store = SqliteStore.open("ledger.sqlite", "example-log");
const ledger = new LedgerService(store);
const record = await ledger.append("unsigned", capsuleBytes);
await store.close();
```

The JSONL backend takes a non-blocking operating-system `flock` for its whole
lifetime and fsyncs each complete version-3 line. SQLite uses WAL and immediate
write transactions. MySQL locks the log metadata row with `SELECT FOR UPDATE`.

JSONL version 3 is this package's bounded incremental event schema. It is not
the Go backend's on-disk schema despite sharing a version number. Go requires a
`log_id` in `log.init` and uses different record, CLL, and witness DTOs. Direct
file migration in either direction is unsupported; migrate through the public
Store data model or an explicit converter.

SQLite and MySQL use normalized tables for records, envelopes, MMR nodes, and
witness state. Their current implementation reconstructs the selected log's
in-memory view on reads and at transaction start, so reads are O(records +
envelopes + nodes + witnesses). They provide transactional parity and
multi-handle correctness, not a high-throughput query-performance claim.

## Runner lifecycle and receipt trust

Both runners start only when the host calls `run(signal)`. Aborting the signal
stops the polling interval and resolves the run promise. Concurrent `run` calls
on one instance are rejected. `runOnce` remains available for schedulers that
own their own cadence.

```ts
import {
  CapsuleAnchorClient,
  CheckpointRunner,
  ReceiptVerifier,
  WitnessDeliveryRunner,
} from "capsule-ledger-ts";

const abort = new AbortController();
const checkpointRunner = new CheckpointRunner(store, {
  logId: "example-log",
  identity,
});
const anchor = new CapsuleAnchorClient(
  "anchor",
  new URL("https://witness.example"),
);
const receiptVerifier = new ReceiptVerifier(pinnedAuthorityPublicKey);
const deliveryRunner = new WitnessDeliveryRunner(
  store,
  new Map([[anchor.id, anchor]]),
  { verifiers: new Map([[anchor.id, receiptVerifier]]) },
);

const running = Promise.all([
  checkpointRunner.run(abort.signal),
  deliveryRunner.run(abort.signal),
]);
// On host shutdown:
abort.abort();
await running;
```

Receipt verifiers are caller-injected pinned trust. A missing verifier or a
failed offline verification is a permanent, fail-closed delivery outcome, and
receipt bytes or metadata are not persisted as trusted success.

`LedgerService.audit(bound)` returns one entry per durable record. A decodable
record has `result`; an isolated decode failure has `error`. Decodable records
are verified together so chain and other store-level findings are preserved.

## Development

```sh
npm install
npm run check
npm run build
```

The MySQL integration suite starts a MySQL 8.4 Testcontainer and therefore
requires Docker.
