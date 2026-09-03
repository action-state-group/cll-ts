# @action-state-group/cll

A generic TypeScript implementation of a Checkpointed Local Log (CLL). It
stores opaque 32-byte entry values, builds an append-only Merkle Mountain Range,
signs checkpoints, and delivers them to witnesses. It does not interpret the
records whose identities are appended.

## Install

Node.js 24 or newer is required.

```sh
npm install @action-state-group/cll
```

Install only the database driver path you use. The root import does not load
SQLite or MySQL native modules.

## Append and checkpoint

```ts
import {
  CheckpointRunner,
  MemoryStore,
  createCheckpointIdentity,
} from "@action-state-group/cll";

const backend = new MemoryStore();
const recordIdentity = new Uint8Array(32); // digest or another opaque identity

const result = await backend.append({
  value: recordIdentity,
  appendedAt: new Date(),
});

console.log(result.entry.seq, result.outcome); // 1n, "inserted"

const runner = new CheckpointRunner(backend, {
  logId: "example-log",
  identity: createCheckpointIdentity(
    crypto.getRandomValues(new Uint8Array(32)),
  ),
  entryCadence: 100,
  ageCadenceMs: 15 * 60_000,
});

await runner.runOnce();
```

Appending the same 32-byte value again is idempotent. It returns the original
entry and does not change its sequence or append time. Sequences are dense and
1-based.

## Witness delivery

Every ID in `CheckpointRunner.witnessIds` needs both a `WitnessClient` and a
`ReceiptVerification` entry under the same ID. Missing local configuration is
retryable and fails closed; receipt bytes are persisted as success only after
the configured verifier accepts them. A rejected or corrupt receipt is marked
permanent so polling does not repeatedly submit the same checkpoint.

```ts
import {
  HttpWitnessClient,
  ReceiptVerifier,
  WitnessDeliveryRunner,
} from "@action-state-group/cll";

const witness = new HttpWitnessClient(
  "public-witness",
  new URL("https://witness.example"),
);
const delivery = new WitnessDeliveryRunner(
  backend,
  new Map([[witness.id, witness]]),
  {
    verifiers: new Map([
      [witness.id, new ReceiptVerifier(pinnedWitnessEd25519PublicKey)],
    ]),
  },
);
await delivery.runOnce();
```

`HttpWitnessClient` sends the raw checkpoint COSE bytes to `POST /checkpoints`
with content type `application/cll-checkpoint+cbor`. It expects JSON containing
`receipt_b64`, `entry_hash_scheme: "legacy"`, a lowercase 64-hex `entry_hash`,
and integer `leaf_index` and `tree_size`. `ReceiptVerifier` validates that RFC
9162-style receipt against a pinned Ed25519 authority key. Other witness
protocols implement `WitnessClient` and `ReceiptVerification`; their receipt may
contain only opaque `bytes`.

After correcting an external condition that caused a permanent failure, an
operator may load the row with `getWitness` and reset it with `commitWitness`
using its current `attempts` value as the compare-and-swap token.

## Backends

All included backends implement `CllBackend` directly and run the same contract
suite.

```ts
import { MemoryStore } from "@action-state-group/cll";
import { JsonlStore } from "@action-state-group/cll/jsonl";
import { SqliteStore } from "@action-state-group/cll/sqlite";
import { MysqlStore } from "@action-state-group/cll/mysql";

const memory = new MemoryStore();
const jsonl = await JsonlStore.open("./events.jsonl");
const sqlite = SqliteStore.open("./cll.sqlite", "example-log");
const mysql = await MysqlStore.open(process.env.MYSQL_URL!, "example-log");
```

- Memory is process-local and intended for tests or ephemeral use.
- JSONL is single-writer, append-only, fsyncs complete events, truncates an
  incomplete tail after a crash, and rejects version 3 files.
- SQLite uses WAL and serializes writes across handles for the same file/log.
- MySQL uses InnoDB transactions and locks the log metadata row while assigning
  sequences or updating checkpoint state.

### SQLite and MySQL tables

`SqliteStore.open()` and `MysqlStore.open()` create the same four
library-owned tables when they do not already exist:

| Table           | Purpose                                                 |
| --------------- | ------------------------------------------------------- |
| `cll_meta`      | Log-level serialized checkpoint and control state       |
| `cll_entries`   | Ordered 32-byte record identities and append timestamps |
| `cll_nodes`     | Merkle Mountain Range nodes used by checkpoints         |
| `cll_witnesses` | Durable witness delivery attempts and receipt state     |

Every table is scoped by `log_id`, so one database can hold multiple independent
logs. The caller must provide an existing database and credentials allowed to
create and access these tables. They do not contain full application records,
Capsules, or Producer Envelopes; the application persists those separately.

SQLite and MySQL currently rebuild the selected log's in-memory view from all
entry, node, and witness rows at the start of each read or write transaction.
This favors simple snapshot correctness and is linear in stored log size. It is
not a high-throughput query design for logs with millions of entries.

## Compose with capsule-emit

AAC is one possible application of CLL. The two packages are independent. The
application verifies and stores the full application record, then appends only
its verified 32-byte identity to CLL.

```ts
import { build, verifyCapsule } from "@action-state-group/capsule-emit";
import { MysqlStore } from "@action-state-group/cll/mysql";

const built = build({
  actionId: "deploy-42",
  actionType: "fyi",
  operator: "matt",
  developer: "example@v1",
  timestamp: new Date(),
});

verifyCapsule(built.json); // returns verified metadata or throws

// The application persists built.json and any Producer Envelope separately.
const cll = await MysqlStore.open(process.env.MYSQL_URL!, "application-log");
await cll.append({
  value: Buffer.from(built.capsuleId, "hex"),
  appendedAt: new Date(),
});
```

Neither package imports the other at runtime. A project that needs both installs
both explicitly.

## Implement another backend

TypeScript interfaces are structural. A class does not need to extend an SDK
base class; it must implement every operation with the documented semantics.

```ts
import type {
  AppendInput,
  AppendResult,
  CllBackend,
  CllEntry,
  CllState,
  WitnessState,
} from "@action-state-group/cll";

export class PostgresBackend implements CllBackend {
  append(input: AppendInput): Promise<AppendResult> {
    throw new Error("implement atomically");
  }
  getEntry(value: Uint8Array): Promise<CllEntry> {
    throw new Error("implement");
  }
  scanEntries(afterSeq: bigint, limit: number): Promise<readonly CllEntry[]> {
    throw new Error("implement");
  }
  loadCll(): Promise<CllState> {
    throw new Error("implement from one consistent snapshot");
  }
  commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void> {
    throw new Error("implement append-only compare-and-swap");
  }
  pendingWitnesses(now: Date, limit: number): Promise<readonly WitnessState[]> {
    throw new Error("implement");
  }
  getWitness(id: string, size: bigint): Promise<WitnessState | undefined> {
    throw new Error("implement");
  }
  commitWitness(expectedAttempts: number, next: WitnessState): Promise<void> {
    throw new Error("implement compare-and-swap");
  }
  close(): Promise<void> {
    throw new Error("implement idempotently");
  }
}
```

Run the repository's
[backend contract](https://github.com/action-state-group/cll-ts/blob/main/test/backend-contract.ts)
unchanged against the new backend. Durable implementations must persist every mutation, return defensive
copies, allocate dense sequences transactionally, provide consistent reads,
enforce checkpoint and witness compare-and-swap, detect corrupt state, and make
`close()` idempotent.

See [DESIGN.md](DESIGN.md) for state and durability invariants.

## Release

Releases are published from `main` with the manual
[Publish npm package](https://github.com/action-state-group/cll-ts/actions/workflows/publish.yml)
GitHub Action:

1. Update `version` in `package.json` and `package-lock.json`, commit the change,
   and wait for `main` CI to pass.
2. In GitHub, open the workflow, choose **Run workflow**, and select `main`.
3. Verify the workflow published `@action-state-group/cll` and created the
   `v<version>` GitHub release and tag on the published commit.

The npm package must have a GitHub Actions trusted publisher configured for
the `action-state-group/cll-ts` repository and
`.github/workflows/publish.yml`. No long-lived npm token is required. Re-running
the workflow is safe: it skips an existing npm version and verifies that its
Git tag points to the `gitHead` recorded by npm.

If npm contains the version but its tag is missing after this workflow has
changed, GitHub may reject recovery with the workflow's `GITHUB_TOKEN`. A
maintainer with `workflow` scope must create the tag at the npm `gitHead`, then
rerun the workflow to verify the tag and create any missing GitHub release:

```sh
version=0.1.1
git_head=$(npm view "@action-state-group/cll@$version" gitHead)
git fetch origin --tags
git tag -a "v$version" "$git_head" -m "Release v$version"
git push origin "refs/tags/v$version"
```
