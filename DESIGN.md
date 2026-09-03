# CLL TypeScript design

## Boundary

CLL receives an opaque 32-byte value for each append. A value is commonly the
digest of a signed record, but CLL does not parse, authenticate, or retain that
record. It proves inclusion, order, and checkpoint consistency. Record truth
and application admission remain outside this package.

The package owns:

- dense append-only entries;
- MMR nodes and inclusion/consistency proofs;
- signed checkpoints and checkpoint cadence;
- witness delivery state and receipts;
- Memory, JSONL, SQLite, and MySQL persistence.

## Backend contract

`CllBackend` combines four narrow structural interfaces: `EntryStore`,
`EntrySource`, `CheckpointStateStore`, and `WitnessStateStore`. Every included
backend implements that interface directly. Durable backends compose the
internal invariant engine; they do not inherit operations from Memory.

Append is atomic. A new value receives the next dense 1-based sequence. The same
value is idempotent and returns the first entry. Returned byte arrays and dates
are defensive copies.

`commitCll` is append-only compare-and-swap over the previous MMR size and
checkpoint bytes. Existing nodes cannot change, indexed sequence cannot move
backward, and the checkpoint tuple must be complete and monotonic. A checkpoint
cannot be replaced at the same size. `commitCll` merges new witness rows and
must preserve newer delivery state for existing rows; otherwise a checkpoint
commit racing with delivery can resurrect completed work. Witness updates use
attempt count as their compare-and-swap version.

## Persistence

JSONL format version 4 uses `cll.init`, `entry.append`, `cll.commit`, and
`witness.commit` events. Only newline-terminated events are durable. Opening a
file truncates an incomplete final line and rejects a corrupt complete line.

SQLite stores `cll_meta`, `cll_entries`, `cll_nodes`, and `cll_witnesses` under
a caller-selected log ID. WAL supports concurrent readers. Writes use
`BEGIN IMMEDIATE`; an in-process per-file/log queue keeps multiple handles from
refreshing or committing over each other.

MySQL uses the same four logical tables. InnoDB transactions lock the selected
`cll_meta` row before refreshing state, assigning a sequence, and committing.
Reads use one repeatable-read transaction so metadata, entries, nodes, and
witnesses come from one snapshot.

Both SQL backends currently reload and decode every row for the selected log at
the beginning of each read or write transaction. This is linear in log size and
prioritizes snapshot correctness over high-throughput access.

The development schemas that predate the generic v4 contract are not migrated.
Applications must start a new backend or perform an explicit application-owned
conversion of verified 32-byte identities.

## Package loading

The core entry point exports types, Memory, MMR, checkpoints, receipts, and
witness runners. Driver-backed implementations are isolated behind `/jsonl`,
`/sqlite`, and `/mysql` exports so importing core does not initialize native
database modules.

## Interoperability

Checkpoint projection JSON uses an internal RFC 8785 integer-only canonicalizer.
Checkpoint COSE, MMR hashing, consistency proofs, and witness receipt validation
retain byte compatibility with the Go and Python reference implementations.
