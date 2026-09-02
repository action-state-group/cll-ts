import Database from "better-sqlite3";
import { realpathSync } from "node:fs";
import { MemoryStore } from "./memory-store.js";
import {
  envelopeToWire,
  recordToWire,
  stateFromRows,
  stateToWire,
  witnessToWire,
  type WireEnvelope,
  type WireState,
  type WireWitness,
} from "./serde.js";
import {
  LedgerError,
  type AppendInput,
  type CllState,
  type EnvelopeInput,
  type WitnessState,
} from "./types.js";

type WireRecord = WireState["records"][number];

/** SQLite WAL backend with normalized, log-scoped rows. */
export class SqliteStore extends MemoryStore {
  private static readonly locks = new Map<
    PropertyKey,
    { tail: Promise<void>; references: number }
  >();
  private sqlQueue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly db: Database.Database,
    private readonly logId: string,
    private readonly lockKey: PropertyKey,
    private readonly sharedLock: { tail: Promise<void>; references: number },
  ) {
    super();
  }

  public static open(path: string, logId = "default"): SqliteStore {
    const db = new Database(path);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.pragma("busy_timeout = 5000");
    db.exec(`
      CREATE TABLE IF NOT EXISTS ledger_meta (
        log_id TEXT PRIMARY KEY,
        cll BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS ledger_records (
        log_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        capsule_id TEXT NOT NULL,
        record BLOB NOT NULL,
        PRIMARY KEY(log_id, seq),
        UNIQUE(log_id, capsule_id)
      );
      CREATE TABLE IF NOT EXISTS ledger_envelopes (
        log_id TEXT NOT NULL,
        capsule_id TEXT NOT NULL,
        digest TEXT NOT NULL,
        envelope BLOB NOT NULL,
        PRIMARY KEY(log_id, capsule_id, digest)
      );
      CREATE TABLE IF NOT EXISTS ledger_nodes (
        log_id TEXT NOT NULL,
        position INTEGER NOT NULL,
        node BLOB NOT NULL,
        PRIMARY KEY(log_id, position)
      );
      CREATE TABLE IF NOT EXISTS ledger_witnesses (
        log_id TEXT NOT NULL,
        witness_id TEXT NOT NULL,
        checkpoint_size TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        witness BLOB NOT NULL,
        PRIMARY KEY(log_id, witness_id, checkpoint_size)
      );
    `);
    const empty = stateToWire([], {
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [],
    }).cll;
    db.prepare("INSERT OR IGNORE INTO ledger_meta(log_id,cll) VALUES(?,?)").run(
      logId,
      JSON.stringify(empty),
    );
    const lockKey: PropertyKey =
      path === ":memory:" ? Symbol(":memory:") : realpathSync(path);
    let sharedLock = SqliteStore.locks.get(lockKey);
    if (sharedLock === undefined) {
      sharedLock = { tail: Promise.resolve(), references: 0 };
      SqliteStore.locks.set(lockKey, sharedLock);
    }
    sharedLock.references += 1;
    const store = new SqliteStore(db, logId, lockKey, sharedLock);
    store.refreshSnapshot();
    return store;
  }

  private refresh(): void {
    const meta = this.db
      .prepare("SELECT cll FROM ledger_meta WHERE log_id=?")
      .get(this.logId) as { cll: Buffer | string } | undefined;
    const recordRows = this.db
      .prepare(
        "SELECT record FROM ledger_records WHERE log_id=? ORDER BY seq ASC",
      )
      .all(this.logId) as Array<{ record: Buffer | string }>;
    const envelopeRows = this.db
      .prepare(
        "SELECT capsule_id,envelope FROM ledger_envelopes WHERE log_id=? ORDER BY capsule_id,digest",
      )
      .all(this.logId) as Array<{
      capsule_id: string;
      envelope: Buffer | string;
    }>;
    const nodeRows = this.db
      .prepare(
        "SELECT node FROM ledger_nodes WHERE log_id=? ORDER BY position ASC",
      )
      .all(this.logId) as Array<{ node: Buffer }>;
    const witnessRows = this.db
      .prepare(
        "SELECT witness FROM ledger_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      )
      .all(this.logId) as Array<{ witness: Buffer | string }>;
    try {
      if (meta === undefined) throw new Error("missing ledger metadata row");
      const state = stateFromRows({
        records: recordRows.map(
          (row) => JSON.parse(String(row.record)) as WireRecord,
        ),
        envelopes: envelopeRows.map((row) => ({
          capsuleId: row.capsule_id,
          envelope: JSON.parse(String(row.envelope)) as WireEnvelope,
        })),
        cll: JSON.parse(String(meta.cll)) as WireState["cll"],
        nodes: nodeRows.map((row) => row.node),
        witnesses: witnessRows.map(
          (row) => JSON.parse(String(row.witness)) as WireWitness,
        ),
      });
      this.replaceState(state.records, state.cll);
    } catch (error) {
      if (error instanceof LedgerError && error.code === "corrupt") throw error;
      throw new LedgerError(
        "corrupt",
        "stored SQLite ledger state is corrupt",
        {
          cause: error,
        },
      );
    }
  }

  private refreshSnapshot(): void {
    if (this.db.inTransaction) {
      this.refresh();
      return;
    }
    this.db.exec("BEGIN");
    try {
      this.refresh();
      this.db.exec("COMMIT");
    } catch (error) {
      if (this.db.inTransaction) this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private async transaction<T>(
    operation: () => Promise<T>,
    persist: (result: T) => void,
  ): Promise<T> {
    const prior = Promise.all([this.sqlQueue, this.sharedLock.tail]);
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.sqlQueue = pending;
    this.sharedLock.tail = pending;
    await prior;
    try {
      this.db.exec("BEGIN IMMEDIATE");
      try {
        this.refresh();
        const result = await operation();
        persist(result);
        this.db.exec("COMMIT");
        return result;
      } catch (error) {
        if (this.db.inTransaction) this.db.exec("ROLLBACK");
        this.refreshSnapshot();
        throw error;
      }
    } finally {
      release();
    }
  }

  public override append(input: AppendInput) {
    return this.transaction(
      () => super.append(input),
      (result) => {
        if (result.outcome !== "inserted") return;
        const wire = recordToWire({ ...result.record, envelopes: [] });
        this.db
          .prepare(
            "INSERT INTO ledger_records(log_id,seq,capsule_id,record) VALUES(?,?,?,?)",
          )
          .run(
            this.logId,
            Number(result.record.seq),
            result.record.capsuleId,
            JSON.stringify(wire),
          );
        const statement = this.db.prepare(
          "INSERT INTO ledger_envelopes(log_id,capsule_id,digest,envelope) VALUES(?,?,?,?)",
        );
        for (const envelope of result.record.envelopes)
          statement.run(
            this.logId,
            result.record.capsuleId,
            envelope.digest,
            JSON.stringify(envelopeToWire(envelope)),
          );
      },
    );
  }

  public override addEnvelope(input: EnvelopeInput) {
    return this.transaction(
      () => super.addEnvelope(input),
      (result) => {
        if (result.outcome !== "inserted") return;
        this.db
          .prepare(
            "INSERT INTO ledger_envelopes(log_id,capsule_id,digest,envelope) VALUES(?,?,?,?)",
          )
          .run(
            this.logId,
            input.capsuleId,
            result.envelope.digest,
            JSON.stringify(envelopeToWire(result.envelope)),
          );
      },
    );
  }

  public override commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ) {
    let beforeWitnesses: readonly WitnessState[] = [];
    return this.transaction(
      () => {
        beforeWitnesses = this.cll.witnesses;
        return super.commitCll(expectedSize, expectedCheckpoint, next);
      },
      () => {
        const committed = this.cll;
        const wire = stateToWire([], {
          ...committed,
          nodes: [],
          witnesses: [],
        }).cll;
        this.db
          .prepare("UPDATE ledger_meta SET cll=? WHERE log_id=?")
          .run(JSON.stringify(wire), this.logId);
        const nodeInsert = this.db.prepare(
          "INSERT INTO ledger_nodes(log_id,position,node) VALUES(?,?,?)",
        );
        for (
          let position = Number(expectedSize);
          position < committed.nodes.length;
          position += 1
        )
          nodeInsert.run(this.logId, position, committed.nodes[position]!);
        const witnessInsert = this.db.prepare(
          "INSERT INTO ledger_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
        );
        for (const witness of this.witnessDelta(
          beforeWitnesses,
          committed.witnesses,
        ))
          witnessInsert.run(
            this.logId,
            witness.witnessId,
            String(witness.checkpointSize),
            witness.attempts,
            JSON.stringify(witnessToWire(witness)),
          );
      },
    );
  }

  public override commitWitness(expectedAttempts: number, next: WitnessState) {
    return this.transaction(
      () => super.commitWitness(expectedAttempts, next),
      () => {
        const result = this.db
          .prepare(
            "UPDATE ledger_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
          )
          .run(
            next.attempts,
            JSON.stringify(witnessToWire(next)),
            this.logId,
            next.witnessId,
            String(next.checkpointSize),
            expectedAttempts,
          );
        if (result.changes !== 1) throw new Error("witness CAS failed");
      },
    );
  }

  private async refreshForRead(): Promise<void> {
    await Promise.all([this.sqlQueue, this.sharedLock.tail]);
    this.refreshSnapshot();
  }
  public override async get(id: string) {
    await this.refreshForRead();
    return super.get(id);
  }
  public override async scan(after: bigint, limit: number) {
    await this.refreshForRead();
    return super.scan(after, limit);
  }
  public override async loadCll() {
    await this.refreshForRead();
    return super.loadCll();
  }
  public override async findChainGaps() {
    await this.refreshForRead();
    return super.findChainGaps();
  }
  public override async pendingWitnesses(now: Date, limit: number) {
    await this.refreshForRead();
    return super.pendingWitnesses(now, limit);
  }
  public override async getWitness(witnessId: string, checkpointSize: bigint) {
    await this.refreshForRead();
    return super.getWitness(witnessId, checkpointSize);
  }
  public override async close(): Promise<void> {
    if (this.closed) return;
    await Promise.all([this.sqlQueue, this.sharedLock.tail]);
    this.db.close();
    this.sharedLock.references -= 1;
    if (this.sharedLock.references === 0)
      SqliteStore.locks.delete(this.lockKey);
    await super.close();
  }
}
