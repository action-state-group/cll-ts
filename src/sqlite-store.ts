import Database from "better-sqlite3";
import { addedWitnesses, BackendState } from "./backend-state.js";
import { cloneCll } from "./clone.js";
import {
  cllToWire,
  entryToWire,
  stateFromRows,
  witnessToWire,
  type WireCllState,
  type WireEntry,
  type WireWitness,
} from "./serde.js";
import {
  CllError,
  validateIdentifier,
  type AppendInput,
  type CllBackend,
  type CllState,
  type WitnessState,
} from "./types.js";

interface SharedLock {
  tail: Promise<void>;
  references: number;
}

/** SQLite backend with WAL durability and log-scoped transactions. */
export class SqliteStore implements CllBackend {
  private static readonly locks = new Map<string, SharedLock>();
  private readonly state = new BackendState();
  private queue: Promise<void> = Promise.resolve();
  private closed = false;

  private constructor(
    private readonly db: Database.Database,
    private readonly logId: string,
    private readonly lockKey: string,
    private readonly sharedLock: SharedLock,
  ) {}

  public static open(path: string, logId = "default"): SqliteStore {
    validateIdentifier(logId);
    const db = new Database(path);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.exec(`
      CREATE TABLE IF NOT EXISTS cll_meta (
        log_id TEXT PRIMARY KEY,
        state BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cll_entries (
        log_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        value BLOB NOT NULL,
        appended_at TEXT NOT NULL,
        PRIMARY KEY(log_id, seq),
        UNIQUE(log_id, value)
      );
      CREATE TABLE IF NOT EXISTS cll_nodes (
        log_id TEXT NOT NULL,
        position INTEGER NOT NULL,
        node BLOB NOT NULL,
        PRIMARY KEY(log_id, position)
      );
      CREATE TABLE IF NOT EXISTS cll_witnesses (
        log_id TEXT NOT NULL,
        witness_id TEXT NOT NULL,
        checkpoint_size TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        witness BLOB NOT NULL,
        PRIMARY KEY(log_id, witness_id, checkpoint_size)
      );
    `);
    const empty = cllToWire({
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [],
    });
    db.prepare("INSERT OR IGNORE INTO cll_meta(log_id,state) VALUES(?,?)").run(
      logId,
      JSON.stringify(empty),
    );
    const lockKey = `${path}\0${logId}`;
    let sharedLock = SqliteStore.locks.get(lockKey);
    if (sharedLock === undefined) {
      sharedLock = { tail: Promise.resolve(), references: 0 };
      SqliteStore.locks.set(lockKey, sharedLock);
    }
    sharedLock.references += 1;
    const backend = new SqliteStore(db, logId, lockKey, sharedLock);
    backend.refreshSnapshot();
    return backend;
  }

  private ensureOpen(): void {
    if (this.closed) throw new CllError("closed", "backend is closed");
  }

  private refresh(): void {
    const meta = this.db
      .prepare("SELECT state FROM cll_meta WHERE log_id=?")
      .get(this.logId) as { state: Buffer | string } | undefined;
    const entries = this.db
      .prepare(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
      )
      .all(this.logId) as Array<{
      seq: number;
      value: Buffer;
      appended_at: string;
    }>;
    const nodes = this.db
      .prepare("SELECT node FROM cll_nodes WHERE log_id=? ORDER BY position")
      .all(this.logId) as Array<{ node: Buffer }>;
    const witnesses = this.db
      .prepare(
        "SELECT witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      )
      .all(this.logId) as Array<{ witness: Buffer | string }>;
    try {
      if (meta === undefined) throw new Error("missing CLL metadata");
      const decoded = stateFromRows({
        cll: JSON.parse(String(meta.state)) as WireCllState,
        entries: entries.map((row) => ({
          seq: String(row.seq),
          value: row.value.toString("base64"),
          appendedAt: row.appended_at,
        })),
        nodes: nodes.map((row) => row.node),
        witnesses: witnesses.map(
          (row) => JSON.parse(String(row.witness)) as WireWitness,
        ),
      });
      this.state.replace(decoded.entries, decoded.cll);
    } catch (error) {
      if (error instanceof CllError) throw error;
      throw new CllError("corrupt", "stored SQLite CLL state is corrupt", {
        cause: error,
      });
    }
  }

  private refreshSnapshot(): void {
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
    operation: () => T,
    persist: (result: T) => void,
  ): Promise<T> {
    const prior = Promise.all([this.queue, this.sharedLock.tail]);
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.queue = pending;
    this.sharedLock.tail = pending;
    await prior;
    try {
      this.ensureOpen();
      this.db.exec("BEGIN IMMEDIATE");
      this.refresh();
      try {
        const result = operation();
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

  private persistCll(before: CllState): void {
    const current = this.state.cll();
    const metadata = cllToWire({ ...current, nodes: [], witnesses: [] });
    this.db
      .prepare("UPDATE cll_meta SET state=? WHERE log_id=?")
      .run(JSON.stringify(metadata), this.logId);
    const nodeInsert = this.db.prepare(
      "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)",
    );
    for (
      let position = before.nodes.length;
      position < current.nodes.length;
      position += 1
    )
      nodeInsert.run(this.logId, position, current.nodes[position]!);
    const witnessInsert = this.db.prepare(
      "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
    );
    for (const witness of addedWitnesses(before.witnesses, current.witnesses))
      witnessInsert.run(
        this.logId,
        witness.witnessId,
        String(witness.checkpointSize),
        witness.attempts,
        JSON.stringify(witnessToWire(witness)),
      );
  }

  public append(input: AppendInput) {
    return this.transaction(
      () => this.state.append(input),
      (result) => {
        if (result.outcome !== "inserted") return;
        const wire: WireEntry = entryToWire(result.entry);
        this.db
          .prepare(
            "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
          )
          .run(
            this.logId,
            Number(result.entry.seq),
            result.entry.value,
            wire.appendedAt,
          );
      },
    );
  }

  public commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ) {
    let before!: CllState;
    return this.transaction(
      () => {
        before = cloneCll(this.state.cll());
        this.state.commitCll(expectedSize, expectedCheckpoint, next);
      },
      () => this.persistCll(before),
    );
  }

  public commitWitness(expectedAttempts: number, next: WitnessState) {
    return this.transaction(
      () => this.state.commitWitness(expectedAttempts, next),
      () => {
        const result = this.db
          .prepare(
            "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
          )
          .run(
            next.attempts,
            JSON.stringify(witnessToWire(next)),
            this.logId,
            next.witnessId,
            String(next.checkpointSize),
            expectedAttempts,
          );
        if (result.changes !== 1)
          throw new CllError("contention", "witness CAS failed");
      },
    );
  }

  private async read<T>(operation: () => T): Promise<T> {
    await Promise.all([this.queue, this.sharedLock.tail]);
    this.ensureOpen();
    this.refreshSnapshot();
    return operation();
  }

  public getEntry(value: Uint8Array) {
    return this.read(() => this.state.getEntry(value));
  }
  public scanEntries(afterSeq: bigint, limit: number) {
    return this.read(() => this.state.scanEntries(afterSeq, limit));
  }
  public loadCll() {
    return this.read(() => this.state.cll());
  }
  public pendingWitnesses(now: Date, limit: number) {
    return this.read(() => this.state.pendingWitnesses(now, limit));
  }
  public getWitness(witnessId: string, checkpointSize: bigint) {
    return this.read(() => this.state.getWitness(witnessId, checkpointSize));
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    await Promise.all([this.queue, this.sharedLock.tail]);
    this.closed = true;
    this.db.close();
    this.sharedLock.references -= 1;
    if (this.sharedLock.references === 0)
      SqliteStore.locks.delete(this.lockKey);
  }
}
