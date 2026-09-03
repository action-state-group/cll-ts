import Database from "better-sqlite3";
import {
  addedWitnesses,
  applyCll,
  applyWitness,
  selectPendingWitnesses,
  validateAppendInput,
  validateEntryScan,
  validateEntryValue,
} from "./backend-state.js";
import { cllToWire, entryToWire, witnessToWire } from "./serde.js";
import {
  cllFromSqlRows,
  entryFromSqlRow,
  witnessFromSqlRow,
  type SqlNodeRow,
  type SqlWitnessRow,
} from "./sql-state.js";
import {
  CllError,
  validateIdentifier,
  type AppendInput,
  type AppendResult,
  type CllBackend,
  type CllEntry,
  type CllState,
  type WitnessState,
} from "./types.js";

interface SharedLock {
  tail: Promise<void>;
  references: number;
}

interface SqliteEntryRow {
  readonly seq: number;
  readonly value: Buffer;
  readonly appended_at: string;
}

/** SQLite backend with WAL durability and log-scoped transactions. */
export class SqliteStore implements CllBackend {
  private static readonly locks = new Map<string, SharedLock>();
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
    db.pragma("busy_timeout = 5000");
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
    try {
      backend.runTransaction("BEGIN", () => {
        backend.validateEntries();
        backend.loadCllDirect();
      });
      return backend;
    } catch (error) {
      db.close();
      sharedLock.references -= 1;
      if (sharedLock.references === 0) SqliteStore.locks.delete(lockKey);
      throw error;
    }
  }

  private ensureOpen(): void {
    if (this.closed) throw new CllError("closed", "backend is closed");
  }

  private runTransaction<T>(
    begin: "BEGIN" | "BEGIN IMMEDIATE",
    operation: () => T,
  ): T {
    this.db.exec(begin);
    try {
      const result = operation();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      if (this.db.inTransaction) this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private async exclusive<T>(operation: () => T): Promise<T> {
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
      return operation();
    } finally {
      release();
    }
  }

  private read<T>(operation: () => T): Promise<T> {
    return this.exclusive(() => this.runTransaction("BEGIN", operation));
  }

  private write<T>(operation: () => T): Promise<T> {
    return this.exclusive(() =>
      this.runTransaction("BEGIN IMMEDIATE", () => {
        const metadata = this.db
          .prepare("SELECT 1 AS present FROM cll_meta WHERE log_id=?")
          .get(this.logId) as { present: number } | undefined;
        if (metadata === undefined)
          throw new CllError("corrupt", "missing CLL metadata");
        return operation();
      }),
    );
  }

  private validateEntries(): void {
    const rows = this.db
      .prepare(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
      )
      .all(this.logId) as SqliteEntryRow[];
    rows.forEach((row, index) => {
      const entry = entryFromSqlRow({
        seq: row.seq,
        value: row.value,
        appendedAt: row.appended_at,
      });
      if (entry.seq !== BigInt(index + 1))
        throw new CllError(
          "corrupt",
          "stored CLL entries are not dense and valid",
        );
    });
  }

  private loadCllDirect(): CllState {
    const metadata = this.db
      .prepare("SELECT state FROM cll_meta WHERE log_id=?")
      .get(this.logId) as { state: Buffer | string } | undefined;
    if (metadata === undefined)
      throw new CllError("corrupt", "missing CLL metadata");
    const nodes = this.db
      .prepare(
        "SELECT position,node FROM cll_nodes WHERE log_id=? ORDER BY position",
      )
      .all(this.logId) as Array<{ position: number; node: Buffer }>;
    const witnesses = this.db
      .prepare(
        "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      )
      .all(this.logId) as SqlWitnessRow[];
    return cllFromSqlRows(
      metadata.state,
      nodes.map(
        (row): SqlNodeRow => ({ position: row.position, node: row.node }),
      ),
      witnesses,
    );
  }

  private witnessRows(): SqlWitnessRow[] {
    const rows = this.db
      .prepare(
        "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      )
      .all(this.logId) as SqlWitnessRow[];
    return rows;
  }

  public append(input: AppendInput): Promise<AppendResult> {
    return this.write(() => {
      validateAppendInput(input);
      const current = this.db
        .prepare(
          "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?",
        )
        .get(this.logId, input.value) as SqliteEntryRow | undefined;
      if (current !== undefined)
        return {
          entry: entryFromSqlRow({
            seq: current.seq,
            value: current.value,
            appendedAt: current.appended_at,
          }),
          outcome: "idempotent",
        };
      const row = this.db
        .prepare("SELECT MAX(seq) AS maximum FROM cll_entries WHERE log_id=?")
        .get(this.logId) as { maximum: number | null };
      const seq = BigInt(row.maximum ?? 0) + 1n;
      if (seq > BigInt(Number.MAX_SAFE_INTEGER))
        throw new CllError("invalid", "entry sequence exceeds portable range");
      const entry: CllEntry = {
        seq,
        value: Uint8Array.from(input.value),
        appendedAt: new Date(Math.trunc(input.appendedAt.valueOf())),
      };
      const wire = entryToWire(entry);
      this.db
        .prepare(
          "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
        )
        .run(this.logId, Number(seq), entry.value, wire.appendedAt);
      return { entry, outcome: "inserted" };
    });
  }

  public getEntry(value: Uint8Array): Promise<CllEntry> {
    return this.read(() => {
      validateEntryValue(value);
      const row = this.db
        .prepare(
          "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?",
        )
        .get(this.logId, value) as SqliteEntryRow | undefined;
      if (row === undefined) throw new CllError("not_found", "entry not found");
      return entryFromSqlRow({
        seq: row.seq,
        value: row.value,
        appendedAt: row.appended_at,
      });
    });
  }

  public scanEntries(
    afterSeq: bigint,
    limit: number,
  ): Promise<readonly CllEntry[]> {
    return this.read(() => {
      validateEntryScan(afterSeq, limit);
      const rows = this.db
        .prepare(
          "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND seq>? ORDER BY seq LIMIT ?",
        )
        .all(this.logId, Number(afterSeq), limit) as SqliteEntryRow[];
      return rows.map((row) =>
        entryFromSqlRow({
          seq: row.seq,
          value: row.value,
          appendedAt: row.appended_at,
        }),
      );
    });
  }

  public loadCll(): Promise<CllState> {
    return this.read(() => this.loadCllDirect());
  }

  public commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void> {
    return this.write(() => {
      const current = this.loadCllDirect();
      const updated = applyCll(current, expectedSize, expectedCheckpoint, next);
      const metadata = cllToWire({ ...updated, nodes: [], witnesses: [] });
      this.db
        .prepare("UPDATE cll_meta SET state=? WHERE log_id=?")
        .run(JSON.stringify(metadata), this.logId);
      const nodeInsert = this.db.prepare(
        "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)",
      );
      for (
        let position = current.nodes.length;
        position < updated.nodes.length;
        position += 1
      )
        nodeInsert.run(this.logId, position, updated.nodes[position]!);
      const witnessInsert = this.db.prepare(
        "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
      );
      for (const witness of addedWitnesses(
        current.witnesses,
        updated.witnesses,
      ))
        witnessInsert.run(
          this.logId,
          witness.witnessId,
          String(witness.checkpointSize),
          witness.attempts,
          JSON.stringify(witnessToWire(witness)),
        );
    });
  }

  public pendingWitnesses(
    now: Date,
    limit: number,
  ): Promise<readonly WitnessState[]> {
    return this.read(() =>
      selectPendingWitnesses(
        this.witnessRows().map(witnessFromSqlRow),
        now,
        limit,
      ),
    );
  }

  public getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): Promise<WitnessState | undefined> {
    return this.read(() => {
      const row = this.db
        .prepare(
          "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
        )
        .get(this.logId, witnessId, String(checkpointSize)) as
        | SqlWitnessRow
        | undefined;
      return row === undefined ? undefined : witnessFromSqlRow(row);
    });
  }

  public commitWitness(
    expectedAttempts: number,
    next: WitnessState,
  ): Promise<void> {
    return this.write(() => {
      const row = this.db
        .prepare(
          "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
        )
        .get(this.logId, next.witnessId, String(next.checkpointSize)) as
        | SqlWitnessRow
        | undefined;
      if (row === undefined)
        throw new CllError("contention", "witness state changed");
      const updated = applyWitness(
        witnessFromSqlRow(row),
        expectedAttempts,
        next,
      );
      const result = this.db
        .prepare(
          "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
        )
        .run(
          updated.attempts,
          JSON.stringify(witnessToWire(updated)),
          this.logId,
          updated.witnessId,
          String(updated.checkpointSize),
          expectedAttempts,
        );
      if (result.changes !== 1)
        throw new CllError("contention", "witness CAS failed");
    });
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
