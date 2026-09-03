import mysql, {
  type Pool,
  type PoolConnection,
  type PoolOptions,
} from "mysql2/promise";
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

interface MysqlEntryRow {
  readonly seq: string | number;
  readonly value: Buffer;
  readonly appended_at: string;
}

/** MySQL 8 backend with one log-scoped metadata row lock per write. */
export class MysqlStore implements CllBackend {
  private queue: Promise<void> = Promise.resolve();
  private closed = false;

  private constructor(
    private readonly pool: Pool,
    private readonly logId: string,
  ) {}

  public static async open(
    options: PoolOptions | string,
    logId = "default",
  ): Promise<MysqlStore> {
    validateIdentifier(logId);
    const pool =
      typeof options === "string"
        ? mysql.createPool(options)
        : mysql.createPool(options);
    try {
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS cll_meta (
          log_id VARCHAR(191) PRIMARY KEY,
          state LONGBLOB NOT NULL
        ) ENGINE=InnoDB
      `);
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS cll_entries (
          log_id VARCHAR(191) NOT NULL,
          seq BIGINT UNSIGNED NOT NULL,
          value BINARY(32) NOT NULL,
          appended_at VARCHAR(32) NOT NULL,
          PRIMARY KEY(log_id, seq),
          UNIQUE KEY uq_cll_entry(log_id, value)
        ) ENGINE=InnoDB
      `);
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS cll_nodes (
          log_id VARCHAR(191) NOT NULL,
          position BIGINT UNSIGNED NOT NULL,
          node BINARY(32) NOT NULL,
          PRIMARY KEY(log_id, position)
        ) ENGINE=InnoDB
      `);
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS cll_witnesses (
          log_id VARCHAR(191) NOT NULL,
          witness_id VARCHAR(191) NOT NULL,
          checkpoint_size VARCHAR(32) NOT NULL,
          attempts INT UNSIGNED NOT NULL,
          witness LONGBLOB NOT NULL,
          PRIMARY KEY(log_id, witness_id, checkpoint_size)
        ) ENGINE=InnoDB
      `);
      const empty = cllToWire({
        size: 0n,
        nodes: [],
        indexedSeq: 0n,
        witnesses: [],
      });
      await pool.execute(
        "INSERT IGNORE INTO cll_meta(log_id,state) VALUES(?,?)",
        [logId, JSON.stringify(empty)],
      );
      const backend = new MysqlStore(pool, logId);
      await backend.serialized(() => backend.validateSnapshot());
      return backend;
    } catch (error) {
      await pool.end();
      throw error;
    }
  }

  private ensureOpen(): void {
    if (this.closed) throw new CllError("closed", "backend is closed");
  }

  private async serialized<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      this.ensureOpen();
      return await operation();
    } finally {
      release();
    }
  }

  private async withConnection<T>(
    readOnly: boolean,
    operation: (connection: PoolConnection) => Promise<T>,
  ): Promise<T> {
    const connection = await this.pool.getConnection();
    try {
      if (readOnly)
        await connection.query(
          "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        );
      await connection.beginTransaction();
      const result = await operation(connection);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private read<T>(operation: (query: Pool) => Promise<T>): Promise<T> {
    return this.serialized(() => operation(this.pool));
  }

  private readSnapshot<T>(
    operation: (connection: PoolConnection) => Promise<T>,
  ): Promise<T> {
    return this.serialized(() => this.withConnection(true, operation));
  }

  private write<T>(
    operation: (connection: PoolConnection) => Promise<T>,
  ): Promise<T> {
    return this.serialized(() =>
      this.withConnection(false, async (connection) => {
        const [metadata] = await connection.execute(
          "SELECT state FROM cll_meta WHERE log_id=? FOR UPDATE",
          [this.logId],
        );
        if ((metadata as unknown[]).length !== 1)
          throw new CllError("corrupt", "missing CLL metadata");
        return operation(connection);
      }),
    );
  }

  private async validateSnapshot(): Promise<void> {
    await this.withConnection(true, async (connection) => {
      const [rows] = await connection.execute(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
        [this.logId],
      );
      (rows as MysqlEntryRow[]).forEach((row, index) => {
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
      await this.loadCllDirect(connection);
    });
  }

  private async loadCllDirect(query: Pool | PoolConnection): Promise<CllState> {
    const [metadataRows] = await query.execute(
      "SELECT state FROM cll_meta WHERE log_id=?",
      [this.logId],
    );
    const metadata = (metadataRows as Array<{ state: Buffer | string }>)[0];
    if (metadata === undefined)
      throw new CllError("corrupt", "missing CLL metadata");
    const [nodeRows] = await query.execute(
      "SELECT position,node FROM cll_nodes WHERE log_id=? ORDER BY position",
      [this.logId],
    );
    const [witnessRows] = await query.execute(
      "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      [this.logId],
    );
    return cllFromSqlRows(
      metadata.state,
      (nodeRows as Array<{ position: string | number; node: Buffer }>).map(
        (row): SqlNodeRow => ({ position: row.position, node: row.node }),
      ),
      witnessRows as SqlWitnessRow[],
    );
  }

  private async witnessRows(
    query: Pool | PoolConnection,
  ): Promise<SqlWitnessRow[]> {
    const [rows] = await query.execute(
      "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      [this.logId],
    );
    return rows as SqlWitnessRow[];
  }

  public append(input: AppendInput): Promise<AppendResult> {
    return this.write(async (connection) => {
      validateAppendInput(input);
      const [currentRows] = await connection.execute(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?",
        [this.logId, Buffer.from(input.value)],
      );
      const current = (currentRows as MysqlEntryRow[])[0];
      if (current !== undefined)
        return {
          entry: entryFromSqlRow({
            seq: current.seq,
            value: current.value,
            appendedAt: current.appended_at,
          }),
          outcome: "idempotent",
        };
      const [maximumRows] = await connection.execute(
        "SELECT MAX(seq) AS maximum FROM cll_entries WHERE log_id=?",
        [this.logId],
      );
      const maximum = (
        maximumRows as Array<{ maximum: string | number | null }>
      )[0]?.maximum;
      const seq = BigInt(maximum ?? 0) + 1n;
      if (seq > BigInt(Number.MAX_SAFE_INTEGER))
        throw new CllError("invalid", "entry sequence exceeds portable range");
      const entry: CllEntry = {
        seq,
        value: Uint8Array.from(input.value),
        appendedAt: new Date(Math.trunc(input.appendedAt.valueOf())),
      };
      const wire = entryToWire(entry);
      await connection.execute(
        "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
        [this.logId, String(seq), Buffer.from(entry.value), wire.appendedAt],
      );
      return { entry, outcome: "inserted" };
    });
  }

  public getEntry(value: Uint8Array): Promise<CllEntry> {
    return this.read(async (query) => {
      validateEntryValue(value);
      const [rows] = await query.execute(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?",
        [this.logId, Buffer.from(value)],
      );
      const row = (rows as MysqlEntryRow[])[0];
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
    return this.read(async (query) => {
      validateEntryScan(afterSeq, limit);
      const [rows] = await query.execute(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND seq>? ORDER BY seq LIMIT ?",
        [this.logId, String(afterSeq), limit],
      );
      return (rows as MysqlEntryRow[]).map((row) =>
        entryFromSqlRow({
          seq: row.seq,
          value: row.value,
          appendedAt: row.appended_at,
        }),
      );
    });
  }

  public loadCll(): Promise<CllState> {
    return this.readSnapshot((connection) => this.loadCllDirect(connection));
  }

  public commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void> {
    return this.write(async (connection) => {
      const current = await this.loadCllDirect(connection);
      const updated = applyCll(current, expectedSize, expectedCheckpoint, next);
      const metadata = cllToWire({ ...updated, nodes: [], witnesses: [] });
      await connection.execute("UPDATE cll_meta SET state=? WHERE log_id=?", [
        JSON.stringify(metadata),
        this.logId,
      ]);
      for (
        let position = current.nodes.length;
        position < updated.nodes.length;
        position += 1
      )
        await connection.execute(
          "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)",
          [this.logId, String(position), Buffer.from(updated.nodes[position]!)],
        );
      for (const witness of addedWitnesses(
        current.witnesses,
        updated.witnesses,
      ))
        await connection.execute(
          "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
          [
            this.logId,
            witness.witnessId,
            String(witness.checkpointSize),
            witness.attempts,
            JSON.stringify(witnessToWire(witness)),
          ],
        );
    });
  }

  public pendingWitnesses(
    now: Date,
    limit: number,
  ): Promise<readonly WitnessState[]> {
    return this.read(async (query) =>
      selectPendingWitnesses(
        (await this.witnessRows(query)).map(witnessFromSqlRow),
        now,
        limit,
      ),
    );
  }

  public getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): Promise<WitnessState | undefined> {
    return this.read(async (query) => {
      const [rows] = await query.execute(
        "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
        [this.logId, witnessId, String(checkpointSize)],
      );
      const row = (rows as SqlWitnessRow[])[0];
      return row === undefined ? undefined : witnessFromSqlRow(row);
    });
  }

  public commitWitness(
    expectedAttempts: number,
    next: WitnessState,
  ): Promise<void> {
    return this.write(async (connection) => {
      const [rows] = await connection.execute(
        "SELECT witness_id AS witnessId,checkpoint_size AS checkpointSize,attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
        [this.logId, next.witnessId, String(next.checkpointSize)],
      );
      const row = (rows as SqlWitnessRow[])[0];
      if (row === undefined)
        throw new CllError("contention", "witness state changed");
      const updated = applyWitness(
        witnessFromSqlRow(row),
        expectedAttempts,
        next,
      );
      const [result] = await connection.execute(
        "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
        [
          updated.attempts,
          JSON.stringify(witnessToWire(updated)),
          this.logId,
          updated.witnessId,
          String(updated.checkpointSize),
          expectedAttempts,
        ],
      );
      if ((result as { affectedRows: number }).affectedRows !== 1)
        throw new CllError("contention", "witness CAS failed");
    });
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    await this.queue;
    this.closed = true;
    await this.pool.end();
  }
}
