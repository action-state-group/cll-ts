import mysql, {
  type Pool,
  type PoolConnection,
  type PoolOptions,
} from "mysql2/promise";
import { addedWitnesses, BackendState } from "./backend-state.js";
import { cloneCll } from "./clone.js";
import {
  cllToWire,
  entryToWire,
  stateFromRows,
  witnessToWire,
  type WireCllState,
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

/** MySQL 8 backend with one log-scoped metadata row lock per transaction. */
export class MysqlStore implements CllBackend {
  private readonly state = new BackendState();
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
    await backend.serialized(() => backend.refreshReadTransaction());
    return backend;
  }

  private ensureOpen(): void {
    if (this.closed) throw new CllError("closed", "backend is closed");
  }

  private async refresh(
    connection: Pool | PoolConnection,
    forUpdate = false,
  ): Promise<void> {
    const [metaRows] = await connection.execute(
      `SELECT state FROM cll_meta WHERE log_id=?${forUpdate ? " FOR UPDATE" : ""}`,
      [this.logId],
    );
    const [entryRows] = await connection.execute(
      "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
      [this.logId],
    );
    const [nodeRows] = await connection.execute(
      "SELECT node FROM cll_nodes WHERE log_id=? ORDER BY position",
      [this.logId],
    );
    const [witnessRows] = await connection.execute(
      "SELECT witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      [this.logId],
    );
    try {
      const meta = (metaRows as Array<{ state: Buffer | string }>)[0];
      if (meta === undefined) throw new Error("missing CLL metadata");
      const nodes = (nodeRows as Array<{ node: Buffer }>).map(
        (row) => row.node,
      );
      const decoded = stateFromRows({
        cll: JSON.parse(String(meta.state)) as WireCllState,
        entries: (
          entryRows as Array<{
            seq: string | number;
            value: Buffer;
            appended_at: string;
          }>
        ).map((row) => ({
          seq: String(row.seq),
          value: row.value.toString("base64"),
          appendedAt: row.appended_at,
        })),
        nodes,
        witnesses: (witnessRows as Array<{ witness: Buffer | string }>).map(
          (row) => JSON.parse(String(row.witness)) as WireWitness,
        ),
      });
      this.state.replace(decoded.entries, decoded.cll);
    } catch (error) {
      if (error instanceof CllError) throw error;
      throw new CllError("corrupt", "stored MySQL CLL state is corrupt", {
        cause: error,
      });
    }
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

  private async refreshReadTransaction(): Promise<void> {
    const connection = await this.pool.getConnection();
    try {
      await connection.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
      await connection.beginTransaction();
      await this.refresh(connection);
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private async transaction<T>(
    operation: () => T,
    persist: (connection: PoolConnection, result: T) => Promise<void>,
  ): Promise<T> {
    return this.serialized(async () => {
      const connection = await this.pool.getConnection();
      let entries: ReturnType<BackendState["entries"]> | undefined;
      let cll: CllState | undefined;
      try {
        await connection.beginTransaction();
        await this.refresh(connection, true);
        entries = this.state.entries();
        cll = this.state.cll();
        const result = operation();
        await persist(connection, result);
        await connection.commit();
        return result;
      } catch (error) {
        await connection.rollback();
        if (entries !== undefined && cll !== undefined)
          this.state.replace(entries, cll);
        throw error;
      } finally {
        connection.release();
      }
    });
  }

  private async persistCll(connection: PoolConnection, before: CllState) {
    const current = this.state.cll();
    const metadata = cllToWire({ ...current, nodes: [], witnesses: [] });
    await connection.execute("UPDATE cll_meta SET state=? WHERE log_id=?", [
      JSON.stringify(metadata),
      this.logId,
    ]);
    for (
      let position = before.nodes.length;
      position < current.nodes.length;
      position += 1
    )
      await connection.execute(
        "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)",
        [this.logId, String(position), Buffer.from(current.nodes[position]!)],
      );
    for (const witness of addedWitnesses(before.witnesses, current.witnesses))
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
  }

  public append(input: AppendInput) {
    return this.transaction(
      () => this.state.append(input),
      async (connection, result) => {
        if (result.outcome !== "inserted") return;
        const wire = entryToWire(result.entry);
        await connection.execute(
          "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
          [
            this.logId,
            String(result.entry.seq),
            Buffer.from(result.entry.value),
            wire.appendedAt,
          ],
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
      (connection) => this.persistCll(connection, before),
    );
  }

  public commitWitness(expectedAttempts: number, next: WitnessState) {
    return this.transaction(
      () => this.state.commitWitness(expectedAttempts, next),
      async (connection) => {
        const [result] = await connection.execute(
          "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
          [
            next.attempts,
            JSON.stringify(witnessToWire(next)),
            this.logId,
            next.witnessId,
            String(next.checkpointSize),
            expectedAttempts,
          ],
        );
        if ((result as { affectedRows: number }).affectedRows !== 1)
          throw new CllError("contention", "witness CAS failed");
      },
    );
  }

  private read<T>(operation: () => T): Promise<T> {
    return this.serialized(async () => {
      await this.refreshReadTransaction();
      return operation();
    });
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
    await this.queue;
    this.closed = true;
    await this.pool.end();
  }
}
