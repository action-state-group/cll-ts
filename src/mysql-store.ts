import mysql, {
  type Pool,
  type PoolConnection,
  type PoolOptions,
} from "mysql2/promise";
import { cloneCll, cloneRecord } from "./clone.js";
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
  validateIdentifier,
  type AppendInput,
  type CllState,
  type EnvelopeInput,
  type WitnessState,
} from "./types.js";

type WireRecord = WireState["records"][number];

/** MySQL 8 backend with normalized rows and one log-scoped transaction lock. */
export class MysqlStore extends MemoryStore {
  private operationQueue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly pool: Pool,
    private readonly logId: string,
  ) {
    super();
  }

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
      CREATE TABLE IF NOT EXISTS capsule_ledger_meta (
        log_id VARCHAR(191) PRIMARY KEY,
        cll LONGBLOB NOT NULL
      ) ENGINE=InnoDB
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS capsule_ledger_records (
        log_id VARCHAR(191) NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        capsule_id CHAR(64) NOT NULL,
        record LONGBLOB NOT NULL,
        PRIMARY KEY(log_id, seq),
        UNIQUE KEY uq_capsule(log_id, capsule_id)
      ) ENGINE=InnoDB
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS capsule_ledger_envelopes (
        log_id VARCHAR(191) NOT NULL,
        capsule_id CHAR(64) NOT NULL,
        digest CHAR(64) NOT NULL,
        envelope LONGBLOB NOT NULL,
        PRIMARY KEY(log_id, capsule_id, digest)
      ) ENGINE=InnoDB
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS capsule_ledger_nodes (
        log_id VARCHAR(191) NOT NULL,
        position BIGINT UNSIGNED NOT NULL,
        node BINARY(32) NOT NULL,
        PRIMARY KEY(log_id, position)
      ) ENGINE=InnoDB
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS capsule_ledger_witnesses (
        log_id VARCHAR(191) NOT NULL,
        witness_id VARCHAR(191) NOT NULL,
        checkpoint_size VARCHAR(32) NOT NULL,
        attempts INT UNSIGNED NOT NULL,
        witness LONGBLOB NOT NULL,
        PRIMARY KEY(log_id, witness_id, checkpoint_size)
      ) ENGINE=InnoDB
    `);
    const empty = stateToWire([], {
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [],
    }).cll;
    await pool.execute(
      "INSERT IGNORE INTO capsule_ledger_meta(log_id,cll) VALUES(?,?)",
      [logId, JSON.stringify(empty)],
    );
    const store = new MysqlStore(pool, logId);
    await store.serialized(() => store.refreshReadTransaction());
    return store;
  }

  private async refresh(
    connection: Pool | PoolConnection = this.pool,
    forUpdate = false,
  ): Promise<void> {
    const [metaRows] = await connection.execute(
      `SELECT cll FROM capsule_ledger_meta WHERE log_id=?${forUpdate ? " FOR UPDATE" : ""}`,
      [this.logId],
    );
    const [recordRows] = await connection.execute(
      "SELECT record FROM capsule_ledger_records WHERE log_id=? ORDER BY seq ASC",
      [this.logId],
    );
    const [envelopeRows] = await connection.execute(
      "SELECT capsule_id,envelope FROM capsule_ledger_envelopes WHERE log_id=? ORDER BY capsule_id,digest",
      [this.logId],
    );
    const [nodeRows] = await connection.execute(
      "SELECT node FROM capsule_ledger_nodes WHERE log_id=? ORDER BY position ASC",
      [this.logId],
    );
    const [witnessRows] = await connection.execute(
      "SELECT witness FROM capsule_ledger_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
      [this.logId],
    );
    try {
      const meta = (metaRows as Array<{ cll: Buffer | string }>)[0];
      if (meta === undefined) throw new Error("missing ledger metadata row");
      const state = stateFromRows({
        records: (recordRows as Array<{ record: Buffer | string }>).map(
          (row) => JSON.parse(String(row.record)) as WireRecord,
        ),
        envelopes: (
          envelopeRows as Array<{
            capsule_id: string;
            envelope: Buffer | string;
          }>
        ).map((row) => ({
          capsuleId: row.capsule_id,
          envelope: JSON.parse(String(row.envelope)) as WireEnvelope,
        })),
        cll: JSON.parse(String(meta.cll)) as WireState["cll"],
        nodes: (nodeRows as Array<{ node: Buffer }>).map((row) => row.node),
        witnesses: (witnessRows as Array<{ witness: Buffer | string }>).map(
          (row) => JSON.parse(String(row.witness)) as WireWitness,
        ),
      });
      this.replaceState(state.records, state.cll);
    } catch (error) {
      if (error instanceof LedgerError && error.code === "corrupt") throw error;
      throw new LedgerError("corrupt", "stored MySQL ledger state is corrupt", {
        cause: error,
      });
    }
  }

  private async serialized<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.operationQueue;
    let release!: () => void;
    this.operationQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
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
      let rollbackError: unknown;
      try {
        await connection.rollback();
      } catch (failure) {
        rollbackError = failure;
      }
      if (rollbackError !== undefined)
        throw new AggregateError(
          [error, rollbackError],
          "MySQL read transaction and rollback both failed",
        );
      throw error;
    } finally {
      connection.release();
    }
  }

  private async transaction<T>(
    operation: () => Promise<T>,
    persist: (connection: PoolConnection, result: T) => Promise<void>,
  ): Promise<T> {
    return this.serialized(() => this.transactionLocked(operation, persist));
  }

  private async transactionLocked<T>(
    operation: () => Promise<T>,
    persist: (connection: PoolConnection, result: T) => Promise<void>,
  ): Promise<T> {
    const connection = await this.pool.getConnection();
    let beforeRecords: ReturnType<typeof cloneRecord>[] | undefined;
    let beforeCll: CllState | undefined;
    try {
      await connection.beginTransaction();
      await this.refresh(connection, true);
      beforeRecords = this.records.map(cloneRecord);
      beforeCll = cloneCll(this.cll);
      const result = await operation();
      await persist(connection, result);
      await connection.commit();
      return result;
    } catch (error) {
      let rollbackError: unknown;
      try {
        await connection.rollback();
      } catch (failure) {
        rollbackError = failure;
      }
      if (beforeRecords !== undefined && beforeCll !== undefined)
        this.replaceState(beforeRecords, beforeCll);
      if (rollbackError !== undefined)
        throw new AggregateError(
          [error, rollbackError],
          "MySQL transaction and rollback both failed",
        );
      throw error;
    } finally {
      connection.release();
    }
  }

  public override append(input: AppendInput) {
    return this.transaction(
      () => super.append(input),
      async (connection, result) => {
        if (result.outcome !== "inserted") return;
        await connection.execute(
          "INSERT INTO capsule_ledger_records(log_id,seq,capsule_id,record) VALUES(?,?,?,?)",
          [
            this.logId,
            String(result.record.seq),
            result.record.capsuleId,
            JSON.stringify(recordToWire({ ...result.record, envelopes: [] })),
          ],
        );
        for (const envelope of result.record.envelopes)
          await connection.execute(
            "INSERT INTO capsule_ledger_envelopes(log_id,capsule_id,digest,envelope) VALUES(?,?,?,?)",
            [
              this.logId,
              result.record.capsuleId,
              envelope.digest,
              JSON.stringify(envelopeToWire(envelope)),
            ],
          );
      },
    );
  }

  public override addEnvelope(input: EnvelopeInput) {
    return this.transaction(
      () => super.addEnvelope(input),
      async (connection, result) => {
        if (result.outcome !== "inserted") return;
        await connection.execute(
          "INSERT INTO capsule_ledger_envelopes(log_id,capsule_id,digest,envelope) VALUES(?,?,?,?)",
          [
            this.logId,
            input.capsuleId,
            result.envelope.digest,
            JSON.stringify(envelopeToWire(result.envelope)),
          ],
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
      async (connection) => {
        const committed = this.cll;
        const wire = stateToWire([], {
          ...committed,
          nodes: [],
          witnesses: [],
        }).cll;
        await connection.execute(
          "UPDATE capsule_ledger_meta SET cll=? WHERE log_id=?",
          [JSON.stringify(wire), this.logId],
        );
        for (
          let position = Number(expectedSize);
          position < committed.nodes.length;
          position += 1
        )
          await connection.execute(
            "INSERT INTO capsule_ledger_nodes(log_id,position,node) VALUES(?,?,?)",
            [
              this.logId,
              String(position),
              Buffer.from(committed.nodes[position]!),
            ],
          );
        for (const witness of this.witnessDelta(
          beforeWitnesses,
          committed.witnesses,
        ))
          await connection.execute(
            "INSERT INTO capsule_ledger_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
            [
              this.logId,
              witness.witnessId,
              String(witness.checkpointSize),
              witness.attempts,
              JSON.stringify(witnessToWire(witness)),
            ],
          );
      },
    );
  }

  public override commitWitness(expectedAttempts: number, next: WitnessState) {
    return this.transaction(
      () => super.commitWitness(expectedAttempts, next),
      async (connection) => {
        const [result] = await connection.execute(
          "UPDATE capsule_ledger_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
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
          throw new Error("witness CAS failed");
      },
    );
  }

  public override async get(id: string) {
    return this.readSnapshot(() => super.get(id));
  }
  public override async scan(after: bigint, limit: number) {
    return this.readSnapshot(() => super.scan(after, limit));
  }
  public override async loadCll() {
    return this.readSnapshot(() => super.loadCll());
  }
  public override async findChainGaps() {
    return this.readSnapshot(() => super.findChainGaps());
  }
  public override async pendingWitnesses(now: Date, limit: number) {
    return this.readSnapshot(() => super.pendingWitnesses(now, limit));
  }
  public override async getWitness(witnessId: string, checkpointSize: bigint) {
    return this.readSnapshot(() => super.getWitness(witnessId, checkpointSize));
  }
  private async readSnapshot<T>(operation: () => Promise<T>): Promise<T> {
    return this.serialized(async () => {
      await this.refreshReadTransaction();
      return operation();
    });
  }
  public override async close(): Promise<void> {
    if (this.closed) return;
    await this.operationQueue;
    await this.pool.end();
    await super.close();
  }
}
