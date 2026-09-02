import { MySqlContainer } from "@testcontainers/mysql";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build, createEd25519Identity } from "capsule-emit-ts";
import {
  CheckpointRunner,
  LedgerError,
  LedgerService,
  MysqlStore,
  type Store,
} from "../src/index.js";
import {
  checkpointPersistenceContract,
  witnessMergeContract,
} from "./helpers.js";

describe("MySQL 8 backend", () => {
  let container: Awaited<ReturnType<MySqlContainer["start"]>>;
  const stores: Store[] = [];
  beforeAll(async () => {
    container = await new MySqlContainer("mysql:8.4")
      .withDatabase("ledger")
      .withUsername("ledger")
      .withUserPassword("ledger-password")
      .start();
  }, 120_000);
  afterAll(async () => {
    await Promise.all(stores.map((store) => store.close()));
    await container.stop();
  });
  it("allocates contiguous sequences across concurrent handles", async () => {
    const uri = container.getConnectionUri();
    const first = await MysqlStore.open(uri, "integration");
    const second = await MysqlStore.open(uri, "integration");
    stores.push(first, second);
    const clock = () => new Date("2026-09-01T12:00:00Z");
    const a = new LedgerService(first, {}, clock);
    const b = new LedgerService(second, {}, clock);
    const one = build({
      actionId: "mysql-1",
      actionType: "fyi",
      operator: "test",
      developer: "test@v1",
      timestamp: clock(),
    });
    const two = build({
      actionId: "mysql-2",
      actionType: "fyi",
      operator: "test",
      developer: "test@v1",
      timestamp: clock(),
    });
    const records = await Promise.all([
      a.append("unsigned", one.json),
      b.append("unsigned", two.json),
    ]);
    expect(new Set(records.map((record) => record.seq))).toEqual(
      new Set([1n, 2n]),
    );
    expect((await first.scan(0n, 10)).length).toBe(2);
  }, 60_000);
  it("preserves concurrent witness updates across CLL commits", async () => {
    const uri = container.getConnectionUri();
    const first = await MysqlStore.open(uri, "witness-merge");
    const second = await MysqlStore.open(uri, "witness-merge");
    stores.push(first, second);
    await witnessMergeContract(first, second);
  }, 60_000);
  it("refreshes checkpoint metadata across handles", async () => {
    const uri = container.getConnectionUri();
    const first = await MysqlStore.open(uri, "checkpoint-persistence");
    const second = await MysqlStore.open(uri, "checkpoint-persistence");
    stores.push(first, second);
    await checkpointPersistenceContract(first, second);
  }, 60_000);
  it("reads normalized tables from one repeatable-read snapshot", async () => {
    const uri = container.getConnectionUri();
    const writer = await MysqlStore.open(uri, "read-snapshot");
    const reader = await MysqlStore.open(uri, "read-snapshot");
    stores.push(writer, reader);
    const clock = () => new Date("2026-09-01T12:00:00Z");
    const service = new LedgerService(writer, {}, clock);
    await service.append(
      "unsigned",
      build({
        actionId: "mysql-snapshot",
        actionType: "fyi",
        operator: "test",
        developer: "test@v1",
        timestamp: clock(),
      }).json,
    );
    const runner = new CheckpointRunner(writer, {
      logId: "read-snapshot",
      identity: createEd25519Identity(
        Uint8Array.of(...Array<number>(32).fill(7)),
      ),
      entryCadence: 1,
      clock,
    });

    const internal = reader as unknown as {
      pool: { getConnection(): Promise<object> };
    };
    const originalGetConnection = internal.pool.getConnection.bind(
      internal.pool,
    );
    let reachedMeta!: () => void;
    const metaRead = new Promise<void>((resolve) => {
      reachedMeta = resolve;
    });
    let releaseRead!: () => void;
    const continueRead = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    Reflect.set(internal.pool, "getConnection", async () => {
      const connection = await originalGetConnection();
      const target = connection as {
        execute: (...args: readonly unknown[]) => Promise<unknown>;
      };
      const originalExecute = target.execute.bind(target);
      let intercepted = false;
      Reflect.set(
        target,
        "execute",
        async (...args: readonly unknown[]): Promise<unknown> => {
          const result = await originalExecute(...args);
          if (
            !intercepted &&
            typeof args[0] === "string" &&
            args[0].startsWith("SELECT cll FROM capsule_ledger_meta")
          ) {
            intercepted = true;
            reachedMeta();
            await continueRead;
            Reflect.set(target, "execute", originalExecute);
          }
          return result;
        },
      );
      return connection;
    });
    const snapshot = reader.loadCll();
    await metaRead;
    await expect(runner.runOnce()).resolves.toBeDefined();
    releaseRead();
    expect((await snapshot).size).toBe(0n);
    Reflect.set(internal.pool, "getConnection", originalGetConnection);
    expect((await reader.loadCll()).size).toBe(1n);
  }, 60_000);
  it("serializes same-handle reads with CLL commits", async () => {
    const uri = container.getConnectionUri();
    const store = await MysqlStore.open(uri, "same-handle-queue");
    stores.push(store);
    const clock = () => new Date("2026-09-01T12:00:00Z");
    const service = new LedgerService(store, {}, clock);
    await service.append(
      "unsigned",
      build({
        actionId: "mysql-same-handle",
        actionType: "fyi",
        operator: "test",
        developer: "test@v1",
        timestamp: clock(),
      }).json,
    );
    const runner = new CheckpointRunner(store, {
      logId: "same-handle-queue",
      identity: createEd25519Identity(new Uint8Array(32)),
      entryCadence: 1,
      clock,
    });

    const internal = store as unknown as {
      refreshReadTransaction(): Promise<void>;
    };
    const originalRefresh = internal.refreshReadTransaction.bind(internal);
    let reachedRefresh!: () => void;
    const refreshComplete = new Promise<void>((resolve) => {
      reachedRefresh = resolve;
    });
    let releaseRead!: () => void;
    const continueRead = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    Reflect.set(internal, "refreshReadTransaction", async () => {
      await originalRefresh();
      reachedRefresh();
      await continueRead;
    });
    const read = store.loadCll();
    await refreshComplete;
    let checkpointSettled = false;
    const checkpoint = runner.runOnce().finally(() => {
      checkpointSettled = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(checkpointSettled).toBe(false);
    Reflect.set(internal, "refreshReadTransaction", originalRefresh);
    releaseRead();
    await expect(read).resolves.toMatchObject({ size: 0n });
    await expect(checkpoint).resolves.toBeDefined();
    expect((await store.loadCll()).checkpointSize).toBe(1n);
  }, 60_000);
  it("reports orphaned durable rows as corruption", async () => {
    const uri = container.getConnectionUri();
    const store = await MysqlStore.open(uri, "corrupt-row");
    stores.push(store);
    const internal = store as unknown as {
      pool: {
        execute(sql: string, values: readonly string[]): Promise<unknown>;
      };
    };
    await internal.pool.execute(
      "INSERT INTO capsule_ledger_envelopes(log_id,capsule_id,digest,envelope) VALUES(?,?,?,?)",
      ["corrupt-row", "0".repeat(64), "1".repeat(64), "{}"],
    );
    await expect(store.loadCll()).rejects.toMatchObject({
      code: "corrupt",
    } satisfies Partial<LedgerError>);
  }, 60_000);
});
