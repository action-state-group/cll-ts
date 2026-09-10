import { MySqlContainer } from "@testcontainers/mysql";
import mysql from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  CheckpointRunner,
  CllError,
  createCheckpointIdentity,
} from "../src/index.js";
import type { CllBackend } from "../src/index.js";
import { MysqlStore } from "../src/mysql.js";
import { backendContract, crossHandleContract } from "./backend-contract.js";

describe("MySQL backend", () => {
  let container: Awaited<ReturnType<MySqlContainer["start"]>>;
  const open: CllBackend[] = [];

  beforeAll(async () => {
    container = await new MySqlContainer("mysql:8.4")
      .withDatabase("cll")
      .withUsername("cll")
      .withUserPassword("cll-password")
      .start();
  }, 120_000);

  afterAll(async () => {
    await Promise.all(open.map((backend) => backend.close()));
    await container.stop();
  });

  it("runs the complete shared contract", async () => {
    const backend = await MysqlStore.open(
      container.getConnectionUri(),
      "contract",
    );
    open.push(backend);
    await backendContract(backend);
  }, 60_000);

  it("allocates dense sequences across handles", async () => {
    const first = await MysqlStore.open(container.getConnectionUri(), "shared");
    const second = await MysqlStore.open(
      container.getConnectionUri(),
      "shared",
    );
    open.push(first, second);
    await crossHandleContract(first, second);
  }, 60_000);

  it("fails closed if the locked log metadata row disappears", async () => {
    const backend = await MysqlStore.open(
      container.getConnectionUri(),
      "missing-meta",
    );
    open.push(backend);
    const connection = await mysql.createConnection(
      container.getConnectionUri(),
    );
    try {
      await connection.execute("DELETE FROM cll_meta WHERE log_id=?", [
        "missing-meta",
      ]);
    } finally {
      await connection.end();
    }
    await expect(
      backend.append({ value: new Uint8Array(32), appendedAt: new Date(0) }),
    ).rejects.toMatchObject({ code: "corrupt" } satisfies Partial<CllError>);
  }, 60_000);

  it("commits different witnesses without serializing on cll_meta", async () => {
    const uri = container.getConnectionUri();
    const store = await MysqlStore.open(uri, "witness-parallel");
    open.push(store);
    const runner = new CheckpointRunner(store, {
      logId: "witness-parallel",
      identity: createCheckpointIdentity(new Uint8Array(32)),
      witnessIds: ["w1", "w2"],
      entryCadence: 1,
      clock: () => new Date("2026-09-05T00:00:00Z"),
    });
    await store.append({
      value: Uint8Array.from({ length: 32 }, () => 1),
      appendedAt: new Date("2026-09-05T00:00:00Z"),
    });
    const checkpoint = await runner.runOnce();
    expect(checkpoint).toBeDefined();
    const size = checkpoint!.mmrSize;
    const w1 = await store.getWitness("w1", size);
    const w2 = await store.getWitness("w2", size);
    expect(w1).toBeDefined();
    expect(w2).toBeDefined();

    // Hold the cll_meta row lock in an independent transaction. commitWitness
    // must not take that lock, so both commits (distinct witness_id) complete
    // while it is held; a meta FOR UPDATE inside commitWitness would block here.
    const blocker = await mysql.createConnection(uri);
    await blocker.beginTransaction();
    await blocker.execute(
      "SELECT state FROM cll_meta WHERE log_id=? FOR UPDATE",
      ["witness-parallel"],
    );
    try {
      await Promise.all([
        store.commitWitness(w1!.attempts, {
          ...w1!,
          attempts: w1!.attempts + 1,
          nextAttemptAt: new Date("2026-09-05T00:01:00Z"),
        }),
        store.commitWitness(w2!.attempts, {
          ...w2!,
          attempts: w2!.attempts + 1,
          nextAttemptAt: new Date("2026-09-05T00:01:00Z"),
        }),
      ]);
    } finally {
      await blocker.rollback();
      await blocker.end();
    }
    expect((await store.getWitness("w1", size))?.attempts).toBe(
      w1!.attempts + 1,
    );
    expect((await store.getWitness("w2", size))?.attempts).toBe(
      w2!.attempts + 1,
    );
  }, 60_000);

  it("drains an in-flight operation before pool teardown on close", async () => {
    // connectionLimit: 1 forces the second operation to queue for the single
    // pooled connection. close() must wait for both to settle rather than let
    // pool.end() reject the queued acquisition.
    const store = await MysqlStore.open(
      { uri: container.getConnectionUri(), connectionLimit: 1 },
      "close-drain",
    );
    await store.append({
      value: Uint8Array.from({ length: 32 }, () => 7),
      appendedAt: new Date("2026-09-05T00:00:00Z"),
    });
    // First op holds the only connection; second enqueues behind it.
    const first = store.getEntry(Uint8Array.from({ length: 32 }, () => 7));
    const second = store.scanEntries(0n, 10);
    const closing = store.close();
    const [firstResult, secondResult, closeResult] = await Promise.allSettled([
      first,
      second,
      closing,
    ]);
    expect(closeResult.status).toBe("fulfilled");
    // Both operations settle on their own terms (they were admitted before
    // close); neither is rejected by pool teardown mid-acquisition.
    expect(firstResult.status).toBe("fulfilled");
    expect(secondResult.status).toBe("fulfilled");
  }, 60_000);

  it("shares one drain across concurrent close calls", async () => {
    // Every close() caller must await the same drain-then-end sequence; a second
    // concurrent call must not resolve early while the pool is still closing.
    const store = await MysqlStore.open(
      { uri: container.getConnectionUri(), connectionLimit: 1 },
      "close-shared",
    );
    const first = store.close();
    const second = store.close();
    expect(second).toBe(first);
    await expect(Promise.all([first, second])).resolves.toBeDefined();
    // A later close() after completion is still idempotent and resolved.
    await expect(store.close()).resolves.toBeUndefined();
  }, 60_000);

  it("rejects an entry sequence gap when reopened", async () => {
    const backend = await MysqlStore.open(
      container.getConnectionUri(),
      "entry-gap",
    );
    open.push(backend);
    await backend.append({
      value: new Uint8Array(32),
      appendedAt: new Date(0),
    });
    await backend.append({
      value: new Uint8Array(32).fill(1),
      appendedAt: new Date(1),
    });
    await backend.close();
    const connection = await mysql.createConnection(
      container.getConnectionUri(),
    );
    try {
      await connection.execute(
        "DELETE FROM cll_entries WHERE log_id=? AND seq=1",
        ["entry-gap"],
      );
    } finally {
      await connection.end();
    }
    await expect(
      MysqlStore.open(container.getConnectionUri(), "entry-gap"),
    ).rejects.toMatchObject({ code: "corrupt" } satisfies Partial<CllError>);
  }, 60_000);
});
