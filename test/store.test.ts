import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { build } from "capsule-emit-ts";
import {
  JsonlStore,
  LedgerError,
  LedgerService,
  MemoryStore,
  SqliteStore,
  type Store,
} from "../src/index.js";
import {
  checkpointPersistenceContract,
  witnessMergeContract,
} from "./helpers.js";

const stores: Store[] = [];
afterEach(async () => {
  await Promise.all(stores.splice(0).map((store) => store.close()));
});
const capsule = (actionId: string) =>
  build({
    actionId,
    actionType: "fyi",
    operator: "test",
    developer: "test@v1",
    timestamp: "2026-09-01T12:00:00Z",
  });
async function contract(store: Store): Promise<void> {
  stores.push(store);
  const service = new LedgerService(
    store,
    {},
    () => new Date("2026-09-01T12:00:00Z"),
  );
  const first = capsule("first");
  const second = capsule("second");
  const [a, b] = await Promise.all([
    service.append("unsigned", first.json),
    service.append("unsigned", second.json),
  ]);
  expect(new Set([a.seq, b.seq])).toEqual(new Set([1n, 2n]));
  expect((await service.append("unsigned", first.json)).seq).toBe(a.seq);
  expect((await service.scan()).map((record) => record.seq)).toEqual([1n, 2n]);
  const copy = await service.get(first.capsuleId);
  copy.capsule[0] = 0;
  expect((await service.get(first.capsuleId)).capsule[0]).not.toBe(0);
}
describe("shared backend contract", () => {
  it("memory", () => contract(new MemoryStore()));
  it("rejects non-append-only CLL transitions", async () => {
    const store = new MemoryStore();
    stores.push(store);
    const first = Uint8Array.from({ length: 32 }, () => 1);
    await store.commitCll(0n, undefined, {
      size: 1n,
      nodes: [first],
      indexedSeq: 0n,
      witnesses: [],
    });
    await expect(
      store.commitCll(1n, undefined, {
        size: 1n,
        nodes: [Uint8Array.from({ length: 32 }, () => 2)],
        indexedSeq: 0n,
        witnesses: [],
      }),
    ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<LedgerError>);
    await expect(
      store.commitCll(1n, undefined, {
        size: 0n,
        nodes: [],
        indexedSeq: 0n,
        witnesses: [],
      }),
    ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<LedgerError>);
  });
  it("JSONL restart and torn tail", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-jsonl-")),
      "ledger.jsonl",
    );
    const store = await JsonlStore.open(path);
    await contract(store);
    await store.close();
    stores.pop();
    writeFileSync(path, "{torn", { flag: "a" });
    const reopened = await JsonlStore.open(path);
    stores.push(reopened);
    expect((await reopened.scan(0n, 10)).length).toBe(2);
  });
  it("JSONL rejects a second writer", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-lock-")),
      "ledger.jsonl",
    );
    const first = await JsonlStore.open(path);
    stores.push(first);
    await expect(JsonlStore.open(path)).rejects.toMatchObject({
      code: "contention",
    } satisfies Partial<LedgerError>);
  });
  it("JSONL rolls memory and disk back when an event write fails", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-jsonl-failure-")),
      "ledger.jsonl",
    );
    const store = await JsonlStore.open(path);
    stores.push(store);
    const service = new LedgerService(store);
    const before = readFileSync(path);
    const internal = store as unknown as {
      appendEvent(event: unknown): Promise<void>;
    };
    const appendEvent = internal.appendEvent.bind(store);
    internal.appendEvent = async () => {
      throw new Error("injected journal write failure");
    };
    await expect(
      service.append("unsigned", capsule("write-failure").json),
    ).rejects.toThrow("injected journal write failure");
    expect(await store.scan(0n, 10)).toEqual([]);
    expect(readFileSync(path)).toEqual(before);
    internal.appendEvent = appendEvent;
    await store.close();
    stores.pop();
    const reopened = await JsonlStore.open(path);
    stores.push(reopened);
    expect(await reopened.scan(0n, 10)).toEqual([]);
  });
  it("JSONL writes bounded incremental events", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-jsonl-events-")),
      "ledger.jsonl",
    );
    const store = await JsonlStore.open(path);
    stores.push(store);
    const service = new LedgerService(store);
    await service.append("unsigned", capsule("event-a").json);
    await service.append("unsigned", capsule("event-b").json);
    const lines = readFileSync(path, "utf8").trimEnd().split("\n");
    expect(lines.map((line) => JSON.parse(line).type)).toEqual([
      "log.init",
      "capsule.append",
      "capsule.append",
    ]);
    expect(lines.every((line) => !("state" in JSON.parse(line)))).toBe(true);
    expect(lines[2]!.length).toBeLessThan(lines[1]!.length + 128);
  });
  it("JSONL rejects corruption before the final torn tail", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-jsonl-corrupt-")),
      "ledger.jsonl",
    );
    writeFileSync(path, '{"version":3,"type":"log.init"}\n{not-json}\n{torn');
    await expect(JsonlStore.open(path)).rejects.toMatchObject({
      code: "corrupt",
    } satisfies Partial<LedgerError>);
  });
  it("SQLite persists", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-sqlite-")),
      "ledger.sqlite",
    );
    const first = SqliteStore.open(path);
    await contract(first);
    await first.close();
    stores.pop();
    const reopened = SqliteStore.open(path);
    stores.push(reopened);
    expect((await reopened.scan(0n, 10)).length).toBe(2);
  });
  it("SQLite allocates across two concurrent handles", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-sqlite-two-")),
      "ledger.sqlite",
    );
    const first = SqliteStore.open(path, "shared");
    const second = SqliteStore.open(path, "shared");
    stores.push(first, second);
    const clock = () => new Date("2026-09-01T12:00:00Z");
    const a = new LedgerService(first, {}, clock);
    const b = new LedgerService(second, {}, clock);
    const [one, two] = await Promise.all([
      a.append("unsigned", capsule("sqlite-a").json),
      b.append("unsigned", capsule("sqlite-b").json),
    ]);
    expect(new Set([one.seq, two.seq])).toEqual(new Set([1n, 2n]));
  });
  it("SQLite preserves concurrent witness updates across CLL commits", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-sqlite-witness-")),
      "ledger.sqlite",
    );
    const first = SqliteStore.open(path, "shared");
    const second = SqliteStore.open(path, "shared");
    stores.push(first, second);
    await witnessMergeContract(first, second);
  });
  it("SQLite refreshes checkpoint metadata across handles", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-sqlite-checkpoint-")),
      "ledger.sqlite",
    );
    const first = SqliteStore.open(path, "checkpoint-persistence");
    const second = SqliteStore.open(path, "checkpoint-persistence");
    stores.push(first, second);
    await checkpointPersistenceContract(first, second);
  });
  it("SQLite wraps cross-handle refreshes in a read transaction", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-sqlite-snapshot-")),
      "ledger.sqlite",
    );
    const first = SqliteStore.open(path, "snapshot");
    const second = SqliteStore.open(path, "snapshot");
    stores.push(first, second);
    const service = new LedgerService(first);
    await service.append("unsigned", capsule("sqlite-snapshot").json);

    const internal = second as unknown as {
      db: { exec(sql: string): unknown };
    };
    const originalExec = internal.db.exec.bind(internal.db);
    const statements: string[] = [];
    Reflect.set(internal.db, "exec", (sql: string) => {
      statements.push(sql);
      return originalExec(sql);
    });
    try {
      expect((await second.scan(0n, 10)).map((record) => record.seq)).toEqual([
        1n,
      ]);
    } finally {
      Reflect.set(internal.db, "exec", originalExec);
    }
    expect(statements).toEqual(["BEGIN", "COMMIT"]);
  });
  it("SQLite reports orphaned durable rows as corruption", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "ledger-sqlite-corrupt-")),
      "ledger.sqlite",
    );
    const store = SqliteStore.open(path, "corrupt");
    stores.push(store);
    const raw = new Database(path);
    raw
      .prepare(
        "INSERT INTO ledger_envelopes(log_id,capsule_id,digest,envelope) VALUES(?,?,?,?)",
      )
      .run("corrupt", "0".repeat(64), "1".repeat(64), "{}");
    raw.close();
    await expect(store.loadCll()).rejects.toMatchObject({
      code: "corrupt",
    } satisfies Partial<LedgerError>);
  });
});
