import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { CllError, MemoryStore, type CllBackend } from "../src/index.js";
import { JsonlStore } from "../src/jsonl.js";
import { SqliteStore } from "../src/sqlite.js";
import { backendContract, crossHandleContract } from "./backend-contract.js";

const open: CllBackend[] = [];
afterEach(async () => {
  await Promise.all(open.splice(0).map((backend) => backend.close()));
});

describe("shared backend contract", () => {
  it("Memory", async () => {
    const backend = new MemoryStore();
    open.push(backend);
    await backendContract(backend);
  });

  it("JSONL", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "cll-jsonl-")), "cll.jsonl");
    const backend = await JsonlStore.open(path);
    open.push(backend);
    await backendContract(backend);
    await backend.close();
    open.pop();
    const reopened = await JsonlStore.open(path);
    open.push(reopened);
    expect(await reopened.scanEntries(0n, 10)).toHaveLength(2);
    expect((await reopened.loadCll()).indexedSeq).toBe(2n);
  });

  it("SQLite", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "cll-sqlite-")), "cll.sqlite");
    const backend = SqliteStore.open(path);
    open.push(backend);
    await backendContract(backend);
    await backend.close();
    open.pop();
    const reopened = SqliteStore.open(path);
    open.push(reopened);
    expect(await reopened.scanEntries(0n, 10)).toHaveLength(2);
    expect((await reopened.loadCll()).indexedSeq).toBe(2n);
  });

  it("SQLite writes fail closed if log metadata disappears", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "cll-sqlite-missing-meta-")),
      "cll.sqlite",
    );
    const backend = SqliteStore.open(path, "missing-meta");
    open.push(backend);
    const external = new Database(path);
    try {
      external
        .prepare("DELETE FROM cll_meta WHERE log_id=?")
        .run("missing-meta");
    } finally {
      external.close();
    }
    await expect(
      backend.append({ value: new Uint8Array(32), appendedAt: new Date(0) }),
    ).rejects.toMatchObject({ code: "corrupt" } satisfies Partial<CllError>);
  });

  it("SQLite rejects an entry sequence gap when reopened", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "cll-sqlite-entry-gap-")),
      "cll.sqlite",
    );
    const backend = SqliteStore.open(path, "entry-gap");
    await backend.append({
      value: new Uint8Array(32),
      appendedAt: new Date(0),
    });
    await backend.append({
      value: new Uint8Array(32).fill(1),
      appendedAt: new Date(1),
    });
    await backend.close();
    const external = new Database(path);
    try {
      external
        .prepare("DELETE FROM cll_entries WHERE log_id=? AND seq=1")
        .run("entry-gap");
    } finally {
      external.close();
    }
    expect(() => SqliteStore.open(path, "entry-gap")).toThrowError(
      expect.objectContaining({ code: "corrupt" }),
    );
  });

  it("JSONL rejects a second writer and truncates only a torn tail", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "cll-jsonl-lock-")),
      "cll.jsonl",
    );
    const first = await JsonlStore.open(path);
    open.push(first);
    await expect(JsonlStore.open(path)).rejects.toMatchObject({
      code: "contention",
    } satisfies Partial<CllError>);
    await first.append({ value: new Uint8Array(32), appendedAt: new Date(0) });
    await first.close();
    open.pop();
    writeFileSync(path, "{torn", { flag: "a" });
    const reopened = await JsonlStore.open(path);
    open.push(reopened);
    expect(await reopened.scanEntries(0n, 10)).toHaveLength(1);
    expect(readFileSync(path, "utf8")).not.toContain("{torn");
  });

  it("JSONL rejects legacy and complete corruption", async () => {
    for (const content of [
      '{"version":3,"type":"log.init"}\n',
      '{"version":4,"type":"cll.init"}\n{not-json}\n',
    ]) {
      const path = join(
        mkdtempSync(join(tmpdir(), "cll-jsonl-bad-")),
        "cll.jsonl",
      );
      writeFileSync(path, content);
      await expect(JsonlStore.open(path)).rejects.toMatchObject({
        code: "corrupt",
      } satisfies Partial<CllError>);
    }
  });

  it("JSONL checkpoints persist only new MMR nodes", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "cll-jsonl-delta-")),
      "cll.jsonl",
    );
    const backend = await JsonlStore.open(path);
    open.push(backend);
    const nodes = Array.from({ length: 100 }, (_, index) =>
      Uint8Array.from({ length: 32 }, () => index),
    );
    await backend.commitCll(0n, undefined, {
      size: 100n,
      nodes,
      indexedSeq: 0n,
      witnesses: [],
    });
    await backend.commitCll(100n, undefined, {
      size: 101n,
      nodes: [...nodes, new Uint8Array(32)],
      indexedSeq: 0n,
      witnesses: [],
    });
    const lines = readFileSync(path, "utf8").trimEnd().split("\n");
    expect(lines[2]!.length).toBeLessThan(lines[1]!.length / 2);
    await backend.close();
    open.pop();
    const reopened = await JsonlStore.open(path);
    open.push(reopened);
    expect((await reopened.loadCll()).size).toBe(101n);
  });

  it("SQLite allocates dense sequences across handles", async () => {
    const path = join(
      mkdtempSync(join(tmpdir(), "cll-sqlite-two-")),
      "cll.sqlite",
    );
    const first = SqliteStore.open(path, "shared");
    const second = SqliteStore.open(path, "shared");
    open.push(first, second);
    await crossHandleContract(first, second);
  });
});
