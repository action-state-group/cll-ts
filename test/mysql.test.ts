import { MySqlContainer } from "@testcontainers/mysql";
import mysql from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CllError } from "../src/index.js";
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
