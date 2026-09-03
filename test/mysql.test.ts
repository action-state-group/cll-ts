import { MySqlContainer } from "@testcontainers/mysql";
import { afterAll, beforeAll, describe, it } from "vitest";
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
});
