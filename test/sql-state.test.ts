import { describe, expect, it } from "vitest";
import { cllToWire, witnessToWire } from "../src/serde.js";
import {
  cllFromSqlRows,
  entryFromSqlRow,
  witnessFromSqlRow,
} from "../src/sql-state.js";
import { CllError, type WitnessState } from "../src/index.js";

function expectCorrupt(action: () => unknown): void {
  let thrown: unknown;
  try {
    action();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(CllError);
  expect((thrown as CllError).code).toBe("corrupt");
}

const emptyMetadata = JSON.stringify(
  cllToWire({ size: 0n, nodes: [], indexedSeq: 0n, witnesses: [] }),
);

const witness: WitnessState = {
  witnessId: "primary",
  checkpointSize: 1n,
  checkpoint: Uint8Array.of(1),
  attempts: 0,
  nextAttemptAt: new Date(0),
  permanent: false,
};

describe("relational row validation", () => {
  it("rejects entries outside the portable sequence range", () => {
    expectCorrupt(() =>
      entryFromSqlRow({
        seq: BigInt(Number.MAX_SAFE_INTEGER) + 1n,
        value: new Uint8Array(32),
        appendedAt: new Date(0).toISOString(),
      }),
    );
  });

  it("rejects non-dense or malformed MMR nodes", () => {
    expectCorrupt(() =>
      cllFromSqlRows(
        JSON.stringify(
          cllToWire({ size: 1n, nodes: [], indexedSeq: 0n, witnesses: [] }),
        ),
        [{ position: 1, node: new Uint8Array(32) }],
        [],
      ),
    );
    expectCorrupt(() =>
      cllFromSqlRows(
        JSON.stringify(
          cllToWire({ size: 1n, nodes: [], indexedSeq: 0n, witnesses: [] }),
        ),
        [{ position: 0, node: Uint8Array.of(1) }],
        [],
      ),
    );
  });

  it("rejects witness payloads that disagree with their index", () => {
    expect(() =>
      witnessFromSqlRow({
        witnessId: "other",
        checkpointSize: "1",
        attempts: 0,
        witness: JSON.stringify(witnessToWire(witness)),
      }),
    ).toThrow(/witness is invalid/u);
  });

  it("loads a valid empty relational state", () => {
    expect(cllFromSqlRows(emptyMetadata, [], [])).toMatchObject({
      size: 0n,
      indexedSeq: 0n,
      witnesses: [],
    });
  });
});
