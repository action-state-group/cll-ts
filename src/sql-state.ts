import {
  cllFromWire,
  entryFromWire,
  witnessFromWire,
  type WireCllState,
  type WireWitness,
} from "./serde.js";
import {
  CllError,
  validateIdentifier,
  type CllEntry,
  type CllState,
  type WitnessState,
} from "./types.js";

export interface SqlEntryRow {
  readonly seq: string | number | bigint;
  readonly value: Uint8Array;
  readonly appendedAt: string;
}

export interface SqlNodeRow {
  readonly position: string | number | bigint;
  readonly node: Uint8Array;
}

export interface SqlWitnessRow {
  readonly witnessId: string;
  readonly checkpointSize: string;
  readonly attempts: number;
  readonly witness: Uint8Array | string;
}

const text = (value: Uint8Array | string): string =>
  typeof value === "string" ? value : Buffer.from(value).toString("utf8");

const corrupt = (message: string, cause?: unknown): CllError =>
  new CllError("corrupt", message, cause === undefined ? undefined : { cause });

/** Decode and validate one relational entry row. */
export function entryFromSqlRow(row: SqlEntryRow): CllEntry {
  try {
    const entry = entryFromWire({
      seq: String(row.seq),
      value: Buffer.from(row.value).toString("base64"),
      appendedAt: row.appendedAt,
    });
    if (entry.seq < 1n || entry.seq > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error("entry sequence is outside the portable range");
    return entry;
  } catch (error) {
    if (error instanceof CllError && error.code === "corrupt") throw error;
    throw corrupt("stored CLL entry is invalid", error);
  }
}

function witnessWireFromSqlRow(row: SqlWitnessRow): WireWitness {
  try {
    const wire = JSON.parse(text(row.witness)) as WireWitness;
    const witness = witnessFromWire(wire);
    validateIdentifier(witness.witnessId);
    if (
      witness.witnessId !== row.witnessId ||
      String(witness.checkpointSize) !== row.checkpointSize ||
      witness.attempts !== row.attempts ||
      witness.checkpointSize < 1n ||
      !Number.isSafeInteger(witness.attempts) ||
      witness.attempts < 0 ||
      !Number.isFinite(witness.nextAttemptAt.valueOf())
    )
      throw new Error("witness index disagrees with payload");
    return wire;
  } catch (error) {
    throw corrupt("stored CLL witness is invalid", error);
  }
}

/** Decode and validate one indexed relational witness row. */
export function witnessFromSqlRow(row: SqlWitnessRow): WitnessState {
  return witnessFromWire(witnessWireFromSqlRow(row));
}

/** Reconstruct complete CLL state from a consistent relational snapshot. */
export function cllFromSqlRows(
  metadata: Uint8Array | string,
  nodes: readonly SqlNodeRow[],
  witnesses: readonly SqlWitnessRow[],
): CllState {
  try {
    nodes.forEach((row, index) => {
      if (BigInt(row.position) !== BigInt(index) || row.node.length !== 32)
        throw new Error("MMR node positions are not dense and valid");
    });
    const wire = JSON.parse(text(metadata)) as WireCllState;
    const cll = cllFromWire({
      ...wire,
      nodes: [],
      witnesses: witnesses.map(witnessWireFromSqlRow),
    });
    if (cll.size !== BigInt(nodes.length))
      throw new Error("stored CLL node count does not match size");
    return { ...cll, nodes: nodes.map((row) => Uint8Array.from(row.node)) };
  } catch (error) {
    if (error instanceof CllError && error.code === "corrupt") throw error;
    throw corrupt("stored relational CLL state is corrupt", error);
  }
}
