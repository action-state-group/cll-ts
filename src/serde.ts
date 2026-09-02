import type { CllState, Envelope, Record, WitnessState } from "./types.js";
export type WireEnvelope = Omit<
  Envelope,
  "bytes" | "addedAt" | "verification"
> & {
  bytes: string;
  addedAt: string;
  verification: Omit<Envelope["verification"], "publicKey"> & {
    publicKey?: string;
  };
};
export type WireRecord = Omit<
  Record,
  "seq" | "capsule" | "appendedAt" | "envelopes"
> & {
  seq: string;
  capsule: string;
  appendedAt: string;
  envelopes: WireEnvelope[];
};
export type WireWitness = Omit<
  WitnessState,
  "checkpointSize" | "checkpoint" | "nextAttemptAt" | "receipt"
> & {
  checkpointSize: string;
  checkpoint: string;
  nextAttemptAt: string;
  receipt?: string;
};
export interface WireState {
  records: WireRecord[];
  cll: Omit<
    CllState,
    | "size"
    | "nodes"
    | "indexedSeq"
    | "firstPendingAt"
    | "checkpoint"
    | "checkpointSize"
    | "checkpointIndexedSeq"
    | "checkpointPeaks"
    | "witnesses"
  > & {
    size: string;
    nodes: string[];
    indexedSeq: string;
    firstPendingAt?: string;
    checkpoint?: string;
    checkpointSize?: string;
    checkpointIndexedSeq?: string;
    checkpointPeaks?: string[];
    witnesses: WireWitness[];
  };
}
export interface DurableStateRows {
  readonly records: readonly WireRecord[];
  readonly envelopes: readonly {
    readonly capsuleId: string;
    readonly envelope: WireEnvelope;
  }[];
  readonly cll: WireState["cll"];
  readonly nodes: readonly Uint8Array[];
  readonly witnesses: readonly WireWitness[];
}
export const envelopeToWire = (value: Envelope): WireEnvelope => {
  const { bytes, addedAt, verification, ...rest } = value;
  const { publicKey, ...verificationRest } = verification;
  return {
    ...rest,
    bytes: Buffer.from(bytes).toString("base64"),
    addedAt: addedAt.toISOString(),
    verification: {
      ...verificationRest,
      ...(publicKey === undefined
        ? {}
        : { publicKey: Buffer.from(publicKey).toString("base64") }),
    },
  };
};
export const envelopeFromWire = (value: WireEnvelope): Envelope => {
  const { bytes, addedAt, verification, ...rest } = value;
  const { publicKey, ...verificationRest } = verification;
  return {
    ...rest,
    bytes: Buffer.from(bytes, "base64"),
    addedAt: new Date(addedAt),
    verification: {
      ...verificationRest,
      ...(publicKey === undefined
        ? {}
        : { publicKey: Buffer.from(publicKey, "base64") }),
    },
  };
};
export const stateToWire = (
  records: readonly Record[],
  cll: CllState,
): WireState => ({
  records: records.map((value) => {
    const { seq, capsule, appendedAt, envelopes, ...rest } = value;
    return {
      ...rest,
      seq: String(seq),
      capsule: Buffer.from(capsule).toString("base64"),
      appendedAt: appendedAt.toISOString(),
      envelopes: envelopes.map(envelopeToWire),
    };
  }),
  cll: (() => {
    const {
      size,
      nodes,
      indexedSeq,
      firstPendingAt,
      checkpoint,
      checkpointSize,
      checkpointIndexedSeq,
      checkpointPeaks,
      witnesses,
      ...rest
    } = cll;
    return {
      ...rest,
      size: String(size),
      indexedSeq: String(indexedSeq),
      nodes: nodes.map((node) => Buffer.from(node).toString("base64")),
      ...(firstPendingAt === undefined
        ? {}
        : { firstPendingAt: firstPendingAt.toISOString() }),
      ...(checkpoint === undefined
        ? {}
        : { checkpoint: Buffer.from(checkpoint).toString("base64") }),
      ...(checkpointSize === undefined
        ? {}
        : { checkpointSize: String(checkpointSize) }),
      ...(checkpointIndexedSeq === undefined
        ? {}
        : { checkpointIndexedSeq: String(checkpointIndexedSeq) }),
      ...(checkpointPeaks === undefined
        ? {}
        : {
            checkpointPeaks: checkpointPeaks.map((item) =>
              Buffer.from(item).toString("base64"),
            ),
          }),
      witnesses: witnesses.map((value) => {
        const {
          checkpointSize: witnessSize,
          checkpoint: signed,
          nextAttemptAt,
          receipt,
          ...witnessRest
        } = value;
        return {
          ...witnessRest,
          checkpointSize: String(witnessSize),
          checkpoint: Buffer.from(signed).toString("base64"),
          nextAttemptAt: nextAttemptAt.toISOString(),
          ...(receipt === undefined
            ? {}
            : { receipt: Buffer.from(receipt).toString("base64") }),
        };
      }),
    };
  })(),
});
export const stateFromWire = (
  wire: WireState,
): { records: Record[]; cll: CllState } => ({
  records: wire.records.map((value) => {
    const { seq, capsule, appendedAt, envelopes, ...rest } = value;
    return {
      ...rest,
      seq: BigInt(seq),
      capsule: Buffer.from(capsule, "base64"),
      appendedAt: new Date(appendedAt),
      envelopes: envelopes.map(envelopeFromWire),
    };
  }),
  cll: (() => {
    const {
      size,
      nodes,
      indexedSeq,
      firstPendingAt,
      checkpoint,
      checkpointSize,
      checkpointIndexedSeq,
      checkpointPeaks,
      witnesses,
      ...rest
    } = wire.cll;
    return {
      ...rest,
      size: BigInt(size),
      indexedSeq: BigInt(indexedSeq),
      nodes: nodes.map((node) => Buffer.from(node, "base64")),
      ...(firstPendingAt === undefined
        ? {}
        : { firstPendingAt: new Date(firstPendingAt) }),
      ...(checkpoint === undefined
        ? {}
        : { checkpoint: Buffer.from(checkpoint, "base64") }),
      ...(checkpointSize === undefined
        ? {}
        : { checkpointSize: BigInt(checkpointSize) }),
      ...(checkpointIndexedSeq === undefined
        ? {}
        : { checkpointIndexedSeq: BigInt(checkpointIndexedSeq) }),
      ...(checkpointPeaks === undefined
        ? {}
        : {
            checkpointPeaks: checkpointPeaks.map((item) =>
              Buffer.from(item, "base64"),
            ),
          }),
      witnesses: witnesses.map((value) => {
        const {
          checkpointSize: witnessSize,
          checkpoint: signed,
          nextAttemptAt,
          receipt,
          ...witnessRest
        } = value;
        return {
          ...witnessRest,
          checkpointSize: BigInt(witnessSize),
          checkpoint: Buffer.from(signed, "base64"),
          nextAttemptAt: new Date(nextAttemptAt),
          ...(receipt === undefined
            ? {}
            : { receipt: Buffer.from(receipt, "base64") }),
        };
      }),
    };
  })(),
});

const emptyCll = (): CllState => ({
  size: 0n,
  nodes: [],
  indexedSeq: 0n,
  witnesses: [],
});

export const recordToWire = (record: Record): WireRecord =>
  stateToWire([record], emptyCll()).records[0]!;

export const recordFromWire = (record: WireRecord): Record =>
  stateFromWire({
    records: [record],
    cll: stateToWire([], emptyCll()).cll,
  }).records[0]!;

export const witnessToWire = (witness: WitnessState): WireWitness =>
  stateToWire([], { ...emptyCll(), witnesses: [witness] }).cll.witnesses[0]!;

export const witnessFromWire = (witness: WireWitness): WitnessState =>
  stateFromWire({
    records: [],
    cll: { ...stateToWire([], emptyCll()).cll, witnesses: [witness] },
  }).cll.witnesses[0]!;

/** Assemble normalized durable rows under the shared backend invariants. */
export function stateFromRows(rows: DurableStateRows): {
  records: Record[];
  cll: CllState;
} {
  const records = rows.records.map(recordFromWire);
  const recordIndexes = new Map(
    records.map((record, index) => [record.capsuleId, index]),
  );
  for (const row of rows.envelopes) {
    const index = recordIndexes.get(row.capsuleId);
    if (index === undefined) throw new Error("orphaned envelope row");
    records[index] = {
      ...records[index]!,
      envelopes: [...records[index]!.envelopes, envelopeFromWire(row.envelope)],
    };
  }
  const cll = stateFromWire({
    records: [],
    cll: {
      ...rows.cll,
      nodes: rows.nodes.map((node) => Buffer.from(node).toString("base64")),
      witnesses: [...rows.witnesses],
    },
  }).cll;
  if (cll.size !== BigInt(rows.nodes.length))
    throw new Error("CLL metadata and node rows disagree");
  return { records, cll };
}
