import {
  CllError,
  type CllEntry,
  type CllState,
  type WitnessState,
} from "./types.js";

export interface WireEntry {
  readonly seq: string;
  readonly value: string;
  readonly appendedAt: string;
}

export type WireWitness = Omit<
  WitnessState,
  "checkpointSize" | "checkpoint" | "nextAttemptAt" | "receipt"
> & {
  checkpointSize: string;
  checkpoint: string;
  nextAttemptAt: string;
  receipt?: string;
};

export type WireCllState = {
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

export const entryToWire = (entry: CllEntry): WireEntry => ({
  seq: String(entry.seq),
  value: Buffer.from(entry.value).toString("base64"),
  appendedAt: entry.appendedAt.toISOString(),
});

export const entryFromWire = (entry: WireEntry): CllEntry => {
  const value = Buffer.from(entry.value, "base64");
  const appendedAt = new Date(entry.appendedAt);
  if (
    value.length !== 32 ||
    !Number.isFinite(appendedAt.valueOf()) ||
    !/^(?:0|[1-9][0-9]*)$/u.test(entry.seq)
  )
    throw new CllError("corrupt", "stored CLL entry is invalid");
  return { seq: BigInt(entry.seq), value, appendedAt };
};

export const witnessToWire = (value: WitnessState): WireWitness => {
  const { checkpointSize, checkpoint, nextAttemptAt, receipt, ...rest } = value;
  return {
    ...rest,
    checkpointSize: String(checkpointSize),
    checkpoint: Buffer.from(checkpoint).toString("base64"),
    nextAttemptAt: nextAttemptAt.toISOString(),
    ...(receipt === undefined
      ? {}
      : { receipt: Buffer.from(receipt).toString("base64") }),
  };
};

export const witnessFromWire = (value: WireWitness): WitnessState => {
  const { checkpointSize, checkpoint, nextAttemptAt, receipt, ...rest } = value;
  return {
    ...rest,
    checkpointSize: BigInt(checkpointSize),
    checkpoint: Buffer.from(checkpoint, "base64"),
    nextAttemptAt: new Date(nextAttemptAt),
    ...(receipt === undefined
      ? {}
      : { receipt: Buffer.from(receipt, "base64") }),
  };
};

export const cllToWire = (cll: CllState): WireCllState => ({
  size: String(cll.size),
  indexedSeq: String(cll.indexedSeq),
  nodes: cll.nodes.map((node) => Buffer.from(node).toString("base64")),
  ...(cll.firstPendingAt === undefined
    ? {}
    : { firstPendingAt: cll.firstPendingAt.toISOString() }),
  ...(cll.checkpoint === undefined
    ? {}
    : { checkpoint: Buffer.from(cll.checkpoint).toString("base64") }),
  ...(cll.checkpointSize === undefined
    ? {}
    : { checkpointSize: String(cll.checkpointSize) }),
  ...(cll.checkpointIndexedSeq === undefined
    ? {}
    : { checkpointIndexedSeq: String(cll.checkpointIndexedSeq) }),
  ...(cll.checkpointPeaks === undefined
    ? {}
    : {
        checkpointPeaks: cll.checkpointPeaks.map((item) =>
          Buffer.from(item).toString("base64"),
        ),
      }),
  witnesses: cll.witnesses.map(witnessToWire),
});

export const cllFromWire = (wire: WireCllState): CllState => ({
  size: BigInt(wire.size),
  indexedSeq: BigInt(wire.indexedSeq),
  nodes: wire.nodes.map((node) => Buffer.from(node, "base64")),
  ...(wire.firstPendingAt === undefined
    ? {}
    : { firstPendingAt: new Date(wire.firstPendingAt) }),
  ...(wire.checkpoint === undefined
    ? {}
    : { checkpoint: Buffer.from(wire.checkpoint, "base64") }),
  ...(wire.checkpointSize === undefined
    ? {}
    : { checkpointSize: BigInt(wire.checkpointSize) }),
  ...(wire.checkpointIndexedSeq === undefined
    ? {}
    : { checkpointIndexedSeq: BigInt(wire.checkpointIndexedSeq) }),
  ...(wire.checkpointPeaks === undefined
    ? {}
    : {
        checkpointPeaks: wire.checkpointPeaks.map((item) =>
          Buffer.from(item, "base64"),
        ),
      }),
  witnesses: wire.witnesses.map(witnessFromWire),
});
