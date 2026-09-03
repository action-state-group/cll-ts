import type { CllEntry, CllState, WitnessState } from "./types.js";

export const cloneEntry = (value: CllEntry): CllEntry => ({
  ...value,
  value: Uint8Array.from(value.value),
  appendedAt: new Date(value.appendedAt),
});

export const cloneWitness = (value: WitnessState): WitnessState => ({
  ...value,
  checkpoint: Uint8Array.from(value.checkpoint),
  nextAttemptAt: new Date(value.nextAttemptAt),
  ...(value.receipt === undefined
    ? {}
    : { receipt: Uint8Array.from(value.receipt) }),
});

export const cloneCll = (value: CllState): CllState => ({
  ...value,
  nodes: value.nodes.map((item) => Uint8Array.from(item)),
  ...(value.firstPendingAt === undefined
    ? {}
    : { firstPendingAt: new Date(value.firstPendingAt) }),
  ...(value.checkpoint === undefined
    ? {}
    : { checkpoint: Uint8Array.from(value.checkpoint) }),
  ...(value.checkpointPeaks === undefined
    ? {}
    : {
        checkpointPeaks: value.checkpointPeaks.map((item) =>
          Uint8Array.from(item),
        ),
      }),
  witnesses: value.witnesses.map(cloneWitness),
});
