import type { CllState, Envelope, Record, WitnessState } from "./types.js";
export const cloneEnvelope = (value: Envelope): Envelope => ({
  ...value,
  bytes: Uint8Array.from(value.bytes),
  addedAt: new Date(value.addedAt),
  verification: {
    ...value.verification,
    findings: value.verification.findings.map((item) => ({ ...item })),
    ...(value.verification.publicKey === undefined
      ? {}
      : { publicKey: Uint8Array.from(value.verification.publicKey) }),
  },
});
export const cloneRecord = (value: Record): Record => ({
  ...value,
  capsule: Uint8Array.from(value.capsule),
  envelopes: value.envelopes.map(cloneEnvelope),
  appendedAt: new Date(value.appendedAt),
  verification: {
    ...value.verification,
    findings: value.verification.findings.map((item) => ({ ...item })),
    assurance: { ...value.verification.assurance },
  },
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
