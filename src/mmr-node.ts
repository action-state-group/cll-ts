import { createHash } from "node:crypto";
import {
  MmrTree as CoreMmrTree,
  commitmentObject,
  consistencyProof,
  inclusionProof,
  leafCount,
  rootFromPeaks as coreRootFromPeaks,
  verifyConsistency as coreVerifyConsistency,
  verifyHexInclusion as coreVerifyHexInclusion,
  verifyInclusionValue as coreVerifyInclusionValue,
  type MmrConsistencyProof,
  type MmrHash,
  type MmrInclusionProof,
  type MmrStructuredConsistencyProof,
} from "./mmr.js";

const hash: MmrHash = async (...parts) =>
  createHash("sha256").update(Buffer.concat(parts)).digest();

export { commitmentObject, consistencyProof, inclusionProof, leafCount };
export type {
  MmrConsistencyProof,
  MmrHash,
  MmrInclusionProof,
  MmrStructuredConsistencyProof,
};
export class MmrTree extends CoreMmrTree {
  public constructor(nodes: readonly Uint8Array[] = []) {
    super(hash, nodes);
  }
}
export const rootFromPeaks = (peaks: readonly Uint8Array[]) =>
  coreRootFromPeaks(hash, peaks);
export const verifyInclusionValue = (
  root: Uint8Array,
  size: bigint,
  leafIndex: bigint,
  value: Uint8Array,
  proof: readonly Uint8Array[],
) => coreVerifyInclusionValue(hash, root, size, leafIndex, value, proof);
export const verifyHexInclusion = (
  root: Uint8Array,
  size: bigint,
  leafIndex: bigint,
  identity: string,
  proof: readonly Uint8Array[],
) => coreVerifyHexInclusion(hash, root, size, leafIndex, identity, proof);
export const verifyConsistency = (
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: MmrConsistencyProof,
) => coreVerifyConsistency(hash, oldRoot, newRoot, proof);
