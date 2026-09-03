import { createHash } from "node:crypto";
import { encode, rfc8949EncodeOptions } from "cborg";

interface NodeMeta {
  readonly height: number;
  readonly left?: number;
  readonly right?: number;
  parent?: number;
}
interface PeakMeta {
  readonly leafStart: number;
  readonly leaves: number;
  readonly nodeStart: number;
  readonly position: number;
}
interface PathStep {
  readonly parent: number;
  readonly isLeft: boolean;
}
export interface MmrConsistencyProof {
  readonly oldSize: bigint;
  readonly newSize: bigint;
  readonly oldPeaks: readonly Uint8Array[];
  readonly witness: readonly (readonly Uint8Array[])[];
  readonly newPeaks: readonly Uint8Array[];
}
const sha = (...parts: readonly Uint8Array[]): Uint8Array =>
  createHash("sha256").update(Buffer.concat(parts)).digest();
const be64 = (value: bigint): Uint8Array => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(value);
  return bytes;
};
const parentHash = (
  left: Uint8Array,
  right: Uint8Array,
  position: number,
): Uint8Array => sha(be64(BigInt(position + 1)), left, right);
const bag = (right: Uint8Array, left: Uint8Array): Uint8Array =>
  sha(right, left);
const validHash = (value: Uint8Array): boolean => value.length === 32;

function topology(leaves: number): {
  meta: NodeMeta[];
  peaks: number[];
  leafPositions: number[];
} {
  const meta: NodeMeta[] = [];
  const peaks: number[] = [];
  const leafPositions: number[] = [];
  for (let leaf = 0; leaf < leaves; leaf += 1) {
    let position = meta.length;
    meta.push({ height: 0 });
    leafPositions.push(position);
    while (
      peaks.length !== 0 &&
      meta[peaks.at(-1)!]!.height === meta[position]!.height
    ) {
      const left = peaks.pop()!;
      const parent = meta.length;
      meta.push({ height: meta[position]!.height + 1, left, right: position });
      meta[left]!.parent = parent;
      meta[position]!.parent = parent;
      position = parent;
    }
    peaks.push(position);
  }
  return { meta, peaks, leafPositions };
}

/** Describe the perfect-tree mountains in left-to-right MMR peak order. */
function peakLayout(leaves: bigint): PeakMeta[] {
  const peaks: PeakMeta[] = [];
  let remaining = leaves;
  let leafStart = 0n;
  let nodeStart = 0n;
  while (remaining > 0n) {
    let mountainLeaves = 1n;
    while (mountainLeaves << 1n <= remaining) mountainLeaves <<= 1n;
    const nodeCount = 2n * mountainLeaves - 1n;
    peaks.push({
      leafStart: Number(leafStart),
      leaves: Number(mountainLeaves),
      nodeStart: Number(nodeStart),
      position: Number(nodeStart + nodeCount - 1n),
    });
    remaining -= mountainLeaves;
    leafStart += mountainLeaves;
    nodeStart += nodeCount;
  }
  return peaks;
}

/** Return the bottom-up path from an aligned perfect subtree to its peak. */
function pathToPeak(
  peak: PeakMeta,
  targetLeafStart: number,
  targetLeaves: number,
): PathStep[] | undefined {
  if (
    targetLeaves < 1 ||
    targetLeafStart < peak.leafStart ||
    targetLeafStart + targetLeaves > peak.leafStart + peak.leaves
  )
    return undefined;
  let relativeStart = targetLeafStart - peak.leafStart;
  let subtreeLeaves = peak.leaves;
  let nodeStart = peak.nodeStart;
  const topDown: PathStep[] = [];
  while (subtreeLeaves !== targetLeaves) {
    const half = subtreeLeaves / 2;
    if (targetLeaves > half) return undefined;
    const childNodes = 2 * half - 1;
    const parent = nodeStart + 2 * subtreeLeaves - 2;
    if (relativeStart < half) {
      if (relativeStart + targetLeaves > half) return undefined;
      topDown.push({ parent, isLeft: true });
    } else {
      relativeStart -= half;
      nodeStart += childNodes;
      topDown.push({ parent, isLeft: false });
    }
    subtreeLeaves = half;
  }
  if (relativeStart !== 0) return undefined;
  return topDown.reverse();
}

export function rootFromPeaks(peaks: readonly Uint8Array[]): Uint8Array {
  if (peaks.length === 0) return new Uint8Array(32);
  let root: Uint8Array = Uint8Array.from(peaks.at(-1)!);
  for (let index = peaks.length - 2; index >= 0; index -= 1)
    root = bag(root, peaks[index]!);
  return root;
}

/** Encode the complete MMR accumulator as the CLL 0.1.0 commitment object. */
export function commitmentObject(peaks: readonly Uint8Array[]): Uint8Array {
  if (peaks.some((peak) => !validHash(peak)))
    throw new TypeError("MMR peaks must be 32 bytes");
  return encode(peaks, rfc8949EncodeOptions);
}

export class MmrTree {
  private readonly nodes_: Uint8Array[] = [];
  private readonly meta: NodeMeta[] = [];
  private readonly peaks: number[] = [];
  private readonly leafPositions: number[] = [];
  public constructor(nodes: readonly Uint8Array[] = []) {
    if (nodes.length !== 0) {
      const leaves = leafCount(BigInt(nodes.length));
      if (leaves === undefined)
        throw new TypeError("invalid complete MMR size");
      const shape = topology(Number(leaves));
      for (const item of shape.meta) this.meta.push(item);
      for (const item of shape.peaks) this.peaks.push(item);
      for (const item of shape.leafPositions) this.leafPositions.push(item);
      if (nodes.some((node) => !validHash(node)))
        throw new TypeError("MMR nodes must be 32 bytes");
      for (const item of nodes) this.nodes_.push(Uint8Array.from(item));
      for (let position = 0; position < this.meta.length; position += 1) {
        const node = this.meta[position]!;
        if (node.left === undefined || node.right === undefined) continue;
        const expected = parentHash(
          this.nodes_[node.left]!,
          this.nodes_[node.right]!,
          position,
        );
        if (!Buffer.from(expected).equals(Buffer.from(this.nodes_[position]!)))
          throw new TypeError(
            `MMR interior node ${position} does not match its children`,
          );
      }
    }
  }
  /** Commit an application-neutral 32-byte record identity as the next CLL leaf. */
  public append(value: Uint8Array): bigint {
    if (value.length !== 32)
      throw new TypeError("CLL leaf value must be exactly 32 bytes");
    let position = this.nodes_.length;
    this.nodes_.push(sha(Uint8Array.of(0), value));
    this.meta.push({ height: 0 });
    this.leafPositions.push(position);
    while (
      this.peaks.length !== 0 &&
      this.meta[this.peaks.at(-1)!]!.height === this.meta[position]!.height
    ) {
      const left = this.peaks.pop()!;
      const parent = this.nodes_.length;
      this.nodes_.push(
        parentHash(this.nodes_[left]!, this.nodes_[position]!, parent),
      );
      this.meta.push({
        height: this.meta[position]!.height + 1,
        left,
        right: position,
      });
      this.meta[left]!.parent = parent;
      this.meta[position]!.parent = parent;
      position = parent;
    }
    this.peaks.push(position);
    return BigInt(this.nodes_.length);
  }
  public get size(): bigint {
    return BigInt(this.nodes_.length);
  }
  public nodes(): readonly Uint8Array[] {
    return this.nodes_.map((item) => Uint8Array.from(item));
  }
  public root(): Uint8Array {
    return rootFromPeaks(this.peaks.map((position) => this.nodes_[position]!));
  }
  public peakHashes(): readonly Uint8Array[] {
    return this.peaks.map((position) =>
      Uint8Array.from(this.nodes_[position]!),
    );
  }
  public peakHashesAt(size: bigint): readonly Uint8Array[] {
    const leaves = leafCount(size);
    if (leaves === undefined || size > this.size)
      throw new RangeError("invalid historical MMR size");
    return topology(Number(leaves)).peaks.map((position) =>
      Uint8Array.from(this.nodes_[position]!),
    );
  }
  private siblingPath(start: number): Uint8Array[] {
    const path: Uint8Array[] = [];
    let position = start;
    while (this.meta[position]!.parent !== undefined) {
      const parent = this.meta[position]!.parent!;
      const item = this.meta[parent]!;
      path.push(
        Uint8Array.from(
          this.nodes_[item.left === position ? item.right! : item.left!]!,
        ),
      );
      position = parent;
    }
    return path;
  }
  public inclusionProof(leafIndex: bigint): readonly Uint8Array[] {
    const leaf = this.leafPositions[Number(leafIndex)];
    if (leaf === undefined) throw new RangeError("leaf index out of range");
    const proof = this.siblingPath(leaf);
    let position = leaf;
    while (this.meta[position]!.parent !== undefined)
      position = this.meta[position]!.parent!;
    const peakIndex = this.peaks.indexOf(position);
    const right = this.peaks
      .slice(peakIndex + 1)
      .map((item) => this.nodes_[item]!);
    if (right.length !== 0) proof.push(rootFromPeaks(right));
    for (let index = peakIndex - 1; index >= 0; index -= 1)
      proof.push(Uint8Array.from(this.nodes_[this.peaks[index]!]!));
    return proof;
  }
  public consistencyProof(oldSize: bigint): MmrConsistencyProof {
    const oldLeaves = leafCount(oldSize);
    if (oldLeaves === undefined || oldSize <= 0n || oldSize > this.size)
      throw new RangeError("invalid previous MMR size");
    const oldShape = topology(Number(oldLeaves));
    const witness = oldShape.peaks.map((oldPeak) => {
      return this.siblingPath(oldPeak);
    });
    return {
      oldSize,
      newSize: this.size,
      oldPeaks: oldShape.peaks.map((position) =>
        Uint8Array.from(this.nodes_[position]!),
      ),
      witness,
      newPeaks: this.peakHashes(),
    };
  }
}

export function leafCount(size: bigint): bigint | undefined {
  if (size < 0n || size > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  const nodesFor = (leaves: bigint): bigint => {
    let value = leaves;
    let peaks = 0n;
    while (value !== 0n) {
      peaks += value & 1n;
      value >>= 1n;
    }
    return 2n * leaves - peaks;
  };
  let low = 0n;
  let high = size + 1n;
  while (low <= high) {
    const middle = (low + high) >> 1n;
    const candidate = nodesFor(middle);
    if (candidate === size) return middle;
    if (candidate < size) low = middle + 1n;
    else high = middle - 1n;
  }
  return undefined;
}

export function verifyInclusionValue(
  root: Uint8Array,
  mmrSize: bigint,
  leafIndex: bigint,
  entryValue: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  const leaves = leafCount(mmrSize);
  if (
    !validHash(root) ||
    leaves === undefined ||
    leafIndex < 0n ||
    leafIndex >= leaves ||
    entryValue.length !== 32 ||
    proof.some((item) => !validHash(item))
  )
    return false;
  const layout = peakLayout(leaves);
  const peakIndex = layout.findIndex(
    (peak) =>
      Number(leafIndex) >= peak.leafStart &&
      Number(leafIndex) < peak.leafStart + peak.leaves,
  );
  if (peakIndex < 0) return false;
  const path = pathToPeak(layout[peakIndex]!, Number(leafIndex), 1);
  if (path === undefined) return false;
  let value = sha(Uint8Array.of(0), entryValue);
  let cursor = 0;
  for (const step of path) {
    const sibling = proof[cursor++];
    if (sibling === undefined) return false;
    value = step.isLeft
      ? parentHash(value, sibling, step.parent)
      : parentHash(sibling, value, step.parent);
  }
  if (peakIndex < layout.length - 1) {
    const right = proof[cursor++];
    if (right === undefined) return false;
    value = bag(right, value);
  }
  for (let index = peakIndex - 1; index >= 0; index -= 1) {
    const left = proof[cursor++];
    if (left === undefined) return false;
    value = bag(value, left);
  }
  return (
    cursor === proof.length && Buffer.from(value).equals(Buffer.from(root))
  );
}

export function verifyConsistency(
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: MmrConsistencyProof,
): boolean {
  const oldLeaves = leafCount(proof.oldSize);
  const newLeaves = leafCount(proof.newSize);
  if (
    oldLeaves === undefined ||
    newLeaves === undefined ||
    proof.oldSize <= 0n ||
    proof.oldSize > proof.newSize ||
    proof.oldPeaks.some((item) => !validHash(item)) ||
    proof.newPeaks.some((item) => !validHash(item)) ||
    proof.witness.length !== proof.oldPeaks.length
  )
    return false;
  if (
    !Buffer.from(rootFromPeaks(proof.oldPeaks)).equals(Buffer.from(oldRoot)) ||
    !Buffer.from(rootFromPeaks(proof.newPeaks)).equals(Buffer.from(newRoot))
  )
    return false;
  const oldShape = peakLayout(oldLeaves);
  const newShape = peakLayout(newLeaves);
  if (
    oldShape.length !== proof.oldPeaks.length ||
    newShape.length !== proof.newPeaks.length
  )
    return false;
  for (let index = 0; index < oldShape.length; index += 1) {
    const oldPeak = oldShape[index]!;
    let value = proof.oldPeaks[index]!;
    let cursor = 0;
    const path = proof.witness[index]!;
    const newPeakIndex = newShape.findIndex(
      (peak) =>
        oldPeak.leafStart >= peak.leafStart &&
        oldPeak.leafStart + oldPeak.leaves <= peak.leafStart + peak.leaves,
    );
    if (newPeakIndex < 0) return false;
    const steps = pathToPeak(
      newShape[newPeakIndex]!,
      oldPeak.leafStart,
      oldPeak.leaves,
    );
    if (steps === undefined) return false;
    for (const step of steps) {
      const sibling = path[cursor++];
      if (sibling === undefined) return false;
      value = step.isLeft
        ? parentHash(value, sibling, step.parent)
        : parentHash(sibling, value, step.parent);
    }
    if (cursor !== path.length) return false;
    if (!Buffer.from(value).equals(Buffer.from(proof.newPeaks[newPeakIndex]!)))
      return false;
  }
  return true;
}
