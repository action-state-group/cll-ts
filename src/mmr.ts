import { encode, rfc8949EncodeOptions } from "cborg";

export type MmrHash = (...parts: readonly Uint8Array[]) => Promise<Uint8Array>;

type Meta = { height: number; left?: number; right?: number; parent?: number };
export interface MmrConsistencyProof {
  readonly oldSize: bigint;
  readonly newSize: bigint;
  readonly oldPeaks: readonly Uint8Array[];
  readonly witness: readonly (readonly Uint8Array[])[];
  readonly newPeaks: readonly Uint8Array[];
}
export interface MmrInclusionProof {
  readonly v: 1;
  readonly kind: "inclusion";
  readonly size: number;
  readonly leaf_index: number;
  readonly witness: readonly string[];
  readonly peaks_left: readonly string[];
  readonly peaks_right: readonly string[];
}
export interface MmrStructuredConsistencyProof {
  readonly v: 1;
  readonly kind: "consistency";
  readonly size_a: number;
  readonly size_b: number;
  readonly old_peaks: readonly string[];
  readonly witness: readonly (readonly string[])[];
  readonly new_peaks: readonly string[];
}
export interface MmrRangeProof {
  readonly v: 1;
  readonly kind: "range";
  readonly size: number;
  readonly from_index: number;
  readonly to_index: number;
  readonly witness: readonly string[];
}
const ok = (x: Uint8Array): boolean => x.length === 32;
const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);
const be64 = (n: bigint): Uint8Array => {
  const x = new Uint8Array(8);
  new DataView(x.buffer).setBigUint64(0, n);
  return x;
};
const parent = (
  hash: MmrHash,
  l: Uint8Array,
  r: Uint8Array,
  p: number,
): Promise<Uint8Array> => hash(be64(BigInt(p + 1)), l, r);
const toHex = (x: Uint8Array): string =>
  Array.from(x, (b) => b.toString(16).padStart(2, "0")).join("");
const hex = (x: string): Uint8Array | undefined =>
  /^[0-9a-f]{64}$/u.test(x)
    ? Uint8Array.from(x.match(/../gu)!, (b) => Number.parseInt(b, 16))
    : undefined;
function shape(leaves: number): {
  meta: Meta[];
  peaks: number[];
  leaves: number[];
} {
  const meta: Meta[] = [],
    peaks: number[] = [],
    positions: number[] = [];
  for (let i = 0; i < leaves; i += 1) {
    let p = meta.length;
    meta.push({ height: 0 });
    positions.push(p);
    while (peaks.length && meta[peaks.at(-1)!]!.height === meta[p]!.height) {
      const l = peaks.pop()!,
        q = meta.length;
      meta.push({ height: meta[p]!.height + 1, left: l, right: p });
      meta[l]!.parent = q;
      meta[p]!.parent = q;
      p = q;
    }
    peaks.push(p);
  }
  return { meta, peaks, leaves: positions };
}
function path(
  s: ReturnType<typeof shape>,
  nodes: readonly Uint8Array[],
  start: number,
): Uint8Array[] {
  const r: Uint8Array[] = [];
  let p = start;
  while (s.meta[p]!.parent !== undefined) {
    const q = s.meta[p]!.parent!,
      m = s.meta[q]!;
    r.push(Uint8Array.from(nodes[m.left === p ? m.right! : m.left!]!));
    p = q;
  }
  return r;
}
export function leafCount(size: bigint): bigint | undefined {
  if (size < 0n || size > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  const count = (n: bigint) =>
    2n * n - BigInt(n.toString(2).replaceAll("0", "").length);
  let lo = 0n,
    hi = size + 1n;
  while (lo <= hi) {
    const n = (lo + hi) >> 1n,
      c = count(n);
    if (c === size) return n;
    if (c < size) lo = n + 1n;
    else hi = n - 1n;
  }
  return undefined;
}
export async function rootFromPeaks(
  hash: MmrHash,
  peaks: readonly Uint8Array[],
): Promise<Uint8Array> {
  if (!peaks.length) return new Uint8Array(32);
  let root: Uint8Array = Uint8Array.from(peaks.at(-1)!);
  for (let i = peaks.length - 2; i >= 0; i -= 1)
    root = await hash(root, peaks[i]!);
  return root;
}
export function commitmentObject(peaks: readonly Uint8Array[]): Uint8Array {
  if (peaks.some((x) => !ok(x)))
    throw new TypeError("MMR peaks must be 32 bytes");
  return encode(peaks, rfc8949EncodeOptions);
}
export class MmrTree {
  private readonly nodes_: Uint8Array[] = [];
  private readonly meta: Meta[] = [];
  private readonly peaks: number[] = [];
  private readonly leafPositions: number[] = [];
  private readonly ready: Promise<void>;
  public constructor(
    private readonly hash: MmrHash,
    nodes: readonly Uint8Array[] = [],
  ) {
    const leaves = leafCount(BigInt(nodes.length));
    if (leaves === undefined || nodes.some((x) => !ok(x)))
      throw new TypeError("invalid complete MMR nodes");
    const s = shape(Number(leaves));
    this.meta.push(...s.meta);
    this.peaks.push(...s.peaks);
    this.leafPositions.push(...s.leaves);
    this.nodes_.push(...nodes.map((node) => Uint8Array.from(node)));
    this.ready = this.validate();
  }
  private async validate(): Promise<void> {
    for (let position = 0; position < this.meta.length; position += 1) {
      const node = this.meta[position]!;
      if (node.left === undefined || node.right === undefined) continue;
      const expected = await parent(
        this.hash,
        this.nodes_[node.left]!,
        this.nodes_[node.right]!,
        position,
      );
      if (!same(expected, this.nodes_[position]!))
        throw new TypeError(
          `MMR interior node ${position} does not match its children`,
        );
    }
  }
  public get size(): bigint {
    return BigInt(this.nodes_.length);
  }
  public nodes(): readonly Uint8Array[] {
    return this.nodes_.map((node) => Uint8Array.from(node));
  }
  public peakHashes(): readonly Uint8Array[] {
    return this.peaks.map((p) => Uint8Array.from(this.nodes_[p]!));
  }
  public async peakHashesAt(size: bigint): Promise<readonly Uint8Array[]> {
    await this.ready;
    const leaves = leafCount(size);
    if (leaves === undefined || size > this.size)
      throw new RangeError("invalid historical MMR size");
    return shape(Number(leaves)).peaks.map((position) =>
      Uint8Array.from(this.nodes_[position]!),
    );
  }
  private siblingPath(start: number): Uint8Array[] {
    return path(
      { meta: this.meta, peaks: this.peaks, leaves: this.leafPositions },
      this.nodes_,
      start,
    );
  }
  public async append(value: Uint8Array): Promise<bigint> {
    await this.ready;
    if (!ok(value))
      throw new TypeError("CLL leaf value must be exactly 32 bytes");
    let p = this.nodes_.length;
    this.nodes_.push(await this.hash(Uint8Array.of(0), value));
    this.meta.push({ height: 0 });
    this.leafPositions.push(p);
    while (
      this.peaks.length &&
      this.meta[this.peaks.at(-1)!]!.height === this.meta[p]!.height
    ) {
      const l = this.peaks.pop()!,
        q = this.nodes_.length;
      this.nodes_.push(
        await parent(this.hash, this.nodes_[l]!, this.nodes_[p]!, q),
      );
      this.meta.push({ height: this.meta[p]!.height + 1, left: l, right: p });
      this.meta[l]!.parent = q;
      this.meta[p]!.parent = q;
      p = q;
    }
    this.peaks.push(p);
    return this.size;
  }
  public async appendHexIdentity(identity: string): Promise<bigint> {
    const value = hex(identity);
    if (!value)
      throw new TypeError(
        "identity must be 64 lowercase hexadecimal characters",
      );
    return this.append(value);
  }
  public async root(): Promise<Uint8Array> {
    await this.ready;
    return rootFromPeaks(this.hash, this.peakHashes());
  }
  public async inclusionProof(
    leafIndex: bigint,
  ): Promise<readonly Uint8Array[]> {
    await this.ready;
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
    if (right.length !== 0) proof.push(await rootFromPeaks(this.hash, right));
    for (let index = peakIndex - 1; index >= 0; index -= 1)
      proof.push(Uint8Array.from(this.nodes_[this.peaks[index]!]!));
    return proof;
  }
  public async consistencyProof(oldSize: bigint): Promise<MmrConsistencyProof> {
    await this.ready;
    const oldLeaves = leafCount(oldSize);
    if (oldLeaves === undefined || oldSize <= 0n || oldSize > this.size)
      throw new RangeError("invalid previous MMR size");
    const oldShape = shape(Number(oldLeaves));
    return {
      oldSize,
      newSize: this.size,
      oldPeaks: oldShape.peaks.map((position) =>
        Uint8Array.from(this.nodes_[position]!),
      ),
      witness: oldShape.peaks.map((oldPeak) => this.siblingPath(oldPeak)),
      newPeaks: this.peakHashes(),
    };
  }
}
export async function inclusionProof(
  tree: MmrTree,
  leafIndex: bigint,
  size: bigint = tree.size,
): Promise<MmrInclusionProof> {
  const leaves = leafCount(size);
  if (
    leaves === undefined ||
    size > tree.size ||
    leafIndex < 0n ||
    leafIndex >= leaves
  )
    throw new RangeError("invalid MMR inclusion proof request");
  const s = shape(Number(leaves)),
    leaf = s.leaves[Number(leafIndex)]!;
  let p = leaf;
  while (s.meta[p]!.parent !== undefined) p = s.meta[p]!.parent!;
  const peak = s.peaks.indexOf(p),
    nodes = tree.nodes();
  return {
    v: 1,
    kind: "inclusion",
    size: Number(size),
    leaf_index: Number(leafIndex),
    witness: path(s, nodes, leaf).map(toHex),
    peaks_left: s.peaks.slice(0, peak).map((x) => toHex(nodes[x]!)),
    peaks_right: s.peaks.slice(peak + 1).map((x) => toHex(nodes[x]!)),
  };
}
export async function consistencyProof(
  tree: MmrTree,
  sizeA: bigint,
  sizeB: bigint = tree.size,
): Promise<MmrStructuredConsistencyProof> {
  const a = leafCount(sizeA),
    b = leafCount(sizeB);
  if (a === undefined || b === undefined || sizeB < sizeA || sizeB > tree.size)
    throw new RangeError("invalid MMR consistency proof request");
  const old = shape(Number(a)),
    next = shape(Number(b)),
    nodes = tree.nodes();
  return {
    v: 1,
    kind: "consistency",
    size_a: Number(sizeA),
    size_b: Number(sizeB),
    old_peaks: old.peaks.map((x) => toHex(nodes[x]!)),
    witness: old.peaks.map((x) => path(next, nodes, x).map(toHex)),
    new_peaks: next.peaks.map((x) => toHex(nodes[x]!)),
  };
}
export async function verifyInclusionValue(
  hash: MmrHash,
  root: Uint8Array,
  size: bigint,
  leafIndex: bigint,
  value: Uint8Array,
  proof: readonly Uint8Array[],
): Promise<boolean> {
  const leaves = leafCount(size);
  if (
    !ok(root) ||
    !ok(value) ||
    leaves === undefined ||
    leafIndex < 0n ||
    leafIndex >= leaves ||
    proof.some((x) => !ok(x))
  )
    return false;
  const s = shape(Number(leaves)),
    leaf = s.leaves[Number(leafIndex)]!;
  let p = leaf,
    v = await hash(Uint8Array.of(0), value),
    i = 0;
  while (s.meta[p]!.parent !== undefined) {
    const q = s.meta[p]!.parent!,
      m = s.meta[q]!,
      x = proof[i++];
    if (!x) return false;
    v =
      m.left === p ? await parent(hash, v, x, q) : await parent(hash, x, v, q);
    p = q;
  }
  const peak = s.peaks.indexOf(p);
  if (peak < s.peaks.length - 1) {
    const right = proof[i++];
    if (!right) return false;
    v = await hash(right, v);
  }
  for (let left = peak - 1; left >= 0; left -= 1) {
    const item = proof[i++];
    if (!item) return false;
    v = await hash(v, item);
  }
  return i === proof.length && same(v, root);
}
export async function verifyHexInclusion(
  hash: MmrHash,
  root: Uint8Array,
  size: bigint,
  leafIndex: bigint,
  identity: string,
  proof: readonly Uint8Array[],
): Promise<boolean> {
  const value = hex(identity);
  return (
    value !== undefined &&
    verifyInclusionValue(hash, root, size, leafIndex, value, proof)
  );
}
export async function verifyConsistency(
  hash: MmrHash,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: MmrConsistencyProof,
): Promise<boolean> {
  const a = leafCount(proof.oldSize),
    b = leafCount(proof.newSize);
  if (
    !a ||
    b === undefined ||
    proof.oldSize > proof.newSize ||
    proof.witness.length !== proof.oldPeaks.length ||
    proof.oldPeaks.some((x) => !ok(x)) ||
    proof.newPeaks.some((x) => !ok(x))
  )
    return false;
  if (
    !same(await rootFromPeaks(hash, proof.oldPeaks), oldRoot) ||
    !same(await rootFromPeaks(hash, proof.newPeaks), newRoot)
  )
    return false;
  const old = shape(Number(a)),
    next = shape(Number(b));
  for (let j = 0; j < old.peaks.length; j += 1) {
    let p = old.peaks[j]!,
      v = proof.oldPeaks[j]!,
      k = 0;
    while (next.meta[p]!.parent !== undefined) {
      const q = next.meta[p]!.parent!,
        m = next.meta[q]!,
        x = proof.witness[j]![k++];
      if (!x || !ok(x)) return false;
      v =
        m.left === p
          ? await parent(hash, v, x, q)
          : await parent(hash, x, v, q);
      p = q;
    }
    const peak = next.peaks.indexOf(p);
    if (k !== proof.witness[j]!.length || !same(v, proof.newPeaks[peak]!))
      return false;
  }
  return true;
}
// Depth-first walk of the subtree rooted at array position `pos` (height
// `height`, covering leaf indices [leafStart, leafStart + 2**height - 1]):
// appends one witness hash for every maximal subtree wholly outside [lo, hi],
// recurses into any subtree the range only partially covers, and contributes
// nothing for a subtree wholly inside [lo, hi] (the verifier rebuilds that part
// from the leaf hashes it already holds). Left/right children of an interior
// node at `pos` sit at pos - 2**height and pos - 1, matching the module's
// post-order array layout (same convention as shape() and add_leaf).
function rangeWitnesses(
  nodes: readonly Uint8Array[],
  pos: number,
  height: number,
  leafStart: number,
  lo: number,
  hi: number,
  out: string[],
): void {
  const span = 2 ** height,
    leafEnd = leafStart + span - 1;
  if (leafEnd < lo || leafStart > hi) {
    out.push(toHex(nodes[pos]!));
    return;
  }
  if (leafStart >= lo && leafEnd <= hi) return;
  const half = 2 ** (height - 1);
  rangeWitnesses(nodes, pos - span, height - 1, leafStart, lo, hi, out);
  rangeWitnesses(nodes, pos - 1, height - 1, leafStart + half, lo, hi, out);
}
export async function rangeProof(
  tree: MmrTree,
  fromIndex: bigint,
  toIndex: bigint,
  size: bigint = tree.size,
): Promise<MmrRangeProof> {
  const leaves = leafCount(size);
  if (
    leaves === undefined ||
    size > tree.size ||
    fromIndex < 0n ||
    toIndex < fromIndex ||
    toIndex >= leaves
  )
    throw new RangeError("invalid MMR range proof request");
  const s = shape(Number(leaves)),
    nodes = tree.nodes(),
    lo = Number(fromIndex),
    hi = Number(toIndex),
    witness: string[] = [];
  let leafStart = 0;
  for (const p of s.peaks) {
    const h = s.meta[p]!.height;
    rangeWitnesses(nodes, p, h, leafStart, lo, hi, witness);
    leafStart += 2 ** h;
  }
  return {
    v: 1,
    kind: "range",
    size: Number(size),
    from_index: lo,
    to_index: hi,
    witness,
  };
}
export async function verifyRange(
  hash: MmrHash,
  root: Uint8Array,
  size: bigint,
  fromIndex: bigint,
  toIndex: bigint,
  bodyDigests: readonly Uint8Array[],
  proof: MmrRangeProof,
): Promise<boolean> {
  try {
    if (!ok(root)) return false;
    if (
      proof === undefined ||
      proof === null ||
      proof.v !== 1 ||
      proof.kind !== "range"
    )
      return false;
    if (
      proof.size !== Number(size) ||
      proof.from_index !== Number(fromIndex) ||
      proof.to_index !== Number(toIndex)
    )
      return false;
    // MAX_MMR_SIZE parity with the Python reference (core.verify_range rejects
    // size >= 2**50) — refuse absurd sizes before any traversal.
    if (size < 0n || size >= 2n ** 50n || fromIndex < 0n || toIndex < fromIndex)
      return false;
    if (!Array.isArray(proof.witness) || !Array.isArray(bodyDigests))
      return false;
    if (BigInt(bodyDigests.length) !== toIndex - fromIndex + 1n) return false;
    const leaves = leafCount(size);
    if (leaves === undefined || toIndex >= leaves) return false;
    if (bodyDigests.some((d) => !ok(d))) return false;
    const witnessBytes: Uint8Array[] = [];
    for (const w of proof.witness) {
      const b = hex(w);
      if (!b) return false;
      witnessBytes.push(b);
    }
    const s = shape(Number(leaves)),
      lo = Number(fromIndex),
      hi = Number(toIndex),
      cursor = { index: 0 };
    // Rebuild every peak the range touches: a subtree wholly outside [lo, hi]
    // consumes one witness, a single covered leaf is hashed from its body
    // digest, and a partially covered subtree folds its two reconstructed
    // children. bodyDigests[i] is the body digest for leaf index lo + i.
    const reconstruct = async (
      pos: number,
      height: number,
      leafStart: number,
    ): Promise<Uint8Array> => {
      const span = 2 ** height,
        leafEnd = leafStart + span - 1;
      if (leafEnd < lo || leafStart > hi) {
        const w = witnessBytes[cursor.index];
        if (!w) throw new RangeError("range proof witness exhausted");
        cursor.index += 1;
        return w;
      }
      if (height === 0)
        return hash(Uint8Array.of(0), bodyDigests[leafStart - lo]!);
      const half = 2 ** (height - 1),
        left = await reconstruct(pos - span, height - 1, leafStart),
        right = await reconstruct(pos - 1, height - 1, leafStart + half);
      return parent(hash, left, right, pos);
    };
    const reconstructedPeaks: Uint8Array[] = [];
    let leafStart = 0;
    for (const p of s.peaks) {
      const h = s.meta[p]!.height;
      reconstructedPeaks.push(await reconstruct(p, h, leafStart));
      leafStart += 2 ** h;
    }
    if (cursor.index !== witnessBytes.length) return false;
    return same(await rootFromPeaks(hash, reconstructedPeaks), root);
  } catch {
    return false;
  }
}
