import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { jcs } from "capsule-emit-ts/aac";
import { checkpointProjection, verifyCheckpoint } from "./checkpoint.js";
import { limits } from "./types.js";
import type { AnchorReceipt } from "./witness.js";

const encodeCanonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);
const sha = (...parts: readonly Uint8Array[]): Uint8Array =>
  createHash("sha256").update(Buffer.concat(parts)).digest();
const nodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array =>
  sha(Uint8Array.of(1), left, right);
const largestPowerBelow = (value: number): number => {
  let power = 1;
  while (power * 2 < value) power *= 2;
  return power;
};
const expectedPath = (size: number, index: number): number => {
  let count = 0;
  let nodes = size;
  let position = index;
  while (nodes > 1) {
    count += 1;
    const split = largestPowerBelow(nodes);
    if (position < split) nodes = split;
    else {
      nodes -= split;
      position -= split;
    }
  }
  return count;
};

function proofRoot(
  entry: Uint8Array,
  index: number,
  size: number,
  path: readonly Uint8Array[],
): Uint8Array | undefined {
  if (
    !Number.isSafeInteger(index) ||
    !Number.isSafeInteger(size) ||
    index < 0 ||
    index >= size ||
    size > 2 ** 53 - 1 ||
    path.length !== expectedPath(size, index)
  )
    return undefined;
  const siblings = [...path];
  const leaf = sha(Uint8Array.of(0), entry);
  const fold = (nodes: number, position: number): Uint8Array | undefined => {
    if (nodes === 1) return leaf;
    const sibling = siblings.pop();
    if (sibling === undefined) return undefined;
    const split = largestPowerBelow(nodes);
    if (position < split) {
      const child = fold(split, position);
      return child === undefined ? undefined : nodeHash(child, sibling);
    }
    const child = fold(nodes - split, position - split);
    return child === undefined ? undefined : nodeHash(sibling, child);
  };
  const root = fold(size, index);
  return root !== undefined && siblings.length === 0 ? root : undefined;
}

function checkpointEntry(checkpoint: Uint8Array): Uint8Array | undefined {
  if (!verifyCheckpoint(checkpoint)) return undefined;
  const items = decode(checkpoint.subarray(1), {
    allowIndefinite: false,
    useMaps: true,
  }) as unknown[];
  const headers = decode(items[0] as Uint8Array, {
    allowIndefinite: false,
    useMaps: true,
  }) as Map<number, unknown>;
  const claims = decode(items[2] as Uint8Array, {
    allowIndefinite: false,
    useMaps: true,
  }) as Map<string, unknown>;
  const cwt = headers.get(15) as Map<number, unknown>;
  const peaks = decode(claims.get("commitment") as Uint8Array) as Uint8Array[];
  const previousCommitment = claims.get("prev_commitment") as Uint8Array;
  const previousPeaks =
    previousCommitment.length === 0
      ? []
      : (decode(previousCommitment) as Uint8Array[]);
  const projection = checkpointProjection({
    logId: cwt.get(1) as string,
    mmrSize: claims.get("log_size") as number,
    peaks,
    previousSize: claims.get("prev_size") as number,
    previousPeaks,
    keyId: Buffer.from(headers.get(4) as Uint8Array).toString("hex"),
    timestamp: claims.get("issued_at") as string,
  });
  return sha(sha(jcs(projection)));
}

/** Offline RFC 9162 receipt verifier under a pinned Ed25519 authority key. */
export class ReceiptVerifier {
  private readonly publicKey: Uint8Array;
  public constructor(publicKey: Uint8Array) {
    if (publicKey.length !== 32)
      throw new TypeError("pinned Ed25519 authority key must be 32 bytes");
    this.publicKey = Uint8Array.from(publicKey);
  }

  public verify(checkpoint: Uint8Array, receipt: AnchorReceipt): boolean {
    try {
      if (
        receipt.bytes.length === 0 ||
        receipt.bytes.length > limits.receipt ||
        receipt.entryHashScheme !== "legacy" ||
        !/^[0-9a-f]{64}$/u.test(receipt.entryHash) ||
        receipt.bytes[0] !== 0xd2
      )
        return false;
      const entry = checkpointEntry(checkpoint);
      if (
        entry === undefined ||
        Buffer.from(entry).toString("hex") !== receipt.entryHash
      )
        return false;
      const items = decode(receipt.bytes.subarray(1), {
        allowIndefinite: false,
        useMaps: true,
      }) as unknown[];
      if (
        !Array.isArray(items) ||
        items.length !== 4 ||
        !(items[0] instanceof Uint8Array) ||
        !(items[1] instanceof Map) ||
        items[2] !== null ||
        !(items[3] instanceof Uint8Array)
      )
        return false;
      const protectedHeaders = decode(items[0], {
        allowIndefinite: false,
        useMaps: true,
      }) as Map<number, unknown>;
      if (protectedHeaders.get(1) !== -8 || protectedHeaders.get(395) !== 1)
        return false;
      const vdp = items[1].get(396);
      if (!(vdp instanceof Map)) return false;
      const proofs = vdp.get(-1);
      if (
        !Array.isArray(proofs) ||
        proofs.length !== 1 ||
        !(proofs[0] instanceof Uint8Array)
      )
        return false;
      const proof = decode(proofs[0], { allowIndefinite: false }) as unknown[];
      if (
        !Array.isArray(proof) ||
        proof.length !== 3 ||
        !Number.isSafeInteger(proof[0]) ||
        !Number.isSafeInteger(proof[1]) ||
        !Array.isArray(proof[2]) ||
        proof[2].some(
          (hash) => !(hash instanceof Uint8Array) || hash.length !== 32,
        ) ||
        proof[0] !== receipt.treeSize ||
        proof[1] !== receipt.leafIndex
      )
        return false;
      const root = proofRoot(
        entry,
        receipt.leafIndex,
        receipt.treeSize,
        proof[2] as Uint8Array[],
      );
      if (root === undefined) return false;
      const key = createPublicKey({
        key: Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          this.publicKey,
        ]),
        format: "der",
        type: "spki",
      });
      return edVerify(
        null,
        encodeCanonical(["Signature1", items[0], new Uint8Array(), root]),
        key,
        items[3],
      );
    } catch {
      return false;
    }
  }
}
