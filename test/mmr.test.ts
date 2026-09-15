import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  commitmentObject,
  MmrTree,
  rangeProof,
  rootFromPeaks,
  verifyConsistency,
  verifyHexInclusion,
  verifyInclusionValue,
  verifyRange,
} from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(
    resolve(
      process.env.CLL_ROOT ?? "../checkpointed-local-log",
      "commitment-conformance-vectors/vectors.json",
    ),
    "utf8",
  ),
) as {
  cases: Array<{
    name: string;
    kind: "positive" | "must-fail";
    peak_hashes: string[];
    commitment_hex: string;
  }>;
};

const entry = (byte: number) => Uint8Array.from({ length: 32 }, () => byte);

describe("CLL MMR", () => {
  for (const vector of vectors.cases)
    it(`matches commitment vector ${vector.name}`, () => {
      const actual = Buffer.from(
        commitmentObject(
          vector.peak_hashes.map((peak) => Buffer.from(peak, "hex")),
        ),
      ).toString("hex");
      if (vector.kind === "positive")
        expect(actual).toBe(vector.commitment_hex);
      else expect(actual).not.toBe(vector.commitment_hex);
    });

  it("appends opaque 32-byte values and proves inclusion", async () => {
    const tree = new MmrTree();
    for (const byte of [1, 2, 3, 4, 5]) await tree.append(entry(byte));
    for (let index = 0; index < 5; index += 1) {
      const proof = await tree.inclusionProof(BigInt(index));
      expect(
        await verifyInclusionValue(
          await tree.root(),
          tree.size,
          BigInt(index),
          entry(index + 1),
          proof,
        ),
      ).toBe(true);
      const bad = proof.map((node) => Uint8Array.from(node));
      if (bad[0] !== undefined) bad[0][0] = bad[0][0]! ^ 1;
      expect(
        await verifyInclusionValue(
          await tree.root(),
          tree.size,
          BigInt(index),
          entry(index + 1),
          bad,
        ),
      ).toBe(false);
    }
    await expect(tree.append(Uint8Array.of(1))).rejects.toThrow(
      "exactly 32 bytes",
    );
  });

  it("supports canonical hexadecimal identities like cll-go", async () => {
    const identity = "ab".repeat(32);
    const tree = new MmrTree();
    await tree.appendHexIdentity(identity);
    expect(
      await verifyHexInclusion(await tree.root(), tree.size, 0n, identity, []),
    ).toBe(true);
    expect(
      await verifyHexInclusion(
        await tree.root(),
        tree.size,
        0n,
        identity.toUpperCase(),
        [],
      ),
    ).toBe(false);
    await expect(
      tree.appendHexIdentity(identity.toUpperCase()),
    ).rejects.toThrow("lowercase hexadecimal");
  });

  it("proves append-only extension from a historical size", async () => {
    const tree = new MmrTree();
    for (let byte = 1; byte <= 7; byte += 1) await tree.append(entry(byte));
    const oldSize = 7n;
    const oldRoot = await new MmrTree(
      tree.nodes().slice(0, Number(oldSize)),
    ).root();
    for (let byte = 8; byte <= 12; byte += 1) await tree.append(entry(byte));
    expect(
      await verifyConsistency(
        oldRoot,
        await tree.root(),
        await tree.consistencyProof(oldSize),
      ),
    ).toBe(true);
  });

  it("rejects corrupted reconstructed nodes", async () => {
    const tree = new MmrTree();
    await tree.append(entry(1));
    await tree.append(entry(2));
    const nodes = tree.nodes().map((node) => Uint8Array.from(node));
    nodes[2]![0] = nodes[2]![0]! ^ 1;
    await expect(new MmrTree(nodes).root()).rejects.toThrow(
      "does not match its children",
    );
  });

  it("encodes 24 or more peaks without spread limits", () => {
    const encoded = commitmentObject(
      Array.from({ length: 24 }, (_, index) => entry(index)),
    );
    expect(encoded.subarray(0, 2)).toEqual(Uint8Array.of(0x98, 0x18));
  });

  // The three pure verifiers derive peaks and the fold path arithmetically
  // (O(log size)), never the O(size) full-tree shape(). A crafted enormous
  // `size` from an untrusted proof must therefore be rejected promptly instead
  // of allocating a tree with billions of nodes and hanging the (browser)
  // verifier. Each case uses a valid MMR size near 2**50 with a deliberately
  // short/empty proof: the arithmetic path finishes essentially instantly and
  // returns false, so the tight timeout fails the test if O(size) ever returns.
  describe("reject an oversized MMR size without O(size) work", () => {
    // Perfect single-peak tree of 2**48 leaves -> size 2**49 - 1 (< 2**50).
    const hugeSize = 2n ** 49n - 1n;

    it("verifyInclusionValue", async () => {
      expect(
        await verifyInclusionValue(entry(1), hugeSize, 0n, entry(0), []),
      ).toBe(false);
    }, 2000);

    it("verifyRange", async () => {
      expect(
        await verifyRange(entry(1), hugeSize, 0n, 0n, [entry(0)], {
          v: 1,
          kind: "range",
          size: Number(hugeSize),
          from_index: 0,
          to_index: 0,
          witness: [],
        }),
      ).toBe(false);
    }, 2000);

    it("verifyConsistency", async () => {
      // old: 2**40 leaves (size 2**41 - 1); new: 2**45 leaves (size 2**46 - 1).
      const oldSize = 2n ** 41n - 1n;
      const newSize = 2n ** 46n - 1n;
      const peak = entry(9);
      const root = await rootFromPeaks([peak]);
      expect(
        await verifyConsistency(root, root, {
          oldSize,
          newSize,
          oldPeaks: [peak],
          witness: [[]],
          newPeaks: [peak],
        }),
      ).toBe(false);
    }, 2000);
  });

  // Independent re-implementation of the two MMR hashing primitives, used to
  // hand-build the root a single-leaf-0 inclusion proof folds to at a size no
  // real tree could ever materialize. Leaf 0 is the left child at every level,
  // so its ancestor at level k sits at post-order position 2**(k+1)-2.
  const be64 = (n: bigint) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n);
    return b;
  };
  const sha = (...parts: Uint8Array[]) => {
    const h = createHash("sha256");
    for (const p of parts) h.update(p);
    return new Uint8Array(h.digest());
  };
  const foldLeafZeroRoot = (
    height: number,
    value: Uint8Array,
    siblings: Uint8Array[],
  ) => {
    let v = sha(Uint8Array.of(0), value);
    for (let k = 1; k <= height; k += 1)
      v = sha(be64(2n ** BigInt(k + 1) - 1n), v, siblings[k - 1]!);
    return v;
  };

  it("accepts a valid single-leaf proof below the bound but the 2**50 bound rejects the identical shape above it", async () => {
    const value = entry(3);
    // Below the bound: 2**48 leaves -> size 2**49 - 1, one peak of height 48.
    // The arithmetic verifier must reproduce foldLeafZeroRoot exactly.
    const below = Array.from({ length: 48 }, (_, k) => entry((k % 200) + 1));
    expect(
      await verifyInclusionValue(
        foldLeafZeroRoot(48, value, below),
        2n ** 49n - 1n,
        0n,
        value,
        below,
      ),
    ).toBe(true);
    // Identical construction one level taller: size 2**51 - 1 (>= 2**50). This
    // proof WOULD verify if the bound were removed, so the test fails closed if
    // anyone drops the 2**50 guard from verifyInclusionValue.
    const above = Array.from({ length: 50 }, (_, k) => entry((k % 200) + 1));
    expect(
      await verifyInclusionValue(
        foldLeafZeroRoot(50, value, above),
        2n ** 51n - 1n,
        0n,
        value,
        above,
      ),
    ).toBe(false);
  }, 4000);

  // The refactor's hard requirement is that the arithmetic verifiers stay
  // byte-identical to the O(size) shape()-based producers for every input.
  // Cross-check the two independent code paths across tree shapes up to 48
  // leaves (multi-peak, mountains up to height 5) — far past the <=11-leaf
  // pinned vectors — for inclusion (every leaf), range, and consistency.
  it("agrees with the shape()-based producer across tree shapes", async () => {
    const value = (i: number) => entry((i % 200) + 1);
    const snaps: { size: bigint; root: Uint8Array }[] = [];
    const tree = new MmrTree();
    for (let n = 1; n <= 48; n += 1) {
      await tree.append(value(n - 1));
      const root = await tree.root();
      const size = tree.size;
      snaps.push({ size, root });
      const digests = Array.from({ length: n }, (_, i) => value(i));

      for (let i = 0; i < n; i += 1) {
        const proof = await tree.inclusionProof(BigInt(i));
        expect(
          await verifyInclusionValue(root, size, BigInt(i), value(i), proof),
        ).toBe(true);
        // A wrong leaf value at the same index must fail (root mismatch).
        expect(
          await verifyInclusionValue(
            root,
            size,
            BigInt(i),
            value(i + 100),
            proof,
          ),
        ).toBe(false);
      }

      const ranges: [number, number][] = [[0, n - 1]];
      if (n >= 3) ranges.push([1, n - 2]);
      for (const [lo, hi] of ranges) {
        const rp = await rangeProof(tree, BigInt(lo), BigInt(hi), size);
        const body = digests.slice(lo, hi + 1);
        expect(
          await verifyRange(root, size, BigInt(lo), BigInt(hi), body, rp),
        ).toBe(true);
        const tampered = body.map((d, i) => (i === 0 ? entry(0) : d));
        expect(
          await verifyRange(root, size, BigInt(lo), BigInt(hi), tampered, rp),
        ).toBe(false);
      }
    }
    const last = snaps.at(-1)!;
    for (let k = 0; k < snaps.length - 1; k += 1) {
      const proof = await tree.consistencyProof(snaps[k]!.size);
      expect(await verifyConsistency(snaps[k]!.root, last.root, proof)).toBe(
        true,
      );
    }
  }, 20000);
});
