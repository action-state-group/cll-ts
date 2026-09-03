import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  commitmentObject,
  MmrTree,
  verifyConsistency,
  verifyHexInclusion,
  verifyInclusionValue,
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

  it("appends opaque 32-byte values and proves inclusion", () => {
    const tree = new MmrTree();
    for (const byte of [1, 2, 3, 4, 5]) tree.append(entry(byte));
    for (let index = 0; index < 5; index += 1) {
      const proof = tree.inclusionProof(BigInt(index));
      expect(
        verifyInclusionValue(
          tree.root(),
          tree.size,
          BigInt(index),
          entry(index + 1),
          proof,
        ),
      ).toBe(true);
      const bad = proof.map((node) => Uint8Array.from(node));
      if (bad[0] !== undefined) bad[0][0] = bad[0][0]! ^ 1;
      expect(
        verifyInclusionValue(
          tree.root(),
          tree.size,
          BigInt(index),
          entry(index + 1),
          bad,
        ),
      ).toBe(false);
    }
    expect(() => tree.append(Uint8Array.of(1))).toThrow("exactly 32 bytes");
  });

  it("supports canonical hexadecimal identities like cll-go", () => {
    const identity = "ab".repeat(32);
    const tree = new MmrTree();
    tree.appendHexIdentity(identity);
    expect(verifyHexInclusion(tree.root(), tree.size, 0n, identity, [])).toBe(
      true,
    );
    expect(
      verifyHexInclusion(
        tree.root(),
        tree.size,
        0n,
        identity.toUpperCase(),
        [],
      ),
    ).toBe(false);
    expect(() => tree.appendHexIdentity(identity.toUpperCase())).toThrow(
      "lowercase hexadecimal",
    );
  });

  it("proves append-only extension from a historical size", () => {
    const tree = new MmrTree();
    for (let byte = 1; byte <= 7; byte += 1) tree.append(entry(byte));
    const oldSize = 7n;
    const oldRoot = new MmrTree(tree.nodes().slice(0, Number(oldSize))).root();
    for (let byte = 8; byte <= 12; byte += 1) tree.append(entry(byte));
    expect(
      verifyConsistency(oldRoot, tree.root(), tree.consistencyProof(oldSize)),
    ).toBe(true);
  });

  it("rejects corrupted reconstructed nodes", () => {
    const tree = new MmrTree();
    tree.append(entry(1));
    tree.append(entry(2));
    const nodes = tree.nodes().map((node) => Uint8Array.from(node));
    nodes[2]![0] = nodes[2]![0]! ^ 1;
    expect(() => new MmrTree(nodes)).toThrow("does not match its children");
  });

  it("encodes 24 or more peaks without spread limits", () => {
    const encoded = commitmentObject(
      Array.from({ length: 24 }, (_, index) => entry(index)),
    );
    expect(encoded.subarray(0, 2)).toEqual(Uint8Array.of(0x98, 0x18));
  });
});
