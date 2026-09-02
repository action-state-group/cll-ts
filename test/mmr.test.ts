import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  commitmentObject,
  MmrTree,
  verifyConsistency,
  verifyInclusion,
  verifyInclusionValue,
} from "../src/index.js";

const commitmentVectors = JSON.parse(
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

const expected = [
  "184208f662bb7a6f5cc14a39988f74f2bb05bd3f934311da0aa3f65a950d8e01",
  "f7b19d3f831d2cddfe91865465a8beb649e4bf16c3aa2fde7378e7ee2e215694",
  "e5280e43815bcb82f184d4dbe10741b65a28c34488a9a3029e0e08d1cbed9a17",
  "44588de7a213cb67d681fd0822d22f57248a50b5cab4d5579c1d9162403b6755",
  "a19de527084fc32502d998b4dd0e73f942d3b4ddc55b2c093dfd907e95a93f1a",
  "ade39981df4d01db5a3c3e5d1ff0a6f87ea3a63077820d37599c6a39fb904b01",
  "a0c0e8e7d78bf06dee4c988a228ff034dca8a25964a4af89a3d7d11670f31d10",
];
describe("CLL MMR", () => {
  for (const vector of commitmentVectors.cases) {
    it(`matches CLL 0.1.0 commitment vector ${vector.name}`, () => {
      const actual = Buffer.from(
        commitmentObject(
          vector.peak_hashes.map((peak) => Buffer.from(peak, "hex")),
        ),
      ).toString("hex");
      if (vector.kind === "positive")
        expect(actual).toBe(vector.commitment_hex);
      else expect(actual).not.toBe(vector.commitment_hex);
    });
  }
  it("appends application-neutral entry bytes and rejects empty values", () => {
    const generic = new MmrTree();
    const compatible = new MmrTree();
    const value = Uint8Array.from({ length: 32 }, () => 0x11);

    expect(generic.append(value)).toBe(1n);
    expect(compatible.appendCapsuleId("11".repeat(32))).toBe(1n);
    expect(generic.root()).toEqual(compatible.root());
    expect(
      verifyInclusionValue(
        generic.root(),
        generic.size,
        0n,
        value,
        generic.inclusionProof(0n),
      ),
    ).toBe(true);
    expect(
      verifyInclusionValue(
        generic.root(),
        generic.size,
        0n,
        Uint8Array.of(1),
        generic.inclusionProof(0n),
      ),
    ).toBe(false);
    expect(() => generic.append(new Uint8Array())).toThrow(
      "CLL leaf value must be exactly 32 bytes",
    );
  });
  it("matches Python roots and DataTrails bagged proofs", () => {
    const tree = new MmrTree();
    const ids: string[] = [];
    expected.forEach((root, index) => {
      const id = createHash("sha256")
        .update(`asg-ledger-mmr-vector-leaf-${index + 1}`)
        .digest("hex");
      ids.push(id);
      tree.appendCapsuleId(id);
      expect(Buffer.from(tree.root()).toString("hex")).toBe(root);
    });
    ids.forEach((id, index) => {
      const proof = tree.inclusionProof(BigInt(index));
      expect(
        verifyInclusion(tree.root(), tree.size, BigInt(index), id, proof),
      ).toBe(true);
      const bad = proof.map((item) => Uint8Array.from(item));
      const first = bad[0];
      if (first !== undefined) first[0] = (first[0] ?? 0) ^ 1;
      expect(
        verifyInclusion(tree.root(), tree.size, BigInt(index), id, bad),
      ).toBe(false);
    });
  });
  it("proves append-only extension between complete historical sizes", () => {
    const tree = new MmrTree();
    for (let i = 0; i < 7; i += 1)
      tree.appendCapsuleId(
        createHash("sha256").update(`leaf-${i}`).digest("hex"),
      );
    const proof = tree.consistencyProof(7n);
    const oldRoot = new MmrTree(tree.nodes().slice(0, 7)).root();
    expect(verifyConsistency(oldRoot, tree.root(), proof)).toBe(true);
    const bad = {
      ...proof,
      newPeaks: proof.newPeaks.map((item) => Uint8Array.from(item)),
    };
    bad.newPeaks[0]![0] = (bad.newPeaks[0]![0] ?? 0) ^ 1;
    expect(verifyConsistency(oldRoot, tree.root(), bad)).toBe(false);
  });
  it("encodes commitments with 24 or more peaks canonically", () => {
    const encoded = commitmentObject(
      Array.from({ length: 24 }, (_, index) =>
        Uint8Array.from({ length: 32 }, () => index),
      ),
    );
    expect(encoded.subarray(0, 2)).toEqual(Uint8Array.of(0x98, 0x18));
  });
  it("rebuilds a complete MMR beyond the spread-argument ceiling", () => {
    const tree = new MmrTree();
    for (let index = 0; index < 70_000; index += 1)
      tree.appendCapsuleId(
        createHash("sha256").update(`large-${index}`).digest("hex"),
      );
    const restored = new MmrTree(tree.nodes());
    expect(restored.size).toBe(tree.size);
    expect(restored.root()).toEqual(tree.root());
  });
  it("rejects a tampered persisted interior node", () => {
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    tree.appendCapsuleId("22".repeat(32));
    const nodes = tree.nodes().map((node) => Uint8Array.from(node));
    nodes[2]![0] = nodes[2]![0]! ^ 1;
    expect(() => new MmrTree(nodes)).toThrow("does not match its children");
  });
});
