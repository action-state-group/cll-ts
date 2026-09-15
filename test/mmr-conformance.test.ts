import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import * as node from "../src/mmr-node.js";
import * as browser from "../src/browser.js";

// Byte-for-byte copy of checkpointed-local-log/mmr-conformance-vectors/vectors.json.
// This test mirrors that repo's reference_verifier.py: every case is a positive
// unless it carries `expect: false` (a tamper case that MUST fail verification
// and is NOT regenerate-compared); positives must both regenerate byte-identical
// and verify true. Both the Node and browser MMR paths run every case.
type Vector = Record<string, unknown>;
const vectors = JSON.parse(
  readFileSync(resolve("test/testdata/mmr-conformance-vectors.json"), "utf8"),
) as { leaf_identity: { template: string }; cases: Vector[] };
const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

type Mmr = typeof node;
type Tree = InstanceType<Mmr["MmrTree"]>;

const buildTree = async (m: Mmr): Promise<Tree> => {
  const tree = new m.MmrTree();
  for (let seq = 1; seq <= 7; seq += 1) {
    const body = Uint8Array.from(
      createHash("sha256")
        .update(
          vectors.leaf_identity.template.replace("{seq}", String(seq)),
          "utf8",
        )
        .digest(),
    );
    await tree.append(body);
  }
  return tree;
};

// Rebuild the flat inclusion witness array verifyInclusionValue expects from a
// structured InclusionProof (witness siblings, then the bagged right peaks, then
// the left peaks tallest-first), so a tampered vector proof is checked verbatim.
const flatInclusion = async (
  m: Mmr,
  proof: node.MmrInclusionProof,
): Promise<Uint8Array[]> => {
  const flat = proof.witness.map(bytes);
  const right = proof.peaks_right.map(bytes);
  const left = proof.peaks_left.map(bytes);
  if (right.length) flat.push(await m.rootFromPeaks(right));
  for (let i = left.length - 1; i >= 0; i -= 1) flat.push(left[i]!);
  return flat;
};

const verifyCase = async (m: Mmr, tree: Tree, c: Vector): Promise<boolean> => {
  if (c.kind === "root") {
    const size = c.size as number;
    const root = await new m.MmrTree(tree.nodes().slice(0, size)).root();
    return Buffer.from(root).toString("hex") === c.root_hex;
  }
  if (c.kind === "inclusion") {
    return m.verifyInclusionValue(
      bytes(c.root_hex as string),
      BigInt(c.size as number),
      BigInt(c.leaf_index as number),
      bytes(c.body_digest_hex as string),
      await flatInclusion(m, c.proof as node.MmrInclusionProof),
    );
  }
  if (c.kind === "consistency") {
    const p = c.proof as node.MmrStructuredConsistencyProof;
    return m.verifyConsistency(
      bytes(c.root_a_hex as string),
      bytes(c.root_b_hex as string),
      {
        oldSize: BigInt(p.size_a),
        newSize: BigInt(p.size_b),
        oldPeaks: p.old_peaks.map(bytes),
        witness: p.witness.map((w) => w.map(bytes)),
        newPeaks: p.new_peaks.map(bytes),
      },
    );
  }
  if (c.kind === "range") {
    return m.verifyRange(
      bytes(c.root_hex as string),
      BigInt(c.size as number),
      BigInt(c.from_index as number),
      BigInt(c.to_index as number),
      (c.body_digests as string[]).map(bytes),
      c.proof as node.MmrRangeProof,
    );
  }
  throw new Error(`unknown kind ${String(c.kind)}`);
};

const regenerate = async (m: Mmr, tree: Tree, c: Vector): Promise<void> => {
  if (c.kind === "inclusion") {
    const partial = new m.MmrTree(tree.nodes().slice(0, c.size as number));
    expect(
      await m.inclusionProof(partial, BigInt(c.leaf_index as number)),
    ).toEqual(c.proof);
  } else if (c.kind === "consistency") {
    const partial = new m.MmrTree(tree.nodes().slice(0, c.size_b as number));
    expect(
      await m.consistencyProof(
        partial,
        BigInt(c.size_a as number),
        BigInt(c.size_b as number),
      ),
    ).toEqual(c.proof);
  } else if (c.kind === "range") {
    const partial = new m.MmrTree(tree.nodes().slice(0, c.size as number));
    expect(
      await m.rangeProof(
        partial,
        BigInt(c.from_index as number),
        BigInt(c.to_index as number),
        BigInt(c.size as number),
      ),
    ).toEqual(c.proof);
  }
};

describe("pinned Python MMR proof vectors", () => {
  const modules: Mmr[] = [node, browser];
  it("mirrors the reference verifier across all cases in Node and browser MMR paths", async () => {
    for (const m of modules) {
      const tree = await buildTree(m);
      for (const c of vectors.cases) {
        const expected = c.expect === undefined ? true : (c.expect as boolean);
        // cll-ts's verifyConsistency rejects the empty-to-empty MMR (leafCount
        // 0 is falsy); its generator still emits the empty proof. This is a
        // pre-existing boundary unrelated to the range port, so skip verifying
        // only that edge (matching the original test's `sizeA > 0` guard) while
        // still regenerating it.
        const skipVerify = c.kind === "consistency" && Number(c.size_a) === 0;
        if (!skipVerify)
          expect(await verifyCase(m, tree, c), c.name as string).toBe(expected);
        if (expected) await regenerate(m, tree, c);
      }
    }
  });
  it("rejects a flipped pinned root", async () => {
    const root = vectors.cases.find((c) => c.kind === "root")!
      .root_hex as string;
    expect(await new node.MmrTree().root()).not.toEqual(bytes(root));
  });
});
