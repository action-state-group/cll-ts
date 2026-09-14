import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  consistencyProof,
  inclusionProof,
  MmrTree,
  verifyInclusionValue,
} from "../src/mmr-node.js";
import * as browser from "../src/browser.js";

// Byte-for-byte copy of checkpointed-local-log/mmr-conformance-vectors/vectors.json.
type Vector = Record<string, unknown>;
const vectors = JSON.parse(
  readFileSync(resolve("test/testdata/mmr-conformance-vectors.json"), "utf8"),
) as { cases: Vector[] };
const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

describe("pinned Python MMR proof vectors", () => {
  const roots = vectors.cases.filter((entry) => entry.kind === "root");
  const inclusions = vectors.cases.filter(
    (entry) => entry.kind === "inclusion",
  );
  const consistencies = vectors.cases.filter(
    (entry) => entry.kind === "consistency",
  );
  const tree = new MmrTree();
  const browserTree = new browser.MmrTree();
  const append = async () => {
    for (let seq = 1; seq <= 7; seq += 1) {
      const body = Uint8Array.from(
        createHash("sha256")
          .update(`asg-ledger-mmr-vector-leaf-${seq}`, "utf8")
          .digest(),
      );
      await tree.append(body);
      await browserTree.append(body);
    }
  };
  it("matches every root, inclusion, and consistency case in Node and browser MMR paths", async () => {
    await append();
    for (const vector of roots) {
      const size = BigInt(vector.size as number);
      expect(
        Buffer.from(
          await new MmrTree(tree.nodes().slice(0, Number(size))).root(),
        ),
      ).toEqual(Buffer.from(bytes(vector.root_hex as string)));
      expect(
        Buffer.from(
          await new browser.MmrTree(
            browserTree.nodes().slice(0, Number(size)),
          ).root(),
        ),
      ).toEqual(Buffer.from(bytes(vector.root_hex as string)));
    }
    for (const vector of inclusions) {
      const size = BigInt(vector.size as number);
      const leafIndex = BigInt(vector.leaf_index as number);
      const partial = new MmrTree(tree.nodes().slice(0, Number(size)));
      expect(await inclusionProof(partial, leafIndex)).toEqual(vector.proof);
      expect(
        await browser.inclusionProof(
          new browser.MmrTree(browserTree.nodes().slice(0, Number(size))),
          leafIndex,
        ),
      ).toEqual(vector.proof);
      expect(
        await verifyInclusionValue(
          await partial.root(),
          size,
          leafIndex,
          bytes(vector.body_digest_hex as string),
          await partial.inclusionProof(leafIndex),
        ),
      ).toBe(true);
      expect(
        await browser.verifyInclusionValue(
          await new browser.MmrTree(
            browserTree.nodes().slice(0, Number(size)),
          ).root(),
          size,
          leafIndex,
          bytes(vector.body_digest_hex as string),
          await partial.inclusionProof(leafIndex),
        ),
      ).toBe(true);
    }
    for (const vector of consistencies) {
      const sizeA = BigInt(vector.size_a as number),
        sizeB = BigInt(vector.size_b as number);
      const partial = new MmrTree(tree.nodes().slice(0, Number(sizeB)));
      expect(await consistencyProof(partial, sizeA, sizeB)).toEqual(
        vector.proof,
      );
      expect(
        await browser.consistencyProof(
          new browser.MmrTree(browserTree.nodes().slice(0, Number(sizeB))),
          sizeA,
          sizeB,
        ),
      ).toEqual(vector.proof);
      if (sizeA > 0n) {
        expect(
          await browser.verifyConsistency(
            await new browser.MmrTree(
              browserTree.nodes().slice(0, Number(sizeA)),
            ).root(),
            await new browser.MmrTree(
              browserTree.nodes().slice(0, Number(sizeB)),
            ).root(),
            await partial.consistencyProof(sizeA),
          ),
        ).toBe(true);
      }
    }
  });
  it("rejects a flipped pinned root", async () => {
    const root = roots[0]!.root_hex as string;
    expect(await new MmrTree().root()).not.toEqual(bytes(root));
  });
});
