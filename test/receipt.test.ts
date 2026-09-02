import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { describe, expect, it } from "vitest";
import { ReceiptVerifier, type AnchorReceipt } from "../src/index.js";

const fixture = resolve("test/fixtures/capsule-anchor-leg1");
const checkpoint = readFileSync(resolve(fixture, "checkpoint.cose"));
const receiptBytes = readFileSync(resolve(fixture, "receipt.cose"));
const authorityKey = Buffer.from(
  "39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5",
  "hex",
);
const receipt: AnchorReceipt = {
  bytes: receiptBytes,
  entryHash: "b16766df5e64792852c1da1210a448e6abf0eb9eef9d2a45b4172aafcb1eb2bb",
  entryHashScheme: "legacy",
  leafIndex: 581,
  treeSize: 582,
};

function tamperReceiptPath(bytes: Uint8Array): Uint8Array {
  const items = decode(bytes.subarray(1), {
    allowIndefinite: false,
    useMaps: true,
  }) as unknown[];
  const unprotected = items[1] as Map<number, unknown>;
  const vdp = unprotected.get(396) as Map<number, unknown>;
  const proofs = vdp.get(-1) as Uint8Array[];
  const proof = decode(proofs[0]!, { allowIndefinite: false }) as unknown[];
  const path = proof[2] as Uint8Array[];
  path[0]![0] = path[0]![0]! ^ 1;
  proofs[0] = encode(proof, rfc8949EncodeOptions);
  return Buffer.concat([
    Uint8Array.of(0xd2),
    encode(items, rfc8949EncodeOptions),
  ]);
}

describe("capsule-anchor receipt interoperability", () => {
  it("verifies the pinned real checkpoint and witness receipt", () => {
    expect(new ReceiptVerifier(authorityKey).verify(checkpoint, receipt)).toBe(
      true,
    );
  });

  it("rejects every authenticated binding when tampered", () => {
    const verifier = new ReceiptVerifier(authorityKey);
    expect(
      new ReceiptVerifier(Uint8Array.from(authorityKey, () => 0)).verify(
        checkpoint,
        receipt,
      ),
    ).toBe(false);
    const signature = Uint8Array.from(receipt.bytes);
    signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    expect(verifier.verify(checkpoint, { ...receipt, bytes: signature })).toBe(
      false,
    );
    expect(
      verifier.verify(checkpoint, {
        ...receipt,
        entryHash: `0${receipt.entryHash.slice(1)}`,
      }),
    ).toBe(false);
    expect(
      verifier.verify(checkpoint, {
        ...receipt,
        leafIndex: receipt.leafIndex - 1,
      }),
    ).toBe(false);
    expect(
      verifier.verify(checkpoint, {
        ...receipt,
        treeSize: receipt.treeSize + 1,
      }),
    ).toBe(false);
    expect(
      verifier.verify(checkpoint, {
        ...receipt,
        bytes: tamperReceiptPath(receipt.bytes),
      }),
    ).toBe(false);
  });
});
