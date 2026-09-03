import { sign as edSign } from "node:crypto";

import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { describe, expect, it } from "vitest";
import {
  createCheckpointIdentity,
  MmrTree,
  signCheckpoint,
  verifyCheckpoint,
  type SignedCheckpoint,
} from "../src/index.js";

const identity = createCheckpointIdentity(new Uint8Array(32));
const canonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);
const firstTree = (): MmrTree => {
  const tree = new MmrTree();
  tree.append(Buffer.from("11".repeat(32), "hex"));
  return tree;
};
const firstCheckpoint = (timestamp = "2026-09-01T12:34:56Z") => {
  const tree = firstTree();
  return signCheckpoint({
    logId: "negative-test",
    mmrSize: tree.size,
    peaks: tree.peakHashes(),
    previousSize: 0n,
    previousPeaks: [],
    timestamp,
    identity,
  });
};

function authenticatedMutation(
  checkpoint: SignedCheckpoint,
  mutate: (headers: Map<number, unknown>, claims: Map<string, unknown>) => void,
): Uint8Array {
  const items = decode(checkpoint.cose.subarray(1), {
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
  mutate(headers, claims);
  const protectedBytes = canonical(headers);
  const payload = canonical(claims);
  const signature = edSign(
    null,
    canonical(["Signature1", protectedBytes, new Uint8Array(), payload]),
    identity.privateKey,
  );
  return Buffer.concat([
    Uint8Array.of(0xd2),
    canonical([protectedBytes, new Map(), payload, signature]),
  ]);
}

describe("checkpoint verifier negative boundaries", () => {
  it("rejects an indefinite-length non-canonical COSE array", () => {
    const checkpoint = firstCheckpoint();
    const items = decode(checkpoint.cose.subarray(1), {
      allowIndefinite: false,
      useMaps: true,
    }) as unknown[];
    const indefinite = Buffer.concat([
      Uint8Array.of(0xd2, 0x9f),
      ...items.map((item) => canonical(item)),
      Uint8Array.of(0xff),
    ]);
    expect(verifyCheckpoint(indefinite)).toBe(false);
  });

  it("rejects authenticated protected-header and CWT errors", () => {
    const checkpoint = firstCheckpoint();
    expect(
      verifyCheckpoint(
        authenticatedMutation(checkpoint, (headers) => {
          headers.set(3, "application/not-a-checkpoint");
        }),
      ),
    ).toBe(false);
    expect(
      verifyCheckpoint(
        authenticatedMutation(checkpoint, (headers) => {
          (headers.get(15) as Map<number, unknown>).set(2, "wrong#1");
        }),
      ),
    ).toBe(false);
  });

  it("rejects an authenticated commitment inconsistent with log size", () => {
    const checkpoint = firstCheckpoint();
    expect(
      verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          claims.set("commitment", canonical([]));
        }),
      ),
    ).toBe(false);
  });

  it("rejects an authenticated invalid consistency proof", () => {
    const tree = firstTree();
    const previousPeaks = tree.peakHashes();
    tree.append(Buffer.from("22".repeat(32), "hex"));
    const proof = tree.consistencyProof(1n);
    const checkpoint = signCheckpoint({
      logId: "negative-test",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 1n,
      previousPeaks,
      timestamp: "2026-09-01T12:34:56Z",
      identity,
      consistencyProof: {
        sizeA: proof.oldSize,
        sizeB: proof.newSize,
        oldPeaks: proof.oldPeaks,
        witness: proof.witness,
        newPeaks: proof.newPeaks,
      },
    });
    expect(verifyCheckpoint(checkpoint.cose)).toBe(true);
    expect(
      verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          const consistency = claims.get("consistency_proof") as Map<
            string,
            unknown
          >;
          consistency.set("size_a", 2);
        }),
      ),
    ).toBe(false);
  });

  it("preserves and verifies microsecond timestamps", () => {
    const checkpoint = firstCheckpoint("2026-09-01T12:34:56.123456Z");
    expect(checkpoint.timestamp).toBe("2026-09-01T12:34:56.123456Z");
    expect(verifyCheckpoint(checkpoint.cose)).toBe(true);
  });

  it("renders checkpoint fractions with Go RFC3339Nano trimming", () => {
    const checkpoint = firstCheckpoint("2026-09-01T12:34:56.836000Z");
    expect(checkpoint.timestamp).toBe("2026-09-01T12:34:56.836Z");
    expect(Buffer.from(checkpoint.json).toString()).toContain(
      '"timestamp":"2026-09-01T12:34:56.836Z"',
    );
    expect(verifyCheckpoint(checkpoint.cose)).toBe(true);
  });
});
