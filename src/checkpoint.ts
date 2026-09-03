import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { canonicalJson } from "./canonical-json.js";
import {
  commitmentObject,
  leafCount,
  rootFromPeaks,
  verifyConsistency,
} from "./mmr.js";
import {
  CllError,
  limits,
  validateIdentifier,
  type CheckpointSigningIdentity,
} from "./types.js";

export const CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor";
export interface ConsistencyProof {
  readonly sizeA: bigint;
  readonly sizeB: bigint;
  readonly oldPeaks: readonly Uint8Array[];
  readonly witness: readonly (readonly Uint8Array[])[];
  readonly newPeaks: readonly Uint8Array[];
}
export interface CheckpointInput {
  readonly logId: string;
  readonly mmrSize: bigint;
  readonly peaks: readonly Uint8Array[];
  readonly previousSize: bigint;
  readonly previousPeaks: readonly Uint8Array[];
  readonly timestamp: Date | string;
  readonly identity: CheckpointSigningIdentity;
  readonly consistencyProof?: ConsistencyProof;
  readonly cadence?: number;
}
export interface SignedCheckpoint {
  readonly json: Uint8Array;
  readonly cose: Uint8Array;
  readonly digest: string;
  readonly logId: string;
  readonly mmrSize: bigint;
  readonly root: string;
  readonly previousSize: bigint;
  readonly previousRoot: string;
  readonly keyId: string;
  readonly timestamp: string;
}
export interface CheckpointProjectionInput {
  readonly logId: string;
  readonly mmrSize: bigint | number;
  readonly peaks: readonly Uint8Array[];
  readonly previousSize: bigint | number;
  readonly previousPeaks: readonly Uint8Array[];
  readonly keyId: string;
  readonly timestamp: string;
}

const ed25519Pkcs8Prefix = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/** Create an Ed25519 checkpoint signer from a 32-byte seed. */
export function createCheckpointIdentity(
  seed: Uint8Array,
): CheckpointSigningIdentity {
  if (seed.length !== 32) throw new TypeError("Ed25519 seed must be 32 bytes");
  const privateKey = createPrivateKey({
    key: Buffer.concat([ed25519Pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
  const der = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  return Object.freeze({
    privateKey,
    publicKey: Uint8Array.from(der.subarray(der.length - 32)),
  });
}

const encodeCanonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);
const taggedSign1 = (items: unknown[]): Uint8Array =>
  Buffer.concat([Uint8Array.of(0xd2), encodeCanonical(items)]);
const formatTime = (value: Date | string): string => {
  if (value instanceof Date) {
    if (Number.isNaN(value.valueOf()))
      throw new CllError("invalid", "invalid checkpoint timestamp");
    return value
      .toISOString()
      .replace(/\.000Z$/u, "Z")
      .replace(/(\.\d*?[1-9])0+Z$/u, "$1Z");
  }
  const match =
    /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/u.exec(
      value,
    );
  if (match === null)
    throw new CllError("invalid", "invalid checkpoint timestamp");
  const fraction = (match[2] ?? "").padEnd(9, "0");
  const parsed = new Date(`${match[1]}.${fraction.slice(0, 3)}${match[3]}`);
  if (Number.isNaN(parsed.valueOf()))
    throw new CllError("invalid", "invalid checkpoint timestamp");
  const trimmed = fraction.replace(/0+$/u, "");
  return `${parsed.toISOString().slice(0, 19)}${trimmed === "" ? "" : `.${trimmed}`}Z`;
};
const commitment = (peaks: readonly Uint8Array[]): Uint8Array => {
  try {
    return commitmentObject(peaks);
  } catch {
    throw new CllError("invalid", "checkpoint peak must be 32 bytes");
  }
};
const proofWire = (proof: ConsistencyProof) => ({
  size_a: Number(proof.sizeA),
  size_b: Number(proof.sizeB),
  old_peaks: proof.oldPeaks,
  witness: proof.witness,
  new_peaks: proof.newPeaks,
});

/** Canonical JSON projection whose double hash is the legacy witness entry. */
export function checkpointProjection(input: CheckpointProjectionInput) {
  const previousSize = BigInt(input.previousSize);
  return {
    v: 1,
    kind: "mmr_checkpoint",
    log_id: input.logId,
    mmr_size: Number(input.mmrSize),
    root: Buffer.from(rootFromPeaks(input.peaks)).toString("hex"),
    prev_size: Number(previousSize),
    prev_root:
      previousSize === 0n
        ? ""
        : Buffer.from(rootFromPeaks(input.previousPeaks)).toString("hex"),
    key_id: input.keyId,
    timestamp: input.timestamp,
  };
}

export function signCheckpoint(input: CheckpointInput): SignedCheckpoint {
  validateIdentifier(input.logId);
  if (
    input.cadence !== undefined &&
    (!Number.isSafeInteger(input.cadence) || input.cadence < 1)
  )
    throw new CllError(
      "invalid",
      "checkpoint cadence must be a positive portable integer",
    );
  if (
    input.mmrSize <= 0n ||
    input.mmrSize > BigInt(Number.MAX_SAFE_INTEGER) ||
    input.previousSize < 0n ||
    input.previousSize >= input.mmrSize
  )
    throw new CllError("invalid", "invalid checkpoint sizes");
  if (input.identity.publicKey.length !== 32)
    throw new CllError("invalid", "invalid checkpoint identity");
  if (input.previousSize === 0n && input.consistencyProof !== undefined)
    throw new CllError(
      "invalid",
      "first checkpoint must not carry consistency proof",
    );
  if (
    input.previousSize > 0n &&
    (input.consistencyProof === undefined ||
      input.consistencyProof.sizeA !== input.previousSize ||
      input.consistencyProof.sizeB !== input.mmrSize)
  )
    throw new CllError(
      "invalid",
      "non-first checkpoint requires matching consistency proof",
    );
  const root = Buffer.from(rootFromPeaks(input.peaks)).toString("hex");
  const previousRoot = Buffer.from(rootFromPeaks(input.previousPeaks)).toString(
    "hex",
  );
  const timestamp = formatTime(input.timestamp);
  const keyId = Buffer.from(input.identity.publicKey).toString("hex");
  const projection = checkpointProjection({
    logId: input.logId,
    mmrSize: input.mmrSize,
    peaks: input.peaks,
    previousSize: input.previousSize,
    previousPeaks: input.previousPeaks,
    keyId,
    timestamp,
  });
  const json = canonicalJson(projection);
  const digest = createHash("sha256").update(json).digest("hex");
  const claims: Record<string, unknown> = {
    kind: "cll-checkpoint",
    log_size: Number(input.mmrSize),
    commitment: commitment(input.peaks),
    prev_size: Number(input.previousSize),
    prev_commitment:
      input.previousSize === 0n
        ? new Uint8Array()
        : commitment(input.previousPeaks),
    issued_at: timestamp,
  };
  if (input.cadence !== undefined) claims.cadence = input.cadence;
  if (input.consistencyProof !== undefined)
    claims.consistency_proof = proofWire(input.consistencyProof);
  const payload = encodeCanonical(claims);
  const protectedBytes = encodeCanonical(
    new Map<unknown, unknown>([
      [1, -8],
      [3, CHECKPOINT_CONTENT_TYPE],
      [4, input.identity.publicKey],
      [
        15,
        new Map([
          [1, input.logId],
          [2, `${input.logId}#${input.mmrSize}`],
        ]),
      ],
    ]),
  );
  const sigStructure = encodeCanonical([
    "Signature1",
    protectedBytes,
    new Uint8Array(),
    payload,
  ]);
  const signature = edSign(null, sigStructure, input.identity.privateKey);
  const cose = taggedSign1([protectedBytes, new Map(), payload, signature]);
  if (cose.length > limits.checkpointPayload)
    throw new CllError("invalid", "signed checkpoint is too large");
  return {
    json,
    cose,
    digest,
    logId: input.logId,
    mmrSize: input.mmrSize,
    root,
    previousSize: input.previousSize,
    previousRoot: input.previousSize === 0n ? "" : previousRoot,
    keyId,
    timestamp,
  };
}

export function verifyCheckpoint(cose: Uint8Array): boolean {
  try {
    if (
      cose.length < 2 ||
      cose.length > limits.checkpointPayload ||
      cose[0] !== 0xd2
    )
      return false;
    const items = decode(cose.subarray(1), {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
      useMaps: true,
    }) as unknown[];
    if (
      !Array.isArray(items) ||
      items.length !== 4 ||
      !(items[0] instanceof Uint8Array) ||
      !(items[1] instanceof Map) ||
      items[1].size !== 0 ||
      !(items[2] instanceof Uint8Array) ||
      !(items[3] instanceof Uint8Array)
    )
      return false;
    const headers = decode(items[0], {
      allowIndefinite: false,
      useMaps: true,
    }) as unknown;
    if (!(headers instanceof Map)) return false;
    const kid = headers.get(4);
    const cwt = headers.get(15);
    if (
      headers.size !== 4 ||
      headers.get(1) !== -8 ||
      headers.get(3) !== CHECKPOINT_CONTENT_TYPE ||
      !(kid instanceof Uint8Array) ||
      kid.length !== 32 ||
      !(cwt instanceof Map) ||
      cwt.size !== 2
    )
      return false;
    const logId = cwt.get(1);
    const subject = cwt.get(2);
    if (typeof logId !== "string" || typeof subject !== "string") return false;
    validateIdentifier(logId);

    const claims = decode(items[2], {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
      useMaps: true,
    }) as unknown;
    if (
      !(claims instanceof Map) ||
      !Buffer.from(encodeCanonical(claims)).equals(Buffer.from(items[2]))
    )
      return false;
    const allowedClaims = new Set([
      "kind",
      "log_size",
      "commitment",
      "prev_size",
      "prev_commitment",
      "issued_at",
      "cadence",
      "consistency_proof",
    ]);
    if (
      claims.size < 6 ||
      claims.size > 8 ||
      [...claims.keys()].some(
        (key) => typeof key !== "string" || !allowedClaims.has(key),
      ) ||
      claims.get("kind") !== "cll-checkpoint"
    )
      return false;
    const logSize = claims.get("log_size");
    const previousSize = claims.get("prev_size");
    const issuedAt = claims.get("issued_at");
    if (
      !Number.isSafeInteger(logSize) ||
      (logSize as number) < 1 ||
      !Number.isSafeInteger(previousSize) ||
      (previousSize as number) < 0 ||
      (previousSize as number) >= (logSize as number) ||
      typeof issuedAt !== "string" ||
      formatTime(issuedAt) !== issuedAt ||
      subject !== `${logId}#${logSize as number}`
    )
      return false;
    const decodePeaks = (value: unknown): Uint8Array[] | undefined => {
      if (!(value instanceof Uint8Array)) return undefined;
      const decoded = decode(value, {
        allowIndefinite: false,
        coerceUndefinedToNull: false,
      }) as unknown;
      if (
        !Array.isArray(decoded) ||
        decoded.some(
          (peak) => !(peak instanceof Uint8Array) || peak.length !== 32,
        ) ||
        !Buffer.from(encodeCanonical(decoded)).equals(Buffer.from(value))
      )
        return undefined;
      return decoded as Uint8Array[];
    };
    const peaks = decodePeaks(claims.get("commitment"));
    if (peaks === undefined) return false;
    const leaves = leafCount(BigInt(logSize as number));
    if (leaves === undefined) return false;
    let peakCount = 0;
    for (let value = leaves; value !== 0n; value >>= 1n)
      peakCount += Number(value & 1n);
    if (peaks.length !== peakCount) return false;

    const previousCommitment = claims.get("prev_commitment");
    if (!(previousCommitment instanceof Uint8Array)) return false;
    if ((previousSize as number) === 0) {
      if (previousCommitment.length !== 0 || claims.has("consistency_proof"))
        return false;
    } else {
      const previousPeaks = decodePeaks(previousCommitment);
      const proof = claims.get("consistency_proof");
      if (previousPeaks === undefined || !(proof instanceof Map)) return false;
      const sizeA = proof.get("size_a");
      const sizeB = proof.get("size_b");
      const oldPeaks = proof.get("old_peaks");
      const witness = proof.get("witness");
      const newPeaks = proof.get("new_peaks");
      if (
        proof.size !== 5 ||
        sizeA !== previousSize ||
        sizeB !== logSize ||
        !Array.isArray(oldPeaks) ||
        !Array.isArray(newPeaks) ||
        !Array.isArray(witness) ||
        oldPeaks.some(
          (peak) => !(peak instanceof Uint8Array) || peak.length !== 32,
        ) ||
        newPeaks.some(
          (peak) => !(peak instanceof Uint8Array) || peak.length !== 32,
        ) ||
        witness.some(
          (path) =>
            !Array.isArray(path) ||
            path.some(
              (hash) => !(hash instanceof Uint8Array) || hash.length !== 32,
            ),
        ) ||
        !Buffer.from(encodeCanonical(oldPeaks)).equals(
          Buffer.from(encodeCanonical(previousPeaks)),
        ) ||
        !Buffer.from(encodeCanonical(newPeaks)).equals(
          Buffer.from(encodeCanonical(peaks)),
        ) ||
        !verifyConsistency(rootFromPeaks(previousPeaks), rootFromPeaks(peaks), {
          oldSize: BigInt(previousSize as number),
          newSize: BigInt(logSize as number),
          oldPeaks: oldPeaks as Uint8Array[],
          witness: witness as Uint8Array[][],
          newPeaks: newPeaks as Uint8Array[],
        })
      )
        return false;
    }
    if (claims.has("cadence")) {
      const cadence = claims.get("cadence");
      if (!Number.isSafeInteger(cadence) || (cadence as number) < 1)
        return false;
    }
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), kid]),
      format: "der",
      type: "spki",
    });
    return edVerify(
      null,
      encodeCanonical(["Signature1", items[0], new Uint8Array(), items[2]]),
      key,
      items[3],
    );
  } catch {
    return false;
  }
}

export interface CheckpointMetadata {
  readonly logId: string;
  readonly size: bigint;
  readonly peaks: readonly Uint8Array[];
  readonly previousSize: bigint;
  readonly previousPeaks: readonly Uint8Array[];
  readonly root: string;
  readonly previousRoot: string;
  readonly keyId: string;
  readonly timestamp: string;
  readonly cadence?: number;
}

/** Return linkage metadata only after the complete checkpoint validates. */
export function checkpointMetadata(
  cose: Uint8Array,
): CheckpointMetadata | undefined {
  if (!verifyCheckpoint(cose)) return undefined;
  const items = decode(cose.subarray(1), {
    allowIndefinite: false,
    coerceUndefinedToNull: false,
    useMaps: true,
  }) as unknown[];
  const headers = decode(items[0] as Uint8Array, {
    allowIndefinite: false,
    useMaps: true,
  }) as Map<number, unknown>;
  const claims = decode(items[2] as Uint8Array, {
    allowIndefinite: false,
    coerceUndefinedToNull: false,
    useMaps: true,
  }) as Map<string, unknown>;
  const decodeCommittedPeaks = (value: Uint8Array): Uint8Array[] =>
    decode(value, {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
    }) as Uint8Array[];
  const cwt = headers.get(15) as Map<number, unknown>;
  const previousSize = BigInt(claims.get("prev_size") as number);
  const previousCommitment = claims.get("prev_commitment") as Uint8Array;
  const peaks = decodeCommittedPeaks(claims.get("commitment") as Uint8Array);
  const previousPeaks =
    previousSize === 0n ? [] : decodeCommittedPeaks(previousCommitment);
  return {
    logId: cwt.get(1) as string,
    size: BigInt(claims.get("log_size") as number),
    peaks,
    previousSize,
    previousPeaks,
    root: Buffer.from(rootFromPeaks(peaks)).toString("hex"),
    previousRoot:
      previousSize === 0n
        ? ""
        : Buffer.from(rootFromPeaks(previousPeaks)).toString("hex"),
    keyId: Buffer.from(headers.get(4) as Uint8Array).toString("hex"),
    timestamp: claims.get("issued_at") as string,
    ...(claims.has("cadence")
      ? { cadence: claims.get("cadence") as number }
      : {}),
  };
}

/** Return the RFC 9162 checkpoint entry hash after full checkpoint validation. */
export function checkpointEntryHash(cose: Uint8Array): Uint8Array | undefined {
  const metadata = checkpointMetadata(cose);
  if (metadata === undefined) return undefined;
  const projection = checkpointProjection({
    logId: metadata.logId,
    mmrSize: metadata.size,
    peaks: metadata.peaks,
    previousSize: metadata.previousSize,
    previousPeaks: metadata.previousPeaks,
    keyId: metadata.keyId,
    timestamp: metadata.timestamp,
  });
  return createHash("sha256")
    .update(createHash("sha256").update(canonicalJson(projection)).digest())
    .digest();
}
