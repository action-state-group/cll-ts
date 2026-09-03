import type { KeyObject } from "node:crypto";

export const limits = Object.freeze({
  entryBytes: 32,
  witnesses: 32,
  checkpointPayload: 64 << 10,
  journalEvent: 4 << 20,
  receipt: 2 << 20,
  identifier: 191,
  reason: 4096,
  scanDefault: 100,
  scanMax: 1000,
});

export type AppendOutcome = "inserted" | "idempotent";

/** One dense, 1-based CLL entry with an opaque 32-byte value. */
export interface CllEntry {
  readonly seq: bigint;
  readonly value: Uint8Array;
  readonly appendedAt: Date;
}

export interface AppendInput {
  readonly value: Uint8Array;
  readonly appendedAt: Date;
}

export interface AppendResult {
  readonly entry: CllEntry;
  readonly outcome: AppendOutcome;
}

/** Structural signer contract accepted by checkpoint creation. */
export interface CheckpointSigningIdentity {
  readonly privateKey: KeyObject;
  readonly publicKey: Uint8Array;
}

export interface WitnessState {
  readonly witnessId: string;
  readonly checkpointSize: bigint;
  readonly checkpoint: Uint8Array;
  readonly attempts: number;
  readonly nextAttemptAt: Date;
  readonly receipt?: Uint8Array;
  readonly entryHash?: string;
  readonly entryHashScheme?: "legacy";
  readonly leafIndex?: number;
  readonly treeSize?: number;
  readonly permanent: boolean;
  readonly lastError?: string;
}

export interface CllState {
  readonly size: bigint;
  readonly nodes: readonly Uint8Array[];
  readonly indexedSeq: bigint;
  readonly firstPendingAt?: Date;
  readonly checkpoint?: Uint8Array;
  readonly checkpointSize?: bigint;
  readonly checkpointIndexedSeq?: bigint;
  readonly checkpointPeaks?: readonly Uint8Array[];
  readonly witnesses: readonly WitnessState[];
}

export interface EntrySource {
  scanEntries(afterSeq: bigint, limit: number): Promise<readonly CllEntry[]>;
}

export interface EntryStore extends EntrySource {
  append(input: AppendInput): Promise<AppendResult>;
  getEntry(value: Uint8Array): Promise<CllEntry>;
}

export interface CheckpointStateStore {
  loadCll(): Promise<CllState>;
  commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void>;
}

export interface WitnessStateStore {
  pendingWitnesses(now: Date, limit: number): Promise<readonly WitnessState[]>;
  getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): Promise<WitnessState | undefined>;
  commitWitness(expectedAttempts: number, next: WitnessState): Promise<void>;
}

export interface CheckpointStore
  extends EntrySource,
    CheckpointStateStore,
    WitnessStateStore {}

/** Complete generic persistence contract implemented by every backend. */
export interface CllBackend
  extends EntryStore,
    CheckpointStateStore,
    WitnessStateStore {
  close(): Promise<void>;
}

export type CllErrorCode =
  | "not_found"
  | "invalid"
  | "corrupt"
  | "closed"
  | "contention"
  | "rejected";

export class CllError extends Error {
  public constructor(
    public readonly code: CllErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CllError";
  }
}

export function validateIdentifier(value: string): void {
  const length = Buffer.byteLength(value);
  if (
    length < 1 ||
    length > limits.identifier ||
    !/^[A-Za-z0-9._:/-]+$/u.test(value)
  )
    throw new CllError(
      "invalid",
      "identifier must be 1..191 UTF-8 bytes in the portable subset",
    );
}
