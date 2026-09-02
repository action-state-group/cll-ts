import type { VerificationResult } from "capsule-emit-ts/aac";

export const limits = Object.freeze({
  capsule: 1 << 20,
  envelope: 4096,
  envelopes: 64,
  witnesses: 32,
  checkpointPayload: 64 << 10,
  receipt: 2 << 20,
  identifier: 191,
  reason: 4096,
  scanDefault: 100,
  scanMax: 1000,
});
export type AdmissionMode = "unsigned" | "signed";
export type Authenticity = AdmissionMode;
export type AppendOutcome = "inserted" | "idempotent";
export type AddOutcome = "inserted" | "idempotent";
export interface EnvelopeVerification {
  readonly ok: boolean;
  readonly findings: readonly {
    readonly code: string;
    readonly detail: string;
  }[];
  readonly publicKey?: Uint8Array;
}
export interface Envelope {
  readonly digest: string;
  readonly bytes: Uint8Array;
  readonly verification: EnvelopeVerification;
  readonly addedAt: Date;
}
export interface Record {
  readonly seq: bigint;
  readonly capsuleId: string;
  readonly capsule: Uint8Array;
  readonly authenticity: Authenticity;
  readonly envelopes: readonly Envelope[];
  readonly verification: VerificationResult;
  readonly parentId?: string;
  readonly appendedAt: Date;
}
export interface LogEntry {
  readonly seq: bigint;
  readonly capsuleId: string;
  readonly appendedAt: Date;
}
/** One dense, 1-based CLL entry with a 32-byte identity and valid append time. */
export interface CllEntry {
  readonly seq: bigint;
  readonly value: Uint8Array;
  readonly appendedAt: Date;
}
export interface ChainGap {
  readonly seq: bigint;
  readonly capsuleId: string;
  readonly parentId: string;
}
export interface AppendInput extends Omit<Record, "seq"> {}
export interface EnvelopeInput {
  readonly capsuleId: string;
  readonly envelope: Envelope;
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
/** Bounded application-neutral source consumed by checkpointing. */
export interface CllSource {
  scanEntries(after: bigint, limit: number): Promise<readonly CllEntry[]>;
}
/** Durable CLL state independent of an application's record API. */
export interface CllStore {
  loadCll(): Promise<CllState>;
  commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void>;
  pendingWitnesses(now: Date, limit: number): Promise<readonly WitnessState[]>;
  getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): Promise<WitnessState | undefined>;
  commitWitness(expectedAttempts: number, next: WitnessState): Promise<void>;
}
export interface CheckpointStore extends CllSource, CllStore {}

/** AAC ledger binding plus the generic CLL contracts. */
export interface Store extends CheckpointStore {
  append(
    input: AppendInput,
  ): Promise<{ readonly record: Record; readonly outcome: AppendOutcome }>;
  addEnvelope(
    input: EnvelopeInput,
  ): Promise<{ readonly envelope: Envelope; readonly outcome: AddOutcome }>;
  get(capsuleId: string): Promise<Record>;
  scan(after: bigint, limit: number): Promise<readonly Record[]>;
  scanIds(after: bigint, limit: number): Promise<readonly LogEntry[]>;
  findChainGaps(): Promise<readonly ChainGap[]>;
  close(): Promise<void>;
}

export class LedgerError extends Error {
  public constructor(
    public readonly code:
      | "not_found"
      | "invalid"
      | "immutable_conflict"
      | "corrupt"
      | "closed"
      | "contention"
      | "admission_rejected",
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "LedgerError";
  }
}

export function validateIdentifier(value: string): void {
  const length = Buffer.byteLength(value);
  if (
    length < 1 ||
    length > limits.identifier ||
    !/^[A-Za-z0-9._:/-]+$/u.test(value)
  )
    throw new LedgerError(
      "invalid",
      "identifier must be 1..191 UTF-8 bytes in the portable subset",
    );
}
