import type { SigningIdentity } from "capsule-emit-ts";
import {
  checkpointMetadata,
  signCheckpoint,
  type ConsistencyProof,
  type SignedCheckpoint,
} from "./checkpoint.js";
import { leafCount, MmrTree } from "./mmr.js";
import { waitForInterval } from "./run-loop.js";
import {
  LedgerError,
  limits,
  validateIdentifier,
  type CllState,
  type Store,
  type WitnessState,
} from "./types.js";

export interface CheckpointRunnerOptions {
  readonly logId: string;
  readonly identity: SigningIdentity;
  readonly witnessIds?: readonly string[];
  readonly entryCadence?: number;
  readonly ageCadenceMs?: number;
  readonly pollIntervalMs?: number;
  readonly clock?: () => Date;
}
export class CheckpointRunner {
  private readonly witnessIds: readonly string[];
  private readonly entryCadence: number;
  private readonly ageCadenceMs: number;
  private readonly pollIntervalMs: number;
  private readonly clock: () => Date;
  private tail: Promise<void> = Promise.resolve();
  private running = false;
  public constructor(
    private readonly store: Store,
    private readonly options: CheckpointRunnerOptions,
  ) {
    validateIdentifier(options.logId);
    this.witnessIds = [...(options.witnessIds ?? [])];
    if (this.witnessIds.length > limits.witnesses)
      throw new TypeError("too many witnesses");
    this.witnessIds.forEach(validateIdentifier);
    this.entryCadence = options.entryCadence ?? 100;
    this.ageCadenceMs = options.ageCadenceMs ?? 15 * 60_000;
    this.pollIntervalMs = options.pollIntervalMs ?? 60_000;
    if (
      !Number.isSafeInteger(this.entryCadence) ||
      this.entryCadence < 1 ||
      !Number.isSafeInteger(this.ageCadenceMs) ||
      this.ageCadenceMs < 1 ||
      !Number.isSafeInteger(this.pollIntervalMs) ||
      this.pollIntervalMs < 1
    )
      throw new TypeError(
        "runner cadence and poll interval must be positive integers",
      );
    this.clock = options.clock ?? (() => new Date());
  }

  /** Run the host-controlled polling lifecycle until its signal is aborted. */
  public async run(signal: AbortSignal): Promise<void> {
    if (this.running)
      throw new LedgerError("invalid", "checkpoint runner is already running");
    if (signal.aborted) return;
    this.running = true;
    try {
      while (!signal.aborted) {
        try {
          await this.runOnce();
        } catch (error) {
          if (!(error instanceof LedgerError) || error.code !== "contention")
            throw error;
        }
        await waitForInterval(signal, this.pollIntervalMs);
      }
    } finally {
      this.running = false;
    }
  }
  public async runOnce(): Promise<SignedCheckpoint | undefined> {
    const prior = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await this.runOnceLocked();
    } finally {
      release();
    }
  }
  private async runOnceLocked(): Promise<SignedCheckpoint | undefined> {
    const now = this.clock();
    const current = await this.store.loadCll();
    if (
      current.size !== BigInt(current.nodes.length) ||
      leafCount(current.size) !== current.indexedSeq
    )
      throw new LedgerError("corrupt", "stored CLL size/index is inconsistent");
    let tree: MmrTree;
    try {
      tree = new MmrTree(current.nodes);
    } catch (error) {
      throw new LedgerError("corrupt", "stored CLL nodes are invalid", {
        cause: error,
      });
    }
    const checkpointFields = [
      current.checkpoint,
      current.checkpointSize,
      current.checkpointIndexedSeq,
      current.checkpointPeaks,
    ];
    const checkpointFieldCount = checkpointFields.filter(
      (value) => value !== undefined,
    ).length;
    if (checkpointFieldCount !== 0 && checkpointFieldCount !== 4)
      throw new LedgerError("corrupt", "stored checkpoint state is incomplete");
    if (
      current.checkpoint !== undefined &&
      current.checkpointSize !== undefined &&
      current.checkpointIndexedSeq !== undefined &&
      current.checkpointPeaks !== undefined
    ) {
      const metadata = checkpointMetadata(current.checkpoint);
      if (
        current.checkpointSize > current.size ||
        leafCount(current.checkpointSize) !== current.checkpointIndexedSeq
      )
        throw new LedgerError(
          "corrupt",
          "stored checkpoint does not match durable CLL state",
        );
      let expectedPeaks: readonly Uint8Array[];
      try {
        expectedPeaks = tree.peakHashesAt(current.checkpointSize);
      } catch (error) {
        throw new LedgerError("corrupt", "stored checkpoint size is invalid", {
          cause: error,
        });
      }
      const samePeaks = (
        left: readonly Uint8Array[],
        right: readonly Uint8Array[],
      ): boolean =>
        left.length === right.length &&
        left.every((value, index) =>
          Buffer.from(value).equals(Buffer.from(right[index]!)),
        );
      if (
        metadata === undefined ||
        metadata.logId !== this.options.logId ||
        metadata.size !== current.checkpointSize ||
        !samePeaks(metadata.peaks, current.checkpointPeaks) ||
        !samePeaks(expectedPeaks, current.checkpointPeaks)
      )
        throw new LedgerError(
          "corrupt",
          "stored checkpoint does not match durable CLL state",
        );
    }
    let cursor = current.indexedSeq;
    let firstPendingAt = current.firstPendingAt;
    while (true) {
      const entries = await this.store.scanIds(cursor, limits.scanMax);
      if (entries.length === 0) break;
      for (const entry of entries) {
        if (entry.seq !== cursor + 1n)
          throw new LedgerError("corrupt", "ledger sequence is not contiguous");
        tree.appendCapsuleId(entry.capsuleId);
        cursor = entry.seq;
        firstPendingAt ??= entry.appendedAt;
      }
      if (entries.length < limits.scanMax) break;
    }
    const checkpointIndexedSeq = current.checkpointIndexedSeq ?? 0n;
    const pendingEntries = cursor - checkpointIndexedSeq;
    const due =
      pendingEntries > 0n &&
      (pendingEntries >= BigInt(this.entryCadence) ||
        (firstPendingAt !== undefined &&
          now.valueOf() - firstPendingAt.valueOf() >= this.ageCadenceMs));
    let signed: SignedCheckpoint | undefined;
    let next: CllState = {
      ...current,
      size: tree.size,
      nodes: tree.nodes(),
      indexedSeq: cursor,
      ...(firstPendingAt === undefined ? {} : { firstPendingAt }),
    };
    if (due) {
      const previousSize = current.checkpointSize ?? 0n;
      const previousPeaks = current.checkpointPeaks ?? [];
      let consistencyProof: ConsistencyProof | undefined;
      if (previousSize > 0n) {
        const proof = tree.consistencyProof(previousSize);
        consistencyProof = {
          sizeA: proof.oldSize,
          sizeB: proof.newSize,
          oldPeaks: proof.oldPeaks,
          witness: proof.witness,
          newPeaks: proof.newPeaks,
        };
      }
      signed = signCheckpoint({
        logId: this.options.logId,
        mmrSize: tree.size,
        peaks: tree.peakHashes(),
        previousSize,
        previousPeaks,
        timestamp: now,
        identity: this.options.identity,
        ...(consistencyProof === undefined ? {} : { consistencyProof }),
      });
      const pending: WitnessState[] = this.witnessIds.map((witnessId) => ({
        witnessId,
        checkpointSize: tree.size,
        checkpoint: signed!.cose,
        attempts: 0,
        nextAttemptAt: now,
        permanent: false,
      }));
      const { firstPendingAt: _cleared, ...withoutPendingAge } = next;
      next = {
        ...withoutPendingAge,
        checkpoint: signed.cose,
        checkpointSize: tree.size,
        checkpointIndexedSeq: cursor,
        checkpointPeaks: tree.peakHashes(),
        witnesses: [...current.witnesses, ...pending],
      };
    }
    if (cursor !== current.indexedSeq || signed !== undefined)
      await this.store.commitCll(current.size, current.checkpoint, next);
    return signed;
  }
}
