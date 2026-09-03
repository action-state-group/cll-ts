import { cloneCll, cloneEntry, cloneWitness } from "./clone.js";
import {
  CllError,
  limits,
  type AppendInput,
  type AppendResult,
  type CllEntry,
  type CllState,
  type WitnessState,
} from "./types.js";

const same = (left: Uint8Array, right: Uint8Array): boolean =>
  Buffer.from(left).equals(Buffer.from(right));

const sameList = (
  left: readonly Uint8Array[],
  right: readonly Uint8Array[],
): boolean =>
  left.length === right.length &&
  left.every((value, index) => same(value, right[index]!));

export const witnessKey = (
  value: Pick<WitnessState, "witnessId" | "checkpointSize">,
): string => `${value.witnessId}\0${value.checkpointSize}`;

export const addedWitnesses = (
  before: readonly WitnessState[],
  after: readonly WitnessState[],
): readonly WitnessState[] => {
  const existing = new Set(before.map(witnessKey));
  return after.filter((item) => !existing.has(witnessKey(item)));
};

/** Shared invariant engine. Durable backends compose it and persist every mutation. */
export class BackendState {
  private entries_: CllEntry[] = [];
  private byValue = new Map<string, CllEntry>();
  private cll_: CllState = {
    size: 0n,
    nodes: [],
    indexedSeq: 0n,
    witnesses: [],
  };

  public entries(): readonly CllEntry[] {
    return this.entries_.map(cloneEntry);
  }

  public cll(): CllState {
    return cloneCll(this.cll_);
  }

  /**
   * Roll back an append or CLL/witness commit when external persistence fails.
   * This remains O(1) because entries only append and each CLL mutation replaces
   * `cll_`; mutation methods must preserve those invariants.
   */
  public async persistMutation<T>(
    operation: () => T,
    persist: (result: T) => Promise<void>,
  ): Promise<T> {
    const entryCount = this.entries_.length;
    const cll = this.cll_;
    try {
      const result = operation();
      await persist(result);
      return result;
    } catch (error) {
      while (this.entries_.length > entryCount) {
        const removed = this.entries_.pop()!;
        this.byValue.delete(Buffer.from(removed.value).toString("hex"));
      }
      this.cll_ = cll;
      throw error;
    }
  }

  public replace(entries: readonly CllEntry[], cll: CllState): void {
    if (
      entries.some(
        (entry, index) =>
          entry.seq !== BigInt(index + 1) ||
          entry.value.length !== limits.entryBytes,
      )
    )
      throw new CllError("corrupt", "stored CLL entries are not contiguous");
    const keys = entries.map((entry) =>
      Buffer.from(entry.value).toString("hex"),
    );
    if (new Set(keys).size !== keys.length)
      throw new CllError("corrupt", "stored CLL entries contain duplicates");
    this.entries_ = entries.map(cloneEntry);
    this.byValue = new Map(
      this.entries_.map((entry) => [
        Buffer.from(entry.value).toString("hex"),
        entry,
      ]),
    );
    this.cll_ = cloneCll(cll);
  }

  public append(input: AppendInput): AppendResult {
    if (
      input.value.length !== limits.entryBytes ||
      !Number.isFinite(input.appendedAt.valueOf())
    )
      throw new CllError(
        "invalid",
        "entry must have 32 bytes and a valid append time",
      );
    const key = Buffer.from(input.value).toString("hex");
    const existing = this.byValue.get(key);
    if (existing !== undefined)
      return { entry: cloneEntry(existing), outcome: "idempotent" };
    const entry: CllEntry = {
      seq: BigInt(this.entries_.length + 1),
      value: Uint8Array.from(input.value),
      appendedAt: new Date(Math.trunc(input.appendedAt.valueOf())),
    };
    this.entries_.push(entry);
    this.byValue.set(key, entry);
    return { entry: cloneEntry(entry), outcome: "inserted" };
  }

  public getEntry(value: Uint8Array): CllEntry {
    if (value.length !== limits.entryBytes)
      throw new CllError("invalid", "entry value must be 32 bytes");
    const entry = this.byValue.get(Buffer.from(value).toString("hex"));
    if (entry === undefined) throw new CllError("not_found", "entry not found");
    return cloneEntry(entry);
  }

  public scanEntries(afterSeq: bigint, limit: number): readonly CllEntry[] {
    if (afterSeq < 0n || limit < 1 || limit > limits.scanMax)
      throw new CllError("invalid", "invalid entry scan");
    const start =
      afterSeq >= BigInt(this.entries_.length)
        ? this.entries_.length
        : Number(afterSeq);
    return this.entries_.slice(start, start + limit).map(cloneEntry);
  }

  public commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): void {
    if (this.cll_.size !== expectedSize)
      throw new CllError("contention", "CLL state changed");
    if (
      (expectedCheckpoint === undefined) !==
        (this.cll_.checkpoint === undefined) ||
      (expectedCheckpoint !== undefined &&
        this.cll_.checkpoint !== undefined &&
        !same(expectedCheckpoint, this.cll_.checkpoint))
    )
      throw new CllError("contention", "CLL checkpoint changed");
    const checkpointFields = [
      next.checkpoint,
      next.checkpointSize,
      next.checkpointIndexedSeq,
      next.checkpointPeaks,
    ];
    const presentCheckpointFields = checkpointFields.filter(
      (value) => value !== undefined,
    ).length;
    if (presentCheckpointFields !== 0 && presentCheckpointFields !== 4)
      throw new CllError("invalid", "checkpoint state is incomplete");
    if (this.cll_.checkpoint !== undefined && next.checkpoint === undefined)
      throw new CllError("contention", "checkpoint state cannot be removed");
    if (
      next.checkpointSize !== undefined &&
      (next.checkpointSize <= 0n ||
        next.checkpointSize > next.size ||
        next.checkpointIndexedSeq! > next.indexedSeq)
    )
      throw new CllError("invalid", "checkpoint state exceeds CLL state");
    if (
      this.cll_.checkpointSize !== undefined &&
      next.checkpointSize !== undefined &&
      next.checkpointSize < this.cll_.checkpointSize
    )
      throw new CllError("contention", "checkpoint size cannot move backward");
    if (
      this.cll_.checkpointIndexedSeq !== undefined &&
      next.checkpointIndexedSeq !== undefined &&
      next.checkpointIndexedSeq < this.cll_.checkpointIndexedSeq
    )
      throw new CllError(
        "contention",
        "checkpoint indexed sequence cannot move backward",
      );
    if (
      this.cll_.checkpointSize !== undefined &&
      this.cll_.checkpointIndexedSeq !== undefined &&
      this.cll_.checkpointPeaks !== undefined &&
      next.checkpointSize === this.cll_.checkpointSize &&
      (next.checkpointIndexedSeq !== this.cll_.checkpointIndexedSeq ||
        !sameList(next.checkpointPeaks!, this.cll_.checkpointPeaks))
    )
      throw new CllError(
        "contention",
        "checkpoint metadata already exists at this CLL size",
      );
    if (
      this.cll_.checkpoint !== undefined &&
      this.cll_.checkpointSize !== undefined &&
      next.checkpoint !== undefined &&
      next.checkpointSize === this.cll_.checkpointSize &&
      !same(next.checkpoint, this.cll_.checkpoint)
    )
      throw new CllError(
        "contention",
        "checkpoint already exists at this CLL size",
      );
    if (
      next.size !== BigInt(next.nodes.length) ||
      next.size < this.cll_.size ||
      next.indexedSeq < this.cll_.indexedSeq ||
      this.cll_.nodes.some(
        (node, index) => !same(node, next.nodes[index] ?? new Uint8Array()),
      ) ||
      next.nodes.some((node) => node.length !== 32)
    )
      throw new CllError("invalid", "invalid append-only CLL state");
    const existing = new Map(
      this.cll_.witnesses.map((item) => [witnessKey(item), item]),
    );
    for (const witness of next.witnesses) {
      const current = existing.get(witnessKey(witness));
      if (
        current !== undefined &&
        !same(current.checkpoint, witness.checkpoint)
      )
        throw new CllError(
          "contention",
          "witness delivery already exists for another checkpoint",
        );
    }
    this.cll_ = cloneCll({
      ...next,
      witnesses: [
        ...this.cll_.witnesses,
        ...next.witnesses.filter((item) => !existing.has(witnessKey(item))),
      ],
    });
  }

  public pendingWitnesses(now: Date, limit: number): readonly WitnessState[] {
    if (
      !Number.isFinite(now.valueOf()) ||
      limit < 1 ||
      limit > limits.witnesses
    )
      throw new CllError("invalid", "invalid pending witness query");
    return this.cll_.witnesses
      .filter(
        (item) =>
          item.receipt === undefined &&
          !item.permanent &&
          item.nextAttemptAt <= now,
      )
      .sort((a, b) => Number(a.checkpointSize - b.checkpointSize))
      .slice(0, limit)
      .map(cloneWitness);
  }

  public getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): WitnessState | undefined {
    const value = this.cll_.witnesses.find(
      (item) => witnessKey(item) === witnessKey({ witnessId, checkpointSize }),
    );
    return value === undefined ? undefined : cloneWitness(value);
  }

  public commitWitness(expectedAttempts: number, next: WitnessState): void {
    const index = this.cll_.witnesses.findIndex(
      (item) => witnessKey(item) === witnessKey(next),
    );
    if (index < 0 || this.cll_.witnesses[index]!.attempts !== expectedAttempts)
      throw new CllError("contention", "witness state changed");
    const witnesses = [...this.cll_.witnesses];
    witnesses[index] = cloneWitness(next);
    this.cll_ = { ...this.cll_, witnesses };
  }
}
