import { createHash } from "node:crypto";
import { cloneCll, cloneEnvelope, cloneRecord, cloneWitness } from "./clone.js";
import {
  LedgerError,
  limits,
  type AddOutcome,
  type AppendInput,
  type AppendOutcome,
  type CllState,
  type EnvelopeInput,
  type Record,
  type Store,
  type WitnessState,
} from "./types.js";

const hex64 = /^[0-9a-f]{64}$/u;
const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");
const same = (left: Uint8Array, right: Uint8Array): boolean =>
  Buffer.from(left).equals(Buffer.from(right));
const normalizeDate = (value: Date): Date =>
  new Date(Math.trunc(value.valueOf()));

export class MemoryStore implements Store {
  protected readonly records: Record[] = [];
  protected readonly byId = new Map<string, Record>();
  protected cll: CllState = {
    size: 0n,
    nodes: [],
    indexedSeq: 0n,
    witnesses: [],
  };
  protected closed = false;
  private queue: Promise<void> = Promise.resolve();

  protected ensureOpen(): void {
    if (this.closed) throw new LedgerError("closed", "store is closed");
  }
  protected witnessKey(
    value: Pick<WitnessState, "witnessId" | "checkpointSize">,
  ): string {
    return `${value.witnessId}\0${value.checkpointSize}`;
  }
  protected witnessDelta(
    previous: readonly WitnessState[],
    current: readonly WitnessState[],
  ): WitnessState[] {
    const existing = new Set(previous.map((item) => this.witnessKey(item)));
    return current
      .filter((item) => !existing.has(this.witnessKey(item)))
      .map(cloneWitness);
  }
  protected replaceState(records: readonly Record[], cll: CllState): void {
    this.records.length = 0;
    for (const record of records) this.records.push(cloneRecord(record));
    this.byId.clear();
    for (const record of this.records) this.byId.set(record.capsuleId, record);
    this.cll = cloneCll(cll);
  }
  protected async exclusive<T>(operation: () => T | Promise<T>): Promise<T> {
    const prior = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      this.ensureOpen();
      return await operation();
    } finally {
      release();
    }
  }
  public async append(
    input: AppendInput,
  ): Promise<{ record: Record; outcome: AppendOutcome }> {
    return this.exclusive(() => {
      if (
        !hex64.test(input.capsuleId) ||
        input.capsule.length < 1 ||
        input.capsule.length > limits.capsule ||
        input.envelopes.length > limits.envelopes ||
        Number.isNaN(input.appendedAt.valueOf())
      )
        throw new LedgerError("invalid", "invalid append");
      const existing = this.byId.get(input.capsuleId);
      if (existing !== undefined) {
        if (
          !same(existing.capsule, input.capsule) ||
          existing.authenticity !== input.authenticity
        )
          throw new LedgerError(
            "immutable_conflict",
            "Capsule ID already has different immutable bytes or admission mode",
          );
        return { record: cloneRecord(existing), outcome: "idempotent" };
      }
      for (const envelope of input.envelopes)
        if (
          digest(envelope.bytes) !== envelope.digest ||
          envelope.bytes.length > limits.envelope
        )
          throw new LedgerError("invalid", "invalid Producer Envelope");
      const record: Record = cloneRecord({
        ...input,
        seq: BigInt(this.records.length + 1),
        appendedAt: normalizeDate(input.appendedAt),
      });
      this.records.push(record);
      this.byId.set(record.capsuleId, record);
      return { record: cloneRecord(record), outcome: "inserted" };
    });
  }
  public async addEnvelope(
    input: EnvelopeInput,
  ): Promise<{ envelope: import("./types.js").Envelope; outcome: AddOutcome }> {
    return this.exclusive(() => {
      const record = this.byId.get(input.capsuleId);
      if (record === undefined)
        throw new LedgerError("not_found", "Capsule not found");
      if (
        digest(input.envelope.bytes) !== input.envelope.digest ||
        input.envelope.bytes.length > limits.envelope
      )
        throw new LedgerError("invalid", "invalid Producer Envelope");
      const existing = record.envelopes.find(
        (item) => item.digest === input.envelope.digest,
      );
      if (existing !== undefined)
        return { envelope: cloneEnvelope(existing), outcome: "idempotent" };
      if (record.envelopes.length >= limits.envelopes)
        throw new LedgerError("invalid", "too many Producer Envelopes");
      const envelope = cloneEnvelope(input.envelope);
      const updated = cloneRecord({
        ...record,
        envelopes: [...record.envelopes, envelope],
      });
      this.records[Number(record.seq - 1n)] = updated;
      this.byId.set(record.capsuleId, updated);
      return { envelope: cloneEnvelope(envelope), outcome: "inserted" };
    });
  }
  public async get(capsuleId: string): Promise<Record> {
    this.ensureOpen();
    const value = this.byId.get(capsuleId);
    if (value === undefined)
      throw new LedgerError("not_found", "Capsule not found");
    return cloneRecord(value);
  }
  public async scan(after: bigint, limit: number): Promise<readonly Record[]> {
    this.ensureOpen();
    if (limit < 1 || limit > limits.scanMax)
      throw new LedgerError("invalid", "invalid scan limit");
    const start =
      after < 0n
        ? 0
        : after >= BigInt(this.records.length)
          ? this.records.length
          : Number(after);
    return this.records.slice(start, start + limit).map(cloneRecord);
  }
  public async scanIds(after: bigint, limit: number) {
    return (await this.scan(after, limit)).map(
      ({ seq, capsuleId, appendedAt }) => ({ seq, capsuleId, appendedAt }),
    );
  }
  /** Project AAC Capsule IDs into application-neutral CLL leaf bytes. */
  public async scanEntries(after: bigint, limit: number) {
    return (await this.scanIds(after, limit)).map(
      ({ seq, capsuleId, appendedAt }) => {
        if (!hex64.test(capsuleId))
          throw new LedgerError("corrupt", "stored Capsule ID is invalid");
        return {
          seq,
          value: Uint8Array.from(Buffer.from(capsuleId, "hex")),
          appendedAt,
        };
      },
    );
  }
  public async findChainGaps() {
    this.ensureOpen();
    return this.records
      .filter(
        (record) =>
          record.parentId !== undefined && !this.byId.has(record.parentId),
      )
      .map(({ seq, capsuleId, parentId }) => ({
        seq,
        capsuleId,
        parentId: parentId!,
      }));
  }
  public async loadCll(): Promise<CllState> {
    this.ensureOpen();
    return cloneCll(this.cll);
  }
  public async commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void> {
    await this.exclusive(() => {
      if (this.cll.size !== expectedSize)
        throw new LedgerError("contention", "CLL state changed");
      if (
        (expectedCheckpoint === undefined) !==
          (this.cll.checkpoint === undefined) ||
        (expectedCheckpoint !== undefined &&
          this.cll.checkpoint !== undefined &&
          !Buffer.from(expectedCheckpoint).equals(
            Buffer.from(this.cll.checkpoint),
          ))
      )
        throw new LedgerError("contention", "CLL checkpoint changed");
      if (
        this.cll.checkpoint !== undefined &&
        this.cll.checkpointSize !== undefined &&
        next.checkpoint !== undefined &&
        next.checkpointSize === this.cll.checkpointSize &&
        !Buffer.from(next.checkpoint).equals(Buffer.from(this.cll.checkpoint))
      )
        throw new LedgerError(
          "contention",
          "checkpoint already exists at this CLL size",
        );
      if (
        next.size !== BigInt(next.nodes.length) ||
        next.size < this.cll.size ||
        next.indexedSeq < this.cll.indexedSeq ||
        this.cll.nodes.some(
          (node, index) =>
            !Buffer.from(node).equals(Buffer.from(next.nodes[index] ?? [])),
        ) ||
        next.nodes.some((node) => node.length !== 32)
      )
        throw new LedgerError("invalid", "invalid append-only CLL state");
      const existing = new Map(
        this.cll.witnesses.map((item) => [this.witnessKey(item), item]),
      );
      for (const witness of next.witnesses) {
        const current = existing.get(this.witnessKey(witness));
        if (
          current !== undefined &&
          !Buffer.from(current.checkpoint).equals(
            Buffer.from(witness.checkpoint),
          )
        )
          throw new LedgerError(
            "contention",
            "witness delivery already exists for another checkpoint",
          );
      }
      this.cll = cloneCll({
        ...next,
        witnesses: [
          ...this.cll.witnesses,
          ...next.witnesses.filter(
            (item) => !existing.has(this.witnessKey(item)),
          ),
        ],
      });
    });
  }
  public async pendingWitnesses(
    now: Date,
    limit: number,
  ): Promise<readonly WitnessState[]> {
    this.ensureOpen();
    return this.cll.witnesses
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
  public async getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): Promise<WitnessState | undefined> {
    this.ensureOpen();
    const value = this.cll.witnesses.find(
      (item) =>
        this.witnessKey(item) ===
        this.witnessKey({ witnessId, checkpointSize }),
    );
    return value === undefined ? undefined : cloneWitness(value);
  }
  public async commitWitness(
    expectedAttempts: number,
    next: WitnessState,
  ): Promise<void> {
    await this.exclusive(() => {
      const index = this.cll.witnesses.findIndex(
        (item) => this.witnessKey(item) === this.witnessKey(next),
      );
      if (index < 0 || this.cll.witnesses[index]!.attempts !== expectedAttempts)
        throw new LedgerError("contention", "witness state changed");
      const witnesses = [...this.cll.witnesses];
      witnesses[index] = cloneWitness(next);
      this.cll = { ...this.cll, witnesses };
    });
  }
  public async close(): Promise<void> {
    this.closed = true;
  }
}
