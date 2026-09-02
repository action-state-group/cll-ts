import {
  closeSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  openSync,
  readFileSync,
  writeSync,
} from "node:fs";
import { flockSync } from "fs-ext";
import { cloneCll, cloneRecord, cloneWitness } from "./clone.js";
import { MemoryStore } from "./memory-store.js";
import {
  envelopeFromWire,
  envelopeToWire,
  recordFromWire,
  stateFromWire,
  stateToWire,
  witnessFromWire,
  type WireEnvelope,
  type WireState,
  type WireWitness,
} from "./serde.js";
import {
  LedgerError,
  type AppendInput,
  type CllState,
  type EnvelopeInput,
  type WitnessState,
} from "./types.js";

type WireRecord = WireState["records"][number];
type WireCllDelta = Omit<WireState["cll"], "nodes" | "witnesses"> & {
  nodes: string[];
  witnesses: WireWitness[];
};
type JournalEvent =
  | { version: 3; type: "log.init" }
  | { version: 3; type: "capsule.append"; record: WireRecord }
  | {
      version: 3;
      type: "envelope.add";
      capsule_id: string;
      envelope: WireEnvelope;
    }
  | { version: 3; type: "cll.commit"; cll: WireCllDelta }
  | {
      version: 3;
      type: "witness.commit";
      expected_attempts: number;
      witness: WireWitness;
    };

/** Single-writer append-only JSONL store with bounded incremental v3 events. */
export class JsonlStore extends MemoryStore {
  private journalQueue: Promise<void> = Promise.resolve();
  private closing = false;

  private constructor(private readonly fd: number) {
    super();
  }

  public static async open(path: string): Promise<JsonlStore> {
    const fd = openSync(path, "a+");
    try {
      flockSync(fd, "exnb");
    } catch (error) {
      closeSync(fd);
      throw new LedgerError(
        "contention",
        "JSONL store is already open by another writer",
        { cause: error },
      );
    }
    const store = new JsonlStore(fd);
    try {
      const bytes = readFileSync(path);
      let validEnd = 0;
      let initialized = false;
      for (let start = 0; start < bytes.length; ) {
        const end = bytes.indexOf(0x0a, start);
        if (end < 0) break;
        const line = bytes.subarray(start, end).toString("utf8");
        try {
          const raw = JSON.parse(line) as unknown;
          if (
            raw !== null &&
            typeof raw === "object" &&
            "v" in raw &&
            (raw as { v: unknown }).v === 3 &&
            "state" in raw
          ) {
            store.hydrate((raw as { state: WireState }).state);
            initialized = true;
          } else {
            store.applyEvent(raw as JournalEvent);
            initialized = true;
          }
        } catch (error) {
          throw new LedgerError(
            "corrupt",
            `corrupt complete JSONL line at byte ${start}`,
            { cause: error },
          );
        }
        validEnd = end + 1;
        start = end + 1;
      }
      if (validEnd !== bytes.length) ftruncateSync(fd, validEnd);
      if (!initialized)
        await store.appendEvent({ version: 3, type: "log.init" });
      return store;
    } catch (error) {
      flockSync(fd, "un");
      closeSync(fd);
      throw error;
    }
  }

  private hydrate(wire: WireState): void {
    const state = stateFromWire(wire);
    this.replaceState(state.records, state.cll);
  }

  private applyEvent(event: JournalEvent): void {
    if (event.version !== 3) throw new Error("unsupported version");
    if (event.type === "log.init") {
      if (this.records.length !== 0 || this.cll.size !== 0n)
        throw new Error("duplicate log initialization");
      return;
    }
    if (event.type === "capsule.append") {
      const decoded = recordFromWire(event.record);
      if (
        decoded.seq !== BigInt(this.records.length + 1) ||
        this.byId.has(decoded.capsuleId)
      )
        throw new Error("invalid capsule append event");
      this.records.push(decoded);
      this.byId.set(decoded.capsuleId, decoded);
      return;
    }
    if (event.type === "envelope.add") {
      const record = this.byId.get(event.capsule_id);
      if (record === undefined)
        throw new Error("envelope references missing capsule");
      const envelope = envelopeFromWire(event.envelope);
      if (
        record.envelopes.some(
          (candidate) => candidate.digest === envelope.digest,
        )
      )
        throw new Error("duplicate envelope event");
      const updated = {
        ...record,
        envelopes: [...record.envelopes, envelope],
      };
      this.records[Number(record.seq - 1n)] = updated;
      this.byId.set(record.capsuleId, updated);
      return;
    }
    if (event.type === "cll.commit") {
      const delta = stateFromWire({
        records: [],
        cll: event.cll,
      }).cll;
      const cll = {
        ...delta,
        nodes: [...this.cll.nodes, ...delta.nodes],
        witnesses: [...this.cll.witnesses, ...delta.witnesses],
      };
      if (cll.size !== BigInt(cll.nodes.length))
        throw new Error("invalid CLL event");
      this.cll = cloneCll(cll);
      return;
    }
    const witness = witnessFromWire(event.witness);
    const index = this.cll.witnesses.findIndex(
      (item) =>
        item.witnessId === witness.witnessId &&
        item.checkpointSize === witness.checkpointSize,
    );
    if (
      index < 0 ||
      this.cll.witnesses[index]!.attempts !== event.expected_attempts
    )
      throw new Error("invalid witness event");
    const witnesses = [...this.cll.witnesses];
    witnesses[index] = witness;
    this.cll = { ...this.cll, witnesses };
  }

  private async appendEvent(event: JournalEvent): Promise<void> {
    const line = `${JSON.stringify(event)}\n`;
    if (Buffer.byteLength(line) > 4 * 1024 * 1024)
      throw new LedgerError("invalid", "JSONL event exceeds 4 MiB");
    const bytes = Buffer.from(line);
    const start = fstatSync(this.fd).size;
    let written = 0;
    while (written < bytes.length) {
      const count = writeSync(
        this.fd,
        bytes,
        written,
        bytes.length - written,
        start + written,
      );
      if (count <= 0) throw new Error("JSONL write made no progress");
      written += count;
    }
    fsyncSync(this.fd);
  }

  /** Keep each memory mutation and its durable event in one ordered unit. */
  private async journalExclusive<T>(
    operation: () => Promise<T>,
    rollback: () => void,
  ): Promise<T> {
    if (this.closing || this.closed)
      throw new LedgerError("closed", "store is closed");
    const prior = this.journalQueue;
    let release!: () => void;
    this.journalQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      if (this.closing || this.closed)
        throw new LedgerError("closed", "store is closed");
      const fileSize = fstatSync(this.fd).size;
      try {
        return await operation();
      } catch (error) {
        rollback();
        try {
          ftruncateSync(this.fd, fileSize);
          fsyncSync(this.fd);
        } catch (rollbackError) {
          this.closed = true;
          try {
            flockSync(this.fd, "un");
            closeSync(this.fd);
          } catch {
            // The descriptor may already be the reason rollback failed.
          }
          throw new LedgerError(
            "corrupt",
            "JSONL write failed and durable rollback could not be verified",
            { cause: new AggregateError([error, rollbackError]) },
          );
        }
        throw error;
      }
    } finally {
      release();
    }
  }

  public override async append(input: AppendInput) {
    let beforeLength: number | undefined;
    return this.journalExclusive(
      async () => {
        beforeLength = this.records.length;
        const result = await super.append(input);
        if (result.outcome === "inserted") {
          const wire = stateToWire([result.record], this.cll).records[0]!;
          await this.appendEvent({
            version: 3,
            type: "capsule.append",
            record: wire,
          });
        }
        return result;
      },
      () => {
        if (beforeLength === undefined) return;
        while (this.records.length > beforeLength) {
          const removed = this.records.pop()!;
          this.byId.delete(removed.capsuleId);
        }
      },
    );
  }

  public override async addEnvelope(input: EnvelopeInput) {
    let snapshot: ReturnType<typeof cloneRecord> | undefined;
    return this.journalExclusive(
      async () => {
        const before = this.byId.get(input.capsuleId);
        snapshot = before === undefined ? undefined : cloneRecord(before);
        const result = await super.addEnvelope(input);
        if (result.outcome === "inserted")
          await this.appendEvent({
            version: 3,
            type: "envelope.add",
            capsule_id: input.capsuleId,
            envelope: envelopeToWire(result.envelope),
          });
        return result;
      },
      () => {
        if (snapshot === undefined) return;
        this.records[Number(snapshot.seq - 1n)] = snapshot;
        this.byId.set(snapshot.capsuleId, snapshot);
      },
    );
  }

  public override async commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): Promise<void> {
    let before: CllState | undefined;
    await this.journalExclusive(
      async () => {
        before = cloneCll(this.cll);
        const priorWitnesses = this.cll.witnesses;
        await super.commitCll(expectedSize, expectedCheckpoint, next);
        const wire = stateToWire([], this.cll).cll;
        const newWitnesses = this.witnessDelta(
          priorWitnesses,
          this.cll.witnesses,
        );
        await this.appendEvent({
          version: 3,
          type: "cll.commit",
          cll: {
            ...wire,
            nodes: wire.nodes.slice(Number(expectedSize)),
            witnesses: wire.witnesses.slice(
              wire.witnesses.length - newWitnesses.length,
            ),
          },
        });
      },
      () => {
        if (before === undefined) return;
        this.cll = cloneCll(before);
      },
    );
  }

  public override async commitWitness(
    expectedAttempts: number,
    next: WitnessState,
  ): Promise<void> {
    let index = -1;
    let before: WitnessState | undefined;
    await this.journalExclusive(
      async () => {
        index = this.cll.witnesses.findIndex(
          (item) =>
            item.witnessId === next.witnessId &&
            item.checkpointSize === next.checkpointSize,
        );
        before =
          index < 0 ? undefined : cloneWitness(this.cll.witnesses[index]!);
        await super.commitWitness(expectedAttempts, next);
        const wire = stateToWire([], {
          ...this.cll,
          witnesses: [next],
        }).cll.witnesses[0]!;
        await this.appendEvent({
          version: 3,
          type: "witness.commit",
          expected_attempts: expectedAttempts,
          witness: wire,
        });
      },
      () => {
        if (before === undefined || index < 0) return;
        const witnesses = [...this.cll.witnesses];
        witnesses[index] = before;
        this.cll = { ...this.cll, witnesses };
      },
    );
  }

  public override async close(): Promise<void> {
    if (this.closed || this.closing) return;
    this.closing = true;
    await this.journalQueue;
    flockSync(this.fd, "un");
    closeSync(this.fd);
    await super.close();
  }
}
