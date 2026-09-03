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
import { addedWitnesses, BackendState } from "./backend-state.js";
import {
  cllFromWire,
  cllToWire,
  entryFromWire,
  entryToWire,
  witnessFromWire,
  witnessToWire,
  type WireCllState,
  type WireEntry,
  type WireWitness,
} from "./serde.js";
import {
  CllError,
  limits,
  type AppendInput,
  type CllBackend,
  type CllState,
  type WitnessState,
} from "./types.js";

type JournalEvent =
  | { version: 4; type: "cll.init" }
  | { version: 4; type: "entry.append"; entry: WireEntry }
  | {
      version: 4;
      type: "cll.commit";
      expected_size: string;
      expected_checkpoint?: string;
      state: WireCllState;
    }
  | {
      version: 4;
      type: "witness.commit";
      expected_attempts: number;
      witness: WireWitness;
    };

/** Single-writer append-only JSONL backend with fsync per complete event. */
export class JsonlStore implements CllBackend {
  private readonly state = new BackendState();
  private queue: Promise<void> = Promise.resolve();
  private closed = false;

  private constructor(private readonly fd: number) {}

  public static async open(path: string): Promise<JsonlStore> {
    const fd = openSync(path, "a+");
    try {
      flockSync(fd, "exnb");
    } catch (error) {
      closeSync(fd);
      throw new CllError("contention", "JSONL backend already has a writer", {
        cause: error,
      });
    }
    const backend = new JsonlStore(fd);
    try {
      const bytes = readFileSync(path);
      let validEnd = 0;
      let initialized = false;
      for (let start = 0; start < bytes.length; ) {
        const end = bytes.indexOf(0x0a, start);
        if (end < 0) break;
        try {
          if (end - start > limits.journalEvent)
            throw new CllError("corrupt", "JSONL event exceeds size limit");
          const raw = JSON.parse(
            bytes.subarray(start, end).toString("utf8"),
          ) as {
            version?: unknown;
            v?: unknown;
          };
          if (raw.version !== 4)
            throw new CllError(
              "corrupt",
              raw.version === 3 || raw.v === 3
                ? "legacy JSONL schema version 3 is unsupported"
                : "unsupported JSONL schema version",
            );
          backend.applyEvent(raw as JournalEvent);
          initialized = true;
        } catch (error) {
          if (error instanceof CllError) throw error;
          throw new CllError(
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
        await backend.appendEvent({ version: 4, type: "cll.init" });
      return backend;
    } catch (error) {
      flockSync(fd, "un");
      closeSync(fd);
      throw error;
    }
  }

  private ensureOpen(): void {
    if (this.closed) throw new CllError("closed", "backend is closed");
  }

  private applyEvent(event: JournalEvent): void {
    if (event.type === "cll.init") {
      if (this.state.entries().length !== 0 || this.state.cll().size !== 0n)
        throw new CllError("corrupt", "duplicate CLL initialization");
      return;
    }
    if (event.type === "entry.append") {
      const entry = entryFromWire(event.entry);
      const result = this.state.append(entry);
      if (result.outcome !== "inserted" || result.entry.seq !== entry.seq)
        throw new CllError("corrupt", "invalid entry append event");
      return;
    }
    if (event.type === "cll.commit") {
      const current = this.state.cll();
      const delta = cllFromWire(event.state);
      this.state.commitCll(
        BigInt(event.expected_size),
        event.expected_checkpoint === undefined
          ? undefined
          : Buffer.from(event.expected_checkpoint, "base64"),
        {
          ...delta,
          nodes: [...current.nodes, ...delta.nodes],
        },
      );
      return;
    }
    this.state.commitWitness(
      event.expected_attempts,
      witnessFromWire(event.witness),
    );
  }

  private async appendEvent(event: JournalEvent): Promise<void> {
    const bytes = Buffer.from(`${JSON.stringify(event)}\n`);
    if (bytes.length > limits.journalEvent)
      throw new CllError("invalid", "JSONL event exceeds size limit");
    const start = fstatSync(this.fd).size;
    try {
      let written = 0;
      while (written < bytes.length) {
        const count = writeSync(
          this.fd,
          bytes,
          written,
          bytes.length - written,
          null,
        );
        if (count === 0) throw new Error("JSONL write made no progress");
        written += count;
      }
      fsyncSync(this.fd);
    } catch (error) {
      try {
        ftruncateSync(this.fd, start);
        fsyncSync(this.fd);
      } catch (rollbackError) {
        throw new AggregateError(
          [error, rollbackError],
          "JSONL write and rollback both failed",
        );
      }
      throw error;
    }
  }

  private async mutate<T>(
    operation: () => T,
    event: (result: T) => JournalEvent | undefined,
  ): Promise<T> {
    const prior = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      this.ensureOpen();
      return await this.state.persistMutation(operation, async (result) => {
        const nextEvent = event(result);
        if (nextEvent !== undefined) await this.appendEvent(nextEvent);
      });
    } finally {
      release();
    }
  }

  public append(input: AppendInput) {
    return this.mutate(
      () => this.state.append(input),
      (result) =>
        result.outcome === "inserted"
          ? {
              version: 4,
              type: "entry.append",
              entry: entryToWire(result.entry),
            }
          : undefined,
    );
  }

  public async getEntry(value: Uint8Array) {
    this.ensureOpen();
    return this.state.getEntry(value);
  }

  public async scanEntries(afterSeq: bigint, limit: number) {
    this.ensureOpen();
    return this.state.scanEntries(afterSeq, limit);
  }

  public async loadCll() {
    this.ensureOpen();
    return this.state.cll();
  }

  public commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ) {
    let before!: CllState;
    return this.mutate(
      () => {
        before = this.state.cll();
        this.state.commitCll(expectedSize, expectedCheckpoint, next);
      },
      () => {
        const current = this.state.cll();
        return {
          version: 4,
          type: "cll.commit",
          expected_size: String(expectedSize),
          ...(expectedCheckpoint === undefined
            ? {}
            : {
                expected_checkpoint:
                  Buffer.from(expectedCheckpoint).toString("base64"),
              }),
          state: cllToWire({
            ...current,
            nodes: current.nodes.slice(before.nodes.length),
            witnesses: addedWitnesses(before.witnesses, current.witnesses),
          }),
        };
      },
    );
  }

  public async pendingWitnesses(now: Date, limit: number) {
    this.ensureOpen();
    return this.state.pendingWitnesses(now, limit);
  }

  public async getWitness(witnessId: string, checkpointSize: bigint) {
    this.ensureOpen();
    return this.state.getWitness(witnessId, checkpointSize);
  }

  public commitWitness(expectedAttempts: number, next: WitnessState) {
    return this.mutate(
      () => this.state.commitWitness(expectedAttempts, next),
      () => ({
        version: 4,
        type: "witness.commit",
        expected_attempts: expectedAttempts,
        witness: witnessToWire(next),
      }),
    );
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    await this.queue;
    this.closed = true;
    flockSync(this.fd, "un");
    closeSync(this.fd);
  }
}
