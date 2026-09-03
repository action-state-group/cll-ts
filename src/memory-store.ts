import { BackendState } from "./backend-state.js";
import {
  CllError,
  type AppendInput,
  type CllBackend,
  type CllState,
  type WitnessState,
} from "./types.js";

/** In-memory implementation of the complete generic backend contract. */
export class MemoryStore implements CllBackend {
  private readonly state = new BackendState();
  private closed = false;
  private queue: Promise<void> = Promise.resolve();

  private ensureOpen(): void {
    if (this.closed) throw new CllError("closed", "backend is closed");
  }

  private async exclusive<T>(operation: () => T | Promise<T>): Promise<T> {
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

  public append(input: AppendInput) {
    return this.exclusive(() => this.state.append(input));
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
    return this.exclusive(() =>
      this.state.commitCll(expectedSize, expectedCheckpoint, next),
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
    return this.exclusive(() =>
      this.state.commitWitness(expectedAttempts, next),
    );
  }

  public async close(): Promise<void> {
    this.closed = true;
  }
}
