import { LedgerError, limits, type Store, type WitnessState } from "./types.js";
import { verifyCheckpoint } from "./checkpoint.js";
import { waitForInterval } from "./run-loop.js";

export interface WitnessClient {
  readonly id: string;
  submit(checkpoint: Uint8Array, signal?: AbortSignal): Promise<AnchorReceipt>;
}
export interface AnchorReceipt {
  readonly bytes: Uint8Array;
  readonly entryHash: string;
  readonly entryHashScheme: "legacy";
  readonly leafIndex: number;
  readonly treeSize: number;
}
export interface ReceiptVerification {
  verify(checkpoint: Uint8Array, receipt: AnchorReceipt): boolean;
}
export interface WitnessDeliveryRunnerOptions {
  readonly verifiers: ReadonlyMap<string, ReceiptVerification>;
  readonly now?: () => Date;
  readonly pollIntervalMs?: number;
}
export class CapsuleAnchorClient implements WitnessClient {
  private readonly baseUrl: URL;
  public constructor(
    public readonly id: string,
    baseUrl: URL,
    private readonly timeoutMs = 30_000,
  ) {
    if (
      (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") ||
      baseUrl.username !== "" ||
      baseUrl.password !== "" ||
      baseUrl.search !== "" ||
      baseUrl.hash !== ""
    )
      throw new TypeError(
        "witness base URL must be an HTTP(S) origin without credentials, query, or fragment",
      );
    this.baseUrl = new URL(baseUrl);
  }
  public async submit(
    checkpoint: Uint8Array,
    signal?: AbortSignal,
  ): Promise<AnchorReceipt> {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const combined =
      signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
    const response = await fetch(new URL("/checkpoints", this.baseUrl), {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/cll-checkpoint+cbor",
      },
      body: checkpoint,
      signal: combined,
      redirect: "manual",
    });
    const chunks: Uint8Array[] = [];
    let length = 0;
    if (response.body !== null) {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > limits.receipt) {
          await reader.cancel();
          throw new LedgerError(
            "admission_rejected",
            "witness response too large",
          );
        }
        chunks.push(value);
      }
    }
    const bytes = Buffer.concat(chunks, length);
    if (!response.ok)
      throw new LedgerError(
        response.status === 408 ||
        response.status === 429 ||
        response.status >= 500
          ? "contention"
          : "admission_rejected",
        `witness rejected checkpoint: HTTP ${response.status}`,
      );
    let wire: unknown;
    try {
      wire = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } catch (error) {
      throw new LedgerError(
        "admission_rejected",
        "invalid witness JSON response",
        { cause: error },
      );
    }
    if (wire === null || typeof wire !== "object" || Array.isArray(wire))
      throw new LedgerError("admission_rejected", "invalid witness response");
    const receipt = wire as Record<string, unknown>;
    if (receipt.entry_hash_scheme !== "legacy")
      throw new LedgerError(
        "admission_rejected",
        "unsupported witness entry_hash_scheme",
      );
    if (
      typeof receipt.entry_hash !== "string" ||
      !/^[0-9a-f]{64}$/u.test(receipt.entry_hash)
    )
      throw new LedgerError("admission_rejected", "invalid witness entry_hash");
    if (
      !Number.isSafeInteger(receipt.tree_size) ||
      (receipt.tree_size as number) < 1 ||
      !Number.isSafeInteger(receipt.leaf_index) ||
      (receipt.leaf_index as number) < 0 ||
      (receipt.leaf_index as number) >= (receipt.tree_size as number)
    )
      throw new LedgerError(
        "admission_rejected",
        "invalid witness tree position",
      );
    if (
      typeof receipt.receipt_b64 !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
        receipt.receipt_b64,
      )
    )
      throw new LedgerError(
        "admission_rejected",
        "invalid witness receipt_b64",
      );
    const decoded = Buffer.from(receipt.receipt_b64, "base64");
    if (decoded.length === 0)
      throw new LedgerError("admission_rejected", "empty witness receipt");
    return {
      bytes: decoded,
      entryHash: receipt.entry_hash,
      entryHashScheme: "legacy",
      leafIndex: receipt.leaf_index as number,
      treeSize: receipt.tree_size as number,
    };
  }
}
const truncate = (value: string): string => {
  const bytes = Buffer.from(value);
  return bytes.length <= limits.reason
    ? value
    : bytes
        .subarray(0, limits.reason)
        .toString("utf8")
        .replace(/\uFFFD$/u, "");
};
export class WitnessDeliveryRunner {
  private readonly verifiers: ReadonlyMap<string, ReceiptVerification>;
  private readonly now: () => Date;
  private readonly pollIntervalMs: number;
  private running = false;

  public constructor(
    private readonly store: Store,
    private readonly clients: ReadonlyMap<string, WitnessClient>,
    options: WitnessDeliveryRunnerOptions,
  ) {
    this.verifiers = options.verifiers;
    this.now = options.now ?? (() => new Date());
    this.pollIntervalMs = options.pollIntervalMs ?? 60_000;
    if (!Number.isSafeInteger(this.pollIntervalMs) || this.pollIntervalMs < 1)
      throw new TypeError("witness poll interval must be a positive integer");
  }

  /** Run the host-controlled polling lifecycle until its signal is aborted. */
  public async run(signal: AbortSignal): Promise<void> {
    if (this.running)
      throw new LedgerError("invalid", "witness runner is already running");
    if (signal.aborted) return;
    this.running = true;
    try {
      while (!signal.aborted) {
        try {
          await this.runOnce(limits.witnesses, signal);
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

  public async runOnce(
    limit = limits.witnesses,
    signal?: AbortSignal,
  ): Promise<number> {
    const pending = await this.store.pendingWitnesses(this.now(), limit);
    const groups = new Map<string, WitnessState[]>();
    for (const item of pending) {
      const group = groups.get(item.witnessId);
      if (group === undefined) groups.set(item.witnessId, [item]);
      else group.push(item);
    }
    const outcomes = await Promise.allSettled(
      [...groups.values()].map(async (items) => {
        let completed = 0;
        for (const item of items) {
          if (signal?.aborted) break;
          completed += await this.deliver(item, signal);
        }
        return completed;
      }),
    );
    let completed = 0;
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") throw outcome.reason;
      completed += outcome.value;
    }
    return completed;
  }

  private async deliver(
    item: WitnessState,
    signal?: AbortSignal,
  ): Promise<number> {
    const client = this.clients.get(item.witnessId);
    let next: WitnessState;
    let completed = 0;
    try {
      if (!verifyCheckpoint(item.checkpoint))
        throw new LedgerError(
          "corrupt",
          "stored checkpoint failed offline verification",
        );
      if (client === undefined)
        throw new LedgerError(
          "admission_rejected",
          "witness client is not configured",
        );
      const verifier = this.verifiers.get(item.witnessId);
      if (verifier === undefined)
        throw new LedgerError(
          "admission_rejected",
          "receipt verifier is not configured",
        );
      const receipt = await client.submit(item.checkpoint, signal);
      let verified = false;
      try {
        verified = verifier.verify(item.checkpoint, receipt);
      } catch (error) {
        throw new LedgerError(
          "admission_rejected",
          "witness receipt verifier failed",
          { cause: error },
        );
      }
      if (!verified)
        throw new LedgerError(
          "admission_rejected",
          "witness receipt failed offline verification",
        );
      const { lastError: _lastError, ...withoutLastError } = item;
      next = {
        ...withoutLastError,
        attempts: item.attempts + 1,
        receipt: receipt.bytes,
        entryHash: receipt.entryHash,
        entryHashScheme: receipt.entryHashScheme,
        leafIndex: receipt.leafIndex,
        treeSize: receipt.treeSize,
        nextAttemptAt: this.now(),
      };
      completed = 1;
    } catch (error) {
      if (signal?.aborted) return 0;
      const permanent =
        error instanceof LedgerError &&
        (error.code === "admission_rejected" || error.code === "corrupt");
      next = {
        ...item,
        attempts: item.attempts + 1,
        permanent,
        lastError: truncate(String(error)),
        nextAttemptAt: new Date(
          this.now().valueOf() +
            Math.min(3_600_000, 1_000 * 2 ** Math.min(item.attempts, 12)),
        ),
      };
    }
    await this.store.commitWitness(item.attempts, next);
    return completed;
  }
}
