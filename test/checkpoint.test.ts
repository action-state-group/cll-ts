import { describe, expect, it, vi } from "vitest";
import { createEd25519Identity } from "capsule-emit-ts";
import {
  CheckpointRunner,
  LedgerError,
  LedgerService,
  MemoryStore,
  MmrTree,
  WitnessDeliveryRunner,
  signCheckpoint,
  verifyCheckpoint,
  type WitnessClient,
} from "../src/index.js";

describe("checkpoint COSE", () => {
  it("signs a self-verifying first checkpoint", () => {
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    const identity = createEd25519Identity(
      Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
    );
    const checkpoint = signCheckpoint({
      logId: "test-log",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: "2026-09-01T12:34:56.836Z",
      identity,
    });
    expect(verifyCheckpoint(checkpoint.cose)).toBe(true);
    expect(checkpoint.previousRoot).toBe("");
    expect(checkpoint.json.length).toBeGreaterThan(0);
    const tampered = Uint8Array.from(checkpoint.cose);
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 1;
    expect(verifyCheckpoint(tampered)).toBe(false);
  });
  it("persists checkpoint and lets permanent witness failure coexist with success", async () => {
    const store = new MemoryStore();
    const service = new LedgerService(
      store,
      {},
      () => new Date("2026-09-01T12:34:56Z"),
    );
    const capsule = (await import("capsule-emit-ts")).build({
      actionId: "runner-1",
      actionType: "fyi",
      operator: "test",
      developer: "test@v1",
      timestamp: "2026-09-01T12:00:00Z",
    });
    await service.append("unsigned", capsule.json);
    const identity = createEd25519Identity(
      Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
    );
    const runner = new CheckpointRunner(store, {
      logId: "test-log",
      identity,
      witnessIds: ["good", "bad"],
      entryCadence: 1,
      clock: () => new Date("2026-09-01T12:34:56Z"),
    });
    const concurrent = await Promise.all([runner.runOnce(), runner.runOnce()]);
    expect(
      concurrent.filter((checkpoint) => checkpoint !== undefined),
    ).toHaveLength(1);
    const good: WitnessClient = {
      id: "good",
      submit: async () => ({
        bytes: Uint8Array.of(1, 2, 3),
        entryHash: "11".repeat(32),
        entryHashScheme: "legacy",
        leafIndex: 0,
        treeSize: 1,
      }),
    };
    const bad: WitnessClient = {
      id: "bad",
      submit: async () => {
        throw new LedgerError("admission_rejected", "rejected");
      },
    };
    const delivery = new WitnessDeliveryRunner(
      store,
      new Map([
        [good.id, good],
        [bad.id, bad],
      ]),
      {
        verifiers: new Map([
          [good.id, { verify: () => true }],
          [bad.id, { verify: () => true }],
        ]),
        now: () => new Date("2026-09-01T12:35:00Z"),
      },
    );
    expect(await delivery.runOnce()).toBe(1);
    expect((await store.getWitness("good", 1n))?.receipt).toEqual(
      Uint8Array.of(1, 2, 3),
    );
    expect((await store.getWitness("bad", 1n))?.permanent).toBe(true);
    await store.close();
  });
  it("does not let a slow witness starve an independent witness", async () => {
    const store = new MemoryStore();
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    const signed = signCheckpoint({
      logId: "parallel-witnesses",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: "2026-09-01T12:00:00Z",
      identity: createEd25519Identity(new Uint8Array(32)),
    });
    const witness = (witnessId: string) => ({
      witnessId,
      checkpointSize: 1n,
      checkpoint: signed.cose,
      attempts: 0,
      nextAttemptAt: new Date(0),
      permanent: false,
    });
    await store.commitCll(0n, undefined, {
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [witness("slow"), witness("fast")],
    });
    let releaseSlow!: () => void;
    const slowGate = new Promise<void>((resolve) => {
      releaseSlow = resolve;
    });
    const receipt = {
      bytes: Uint8Array.of(1),
      entryHash: "11".repeat(32),
      entryHashScheme: "legacy" as const,
      leafIndex: 0,
      treeSize: 1,
    };
    const fastSubmit = vi.fn(async () => receipt);
    const delivery = new WitnessDeliveryRunner(
      store,
      new Map([
        [
          "slow",
          {
            id: "slow",
            submit: async () => {
              await slowGate;
              return receipt;
            },
          },
        ],
        ["fast", { id: "fast", submit: fastSubmit }],
      ]),
      {
        verifiers: new Map([
          ["slow", { verify: () => true }],
          ["fast", { verify: () => true }],
        ]),
        now: () => new Date("2026-09-01T12:00:01Z"),
      },
    );
    const running = delivery.runOnce();
    try {
      await vi.waitFor(() => expect(fastSubmit).toHaveBeenCalledOnce());
    } finally {
      releaseSlow();
    }
    await expect(running).resolves.toBe(2);
    await store.close();
  });

  it("fails closed before persisting an unverified receipt", async () => {
    const store = new MemoryStore();
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    const signed = signCheckpoint({
      logId: "unverified",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: "2026-09-01T12:00:00Z",
      identity: createEd25519Identity(new Uint8Array(32)),
    });
    await store.commitCll(0n, undefined, {
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [
        {
          witnessId: "unverified",
          checkpointSize: 1n,
          checkpoint: signed.cose,
          attempts: 0,
          nextAttemptAt: new Date(0),
          permanent: false,
        },
      ],
    });
    const delivery = new WitnessDeliveryRunner(
      store,
      new Map([
        [
          "unverified",
          {
            id: "unverified",
            submit: async () => ({
              bytes: Uint8Array.of(1),
              entryHash: "11".repeat(32),
              entryHashScheme: "legacy" as const,
              leafIndex: 0,
              treeSize: 1,
            }),
          },
        ],
      ]),
      { verifiers: new Map(), now: () => new Date(0) },
    );
    expect(await delivery.runOnce()).toBe(0);
    const state = await store.getWitness("unverified", 1n);
    expect(state?.permanent).toBe(true);
    expect(state?.receipt).toBeUndefined();
    await store.close();
  });
  it("backs retryable witness failures off without marking them permanent", async () => {
    const store = new MemoryStore();
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    const identity = createEd25519Identity(new Uint8Array(32));
    const signed = signCheckpoint({
      logId: "retryable",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: "2026-09-01T12:00:00Z",
      identity,
    });
    const now = new Date("2026-09-01T12:00:00Z");
    await store.commitCll(0n, undefined, {
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [
        {
          witnessId: "retryable",
          checkpointSize: 1n,
          checkpoint: signed.cose,
          attempts: 0,
          nextAttemptAt: now,
          permanent: false,
        },
      ],
    });
    const delivery = new WitnessDeliveryRunner(
      store,
      new Map([
        [
          "retryable",
          {
            id: "retryable",
            submit: async () => {
              throw new LedgerError("contention", "retry later");
            },
          },
        ],
      ]),
      {
        verifiers: new Map([["retryable", { verify: () => true }]]),
        now: () => now,
      },
    );
    expect(await delivery.runOnce()).toBe(0);
    const state = await store.getWitness("retryable", 1n);
    expect(state?.attempts).toBe(1);
    expect(state?.permanent).toBe(false);
    expect(state?.nextAttemptAt.valueOf()).toBe(now.valueOf() + 1_000);
    await store.close();
  });
  it("runs and stops both polling lifecycles without duplicate starts", async () => {
    const store = new MemoryStore();
    const identity = createEd25519Identity(new Uint8Array(32));
    const checkpoint = new CheckpointRunner(store, {
      logId: "lifecycle",
      identity,
      pollIntervalMs: 5,
    });
    const checkpointAbort = new AbortController();
    const checkpointRun = checkpoint.run(checkpointAbort.signal);
    await expect(
      checkpoint.run(new AbortController().signal),
    ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<LedgerError>);
    checkpointAbort.abort();
    await checkpointRun;

    const delivery = new WitnessDeliveryRunner(store, new Map(), {
      verifiers: new Map(),
      pollIntervalMs: 5,
    });
    const deliveryAbort = new AbortController();
    const deliveryRun = delivery.run(deliveryAbort.signal);
    await expect(
      delivery.run(new AbortController().signal),
    ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<LedgerError>);
    deliveryAbort.abort();
    await deliveryRun;

    const alreadyAborted = new AbortController();
    alreadyAborted.abort();
    await expect(
      checkpoint.run(alreadyAborted.signal),
    ).resolves.toBeUndefined();
    await expect(delivery.run(alreadyAborted.signal)).resolves.toBeUndefined();
    await store.close();
  });
  it("aborts an in-flight witness request without recording a failed attempt", async () => {
    const store = new MemoryStore();
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    const signed = signCheckpoint({
      logId: "abort-request",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: "2026-09-01T12:00:00Z",
      identity: createEd25519Identity(new Uint8Array(32)),
    });
    await store.commitCll(0n, undefined, {
      size: 0n,
      nodes: [],
      indexedSeq: 0n,
      witnesses: [
        {
          witnessId: "abort-request",
          checkpointSize: 1n,
          checkpoint: signed.cose,
          attempts: 0,
          nextAttemptAt: new Date(0),
          permanent: false,
        },
      ],
    });
    let markSubmitted!: () => void;
    const submitted = new Promise<void>((resolve) => {
      markSubmitted = resolve;
    });
    const delivery = new WitnessDeliveryRunner(
      store,
      new Map([
        [
          "abort-request",
          {
            id: "abort-request",
            submit: async (_checkpoint: Uint8Array, signal?: AbortSignal) => {
              markSubmitted();
              return new Promise((_resolve, reject) => {
                signal?.addEventListener("abort", () => reject(signal.reason), {
                  once: true,
                });
              });
            },
          },
        ],
      ]),
      {
        verifiers: new Map([["abort-request", { verify: () => true }]]),
        pollIntervalMs: 5,
      },
    );
    const abort = new AbortController();
    const running = delivery.run(abort.signal);
    await submitted;
    abort.abort();
    await running;
    expect((await store.getWitness("abort-request", 1n))?.attempts).toBe(0);
    await store.close();
  });
  it("reports a corrupt stored checkpoint size as LedgerError", async () => {
    const store = new MemoryStore();
    const tree = new MmrTree();
    tree.appendCapsuleId("11".repeat(32));
    const identity = createEd25519Identity(new Uint8Array(32));
    const signed = signCheckpoint({
      logId: "corrupt-size",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: "2026-09-01T12:00:00Z",
      identity,
    });
    await store.commitCll(0n, undefined, {
      size: tree.size,
      nodes: tree.nodes(),
      indexedSeq: 1n,
      checkpoint: signed.cose,
      checkpointSize: 2n,
      checkpointIndexedSeq: 1n,
      checkpointPeaks: tree.peakHashes(),
      witnesses: [],
    });
    const runner = new CheckpointRunner(store, {
      logId: "corrupt-size",
      identity,
    });
    await expect(
      runner.run(new AbortController().signal),
    ).rejects.toMatchObject({
      code: "corrupt",
    } satisfies Partial<LedgerError>);
    await store.close();
  });

  it("rejects competing checkpoints at the same MMR size", async () => {
    const store = new MemoryStore();
    const appendClock = () => new Date("2026-09-01T12:00:00Z");
    const service = new LedgerService(store, {}, appendClock);
    for (const actionId of ["race-1", "race-2", "race-3"]) {
      const capsule = (await import("capsule-emit-ts")).build({
        actionId,
        actionType: "fyi",
        operator: "test",
        developer: "test@v1",
        timestamp: appendClock(),
      });
      await service.append("unsigned", capsule.json);
    }
    const identity = createEd25519Identity(new Uint8Array(32));
    const indexing = new CheckpointRunner(store, {
      logId: "checkpoint-race",
      identity,
      entryCadence: 100,
      ageCadenceMs: 60 * 60_000,
      clock: appendClock,
    });
    expect(await indexing.runOnce()).toBeUndefined();
    const staleBeforeCheckpoint = await store.loadCll();

    const first = new CheckpointRunner(store, {
      logId: "checkpoint-race",
      identity,
      witnessIds: ["anchor"],
      entryCadence: 100,
      ageCadenceMs: 1,
      clock: () => new Date("2026-09-01T13:00:00Z"),
    });
    const second = new CheckpointRunner(store, {
      logId: "checkpoint-race",
      identity,
      witnessIds: ["anchor"],
      entryCadence: 100,
      ageCadenceMs: 1,
      clock: () => new Date("2026-09-01T13:00:01Z"),
    });
    const results = await Promise.allSettled([
      first.runOnce(),
      second.runOnce(),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      reason: { code: "contention" },
    });
    const state = await store.loadCll();
    const witness = await store.getWitness("anchor", state.size);
    expect(witness?.checkpoint).toEqual(state.checkpoint);
    await expect(
      store.commitCll(
        staleBeforeCheckpoint.size,
        staleBeforeCheckpoint.checkpoint,
        {
          ...state,
          checkpoint: Uint8Array.of(9),
          checkpointSize: 7n,
        },
      ),
    ).rejects.toMatchObject({
      code: "contention",
    } satisfies Partial<LedgerError>);
    await store.close();
  });
});
