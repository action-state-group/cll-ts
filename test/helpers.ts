import { expect } from "vitest";
import { build, createEd25519Identity } from "capsule-emit-ts";
import { CheckpointRunner, LedgerService, type Store } from "../src/index.js";

export async function witnessMergeContract(
  first: Store,
  second: Store,
): Promise<void> {
  const at = new Date("2026-09-01T12:00:00Z");
  const initial = {
    witnessId: "first",
    checkpointSize: 1n,
    checkpoint: Uint8Array.of(1),
    attempts: 0,
    nextAttemptAt: at,
    permanent: false,
  };
  await first.commitCll(0n, undefined, {
    size: 0n,
    nodes: [],
    indexedSeq: 0n,
    witnesses: [initial],
  });
  const stale = await second.loadCll();
  await Promise.all([
    first.commitWitness(0, {
      ...initial,
      attempts: 1,
      nextAttemptAt: new Date(at.valueOf() + 1_000),
      lastError: "retry",
    }),
    second.commitCll(stale.size, stale.checkpoint, {
      ...stale,
      witnesses: [
        ...stale.witnesses,
        {
          ...initial,
          witnessId: "second",
          checkpointSize: 2n,
        },
      ],
    }),
  ]);
  expect((await second.getWitness("first", 1n))?.attempts).toBe(1);
  expect((await first.getWitness("second", 2n))?.attempts).toBe(0);
}

export async function checkpointPersistenceContract(
  writer: Store,
  reader: Store,
): Promise<void> {
  const at = new Date("2026-09-01T12:00:00Z");
  const service = new LedgerService(writer, {}, () => at);
  await service.append(
    "unsigned",
    build({
      actionId: "checkpoint-persistence",
      actionType: "fyi",
      operator: "test",
      developer: "test@v1",
      timestamp: at,
    }).json,
  );
  const runner = new CheckpointRunner(writer, {
    logId: "checkpoint-persistence",
    identity: createEd25519Identity(new Uint8Array(32)),
    witnessIds: ["anchor"],
    entryCadence: 1,
    clock: () => at,
  });
  await expect(runner.runOnce()).resolves.toBeDefined();
  const state = await reader.loadCll();
  expect(state.indexedSeq).toBe(1n);
  expect(state.size).toBe(1n);
  expect(state.checkpointSize).toBe(1n);
  expect(state.checkpointIndexedSeq).toBe(1n);
  expect(state.witnesses).toHaveLength(1);
}
