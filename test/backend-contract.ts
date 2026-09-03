import { expect } from "vitest";
import {
  CheckpointRunner,
  CllError,
  createCheckpointIdentity,
  type CllBackend,
  type WitnessState,
} from "../src/index.js";

const at = new Date("2026-09-01T12:00:00Z");
const value = (byte: number) => Uint8Array.from({ length: 32 }, () => byte);

/** Complete behavior contract executed unchanged against every backend. */
export async function backendContract(backend: CllBackend): Promise<void> {
  const [first, second] = await Promise.all([
    backend.append({ value: value(1), appendedAt: at }),
    backend.append({ value: value(2), appendedAt: at }),
  ]);
  expect(new Set([first.entry.seq, second.entry.seq])).toEqual(
    new Set([1n, 2n]),
  );

  const duplicate = await backend.append({
    value: value(1),
    appendedAt: new Date(at.valueOf() + 10_000),
  });
  expect(duplicate.outcome).toBe("idempotent");
  expect(duplicate.entry.seq).toBe(first.entry.seq);
  expect(duplicate.entry.appendedAt).toEqual(at);

  const scanned = await backend.scanEntries(0n, 2);
  expect(scanned.map((entry) => entry.seq)).toEqual([1n, 2n]);
  scanned[0]!.value[0] = 99;
  expect((await backend.getEntry(value(1))).value[0]).toBe(1);

  await expect(
    backend.append({ value: Uint8Array.of(1), appendedAt: at }),
  ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<CllError>);
  await expect(backend.scanEntries(-1n, 1)).rejects.toMatchObject({
    code: "invalid",
  } satisfies Partial<CllError>);
  await expect(
    backend.scanEntries(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 1),
  ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<CllError>);
  await expect(backend.scanEntries(0n, 1.5)).rejects.toMatchObject({
    code: "invalid",
  } satisfies Partial<CllError>);
  await expect(backend.getEntry(value(9))).rejects.toMatchObject({
    code: "not_found",
  } satisfies Partial<CllError>);
  await expect(backend.getWitness("", 0n)).resolves.toBeUndefined();

  const runner = new CheckpointRunner(backend, {
    logId: "contract",
    identity: createCheckpointIdentity(new Uint8Array(32)),
    entryCadence: 1,
    clock: () => at,
  });
  await expect(runner.runOnce()).resolves.toBeDefined();
  const checkpointed = await backend.loadCll();
  expect(checkpointed.indexedSeq).toBe(2n);
  expect(checkpointed.checkpointSize).toBe(checkpointed.size);
  const { checkpointPeaks: _checkpointPeaks, ...partialCheckpoint } =
    checkpointed;
  await expect(
    backend.commitCll(
      checkpointed.size,
      checkpointed.checkpoint,
      partialCheckpoint,
    ),
  ).rejects.toMatchObject({ code: "invalid" } satisfies Partial<CllError>);
  await expect(
    backend.commitCll(checkpointed.size, checkpointed.checkpoint, {
      ...checkpointed,
      checkpointSize: checkpointed.checkpointSize! - 1n,
    }),
  ).rejects.toMatchObject({ code: "contention" } satisfies Partial<CllError>);

  const witness: WitnessState = {
    witnessId: "witness",
    checkpointSize: checkpointed.size,
    checkpoint: checkpointed.checkpoint!,
    attempts: 0,
    nextAttemptAt: at,
    permanent: false,
  };
  await backend.commitCll(checkpointed.size, checkpointed.checkpoint, {
    ...checkpointed,
    witnesses: [...checkpointed.witnesses, witness],
  });
  expect(await backend.pendingWitnesses(at, 1)).toHaveLength(1);
  const stale = await backend.loadCll();
  await backend.commitWitness(0, {
    ...witness,
    attempts: 1,
    permanent: true,
    lastError: "rejected",
  });
  expect(
    (await backend.getWitness("witness", checkpointed.size))?.attempts,
  ).toBe(1);
  const secondWitness: WitnessState = {
    ...witness,
    witnessId: "second-witness",
  };
  await backend.commitCll(stale.size, stale.checkpoint, {
    ...stale,
    witnesses: [...stale.witnesses, secondWitness],
  });
  expect(
    (await backend.getWitness("witness", checkpointed.size))?.attempts,
  ).toBe(1);
  expect(
    await backend.getWitness("second-witness", checkpointed.size),
  ).toBeDefined();
  await expect(backend.commitWitness(0, witness)).rejects.toMatchObject({
    code: "contention",
  } satisfies Partial<CllError>);
  await backend.close();
  await backend.close();
  await expect(backend.scanEntries(0n, 1)).rejects.toMatchObject({
    code: "closed",
  } satisfies Partial<CllError>);
  await expect(
    backend.append({ value: value(8), appendedAt: at }),
  ).rejects.toMatchObject({ code: "closed" } satisfies Partial<CllError>);
  await backend.close();
}

export async function crossHandleContract(
  first: CllBackend,
  second: CllBackend,
): Promise<void> {
  const results = await Promise.all([
    first.append({ value: value(3), appendedAt: at }),
    second.append({ value: value(4), appendedAt: at }),
  ]);
  expect(new Set(results.map((item) => item.entry.seq))).toEqual(
    new Set([1n, 2n]),
  );
  expect(await first.scanEntries(0n, 10)).toHaveLength(2);
  expect(await second.scanEntries(0n, 10)).toHaveLength(2);
}
