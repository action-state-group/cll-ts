import { build, createEd25519Identity, sign } from "capsule-emit-ts";
import { jcs } from "capsule-emit-ts/aac";
import { describe, expect, it } from "vitest";
import { LedgerService, MemoryStore } from "../src/index.js";

const at = new Date("2026-09-01T12:00:00Z");
const input = (actionId: string) => ({
  actionId,
  actionType: "fyi" as const,
  operator: "test",
  developer: "test@v1",
  timestamp: at,
});

describe("ledger service regressions", () => {
  it("isolates one decode failure during a whole-store audit", async () => {
    const store = new MemoryStore();
    const valid = build(input("valid"));
    const service = new LedgerService(store, {}, () => at);
    const validRecord = await service.append("unsigned", valid.json);
    await store.append({
      capsuleId: "aa".repeat(32),
      capsule: Uint8Array.of(0xff),
      authenticity: "unsigned",
      envelopes: [],
      verification: validRecord.verification,
      appendedAt: at,
    });
    const audit = await service.audit(10);
    expect(audit[0]?.result?.ok).toBe(true);
    expect(audit[1]?.error).toContain("UTF-8");
    await store.close();
  });

  it("retains store-level chain findings in audit results", async () => {
    const store = new MemoryStore();
    const service = new LedgerService(store, {}, () => at);
    const parent = "11".repeat(32);
    for (const actionId of ["child-a", "child-b"])
      await service.append(
        "unsigned",
        build({
          ...input(actionId),
          chain: { parentCapsuleId: parent, relation: "supersedes" },
        }).json,
      );
    const audit = await service.audit(10);
    expect(
      audit.flatMap((item) => item.result?.findings.map((f) => f.code) ?? []),
    ).toEqual(
      expect.arrayContaining(["chain_parent_missing", "concurrent_supersedes"]),
    );
    await store.close();
  });

  it("deduplicates the same explicit and embedded Producer Envelope", async () => {
    const store = new MemoryStore();
    const service = new LedgerService(store, {}, () => at);
    const identity = createEd25519Identity(new Uint8Array(32));
    const built = build(input("embedded-envelope"));
    const envelope = sign(built, identity);
    const capsule = jcs({
      ...built.value,
      signature: Buffer.from(envelope).toString("hex"),
      key_id: Buffer.from(identity.publicKey).toString("hex"),
    });
    const record = await service.append("signed", capsule, [envelope]);
    expect(record.envelopes).toHaveLength(1);
    await store.close();
  });
});
