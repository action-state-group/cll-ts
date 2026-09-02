import {
  asJsonObject,
  decodeCapsuleJson,
  sha256Hex,
  verifyClass1,
  verifyStore,
  type ParsedJson,
  type VerificationResult,
} from "capsule-emit-ts/aac";
import { verifyEnvelope } from "capsule-emit-ts";
import {
  LedgerError,
  limits,
  type AdmissionMode,
  type Envelope,
  type Record,
  type Store,
} from "./types.js";

const hex64 = /^[0-9a-f]{64}$/u;
const utcNow = (): Date => new Date();

export class LedgerService {
  public constructor(
    private readonly store: Store,
    private readonly registryExtensions: Readonly<
      globalThis.Record<string, ReadonlySet<string>>
    > = {},
    private readonly clock: () => Date = utcNow,
  ) {}
  public async append(
    mode: AdmissionMode,
    capsule: Uint8Array,
    envelopes: readonly Uint8Array[] = [],
  ): Promise<Record> {
    if (mode !== "signed" && mode !== "unsigned")
      throw new LedgerError(
        "invalid",
        "admission mode must be unsigned or signed",
      );
    if (capsule.length < 1 || capsule.length > limits.capsule)
      throw new LedgerError("invalid", "Capsule size is invalid");
    if (mode === "unsigned" && envelopes.length !== 0)
      throw new LedgerError(
        "admission_rejected",
        "unsigned admission rejects Producer Envelopes",
      );
    const decoded = decodeCapsuleJson(capsule);
    const verification = verifyClass1(
      decoded,
      undefined,
      this.registryExtensions,
    );
    if (!verification.ok || verification.capsuleId === undefined)
      throw new LedgerError(
        "admission_rejected",
        "Capsule failed AAC Class 1 verification",
      );
    const capsuleId = verification.capsuleId;
    const valid: Envelope[] = [];
    const addValid = (candidate: Envelope): void => {
      const existing = valid.find((item) => item.digest === candidate.digest);
      if (existing === undefined) {
        valid.push(candidate);
        return;
      }
      if (!Buffer.from(existing.bytes).equals(Buffer.from(candidate.bytes)))
        throw new LedgerError(
          "immutable_conflict",
          `envelope digest collision for ${candidate.digest}`,
        );
    };
    if (mode === "signed") {
      for (const bytes of envelopes) {
        const checked = verifyEnvelope(capsuleId, bytes);
        if (!checked.ok) continue;
        addValid({
          digest: sha256Hex(bytes),
          bytes: Uint8Array.from(bytes),
          verification: checked,
          addedAt: this.clock(),
        });
      }
      const signature =
        typeof decoded.signature === "string" &&
        /^[0-9a-f]+$/u.test(decoded.signature)
          ? Buffer.from(decoded.signature, "hex")
          : undefined;
      const keyId =
        typeof decoded.key_id === "string" &&
        /^[0-9a-f]{64}$/u.test(decoded.key_id)
          ? decoded.key_id
          : undefined;
      if (signature !== undefined && keyId !== undefined) {
        const checked = verifyEnvelope(capsuleId, signature);
        if (
          checked.ok &&
          checked.publicKey !== undefined &&
          Buffer.from(checked.publicKey).toString("hex") === keyId
        )
          addValid({
            digest: sha256Hex(signature),
            bytes: signature,
            verification: checked,
            addedAt: this.clock(),
          });
      }
      if (valid.length === 0)
        throw new LedgerError(
          "admission_rejected",
          "signed admission requires one valid Producer Envelope",
        );
    }
    const chain = asJsonObject(decoded.chain);
    const parentId =
      chain !== undefined &&
      typeof chain.parent_capsule_id === "string" &&
      hex64.test(chain.parent_capsule_id)
        ? chain.parent_capsule_id
        : undefined;
    return (
      await this.store.append({
        capsuleId,
        capsule: Uint8Array.from(capsule),
        authenticity: mode,
        envelopes: valid,
        verification,
        ...(parentId === undefined ? {} : { parentId }),
        appendedAt: this.clock(),
      })
    ).record;
  }
  public async addEnvelope(
    capsuleId: string,
    bytes: Uint8Array,
  ): Promise<Envelope> {
    const checked = verifyEnvelope(capsuleId, bytes);
    if (!checked.ok)
      throw new LedgerError(
        "admission_rejected",
        "Producer Envelope verification failed",
      );
    return (
      await this.store.addEnvelope({
        capsuleId,
        envelope: {
          digest: sha256Hex(bytes),
          bytes: Uint8Array.from(bytes),
          verification: checked,
          addedAt: this.clock(),
        },
      })
    ).envelope;
  }
  public get(capsuleId: string) {
    return this.store.get(capsuleId);
  }
  public scan(after = 0n, limit = limits.scanDefault) {
    return this.store.scan(after, limit);
  }
  public scanIds(after = 0n, limit = limits.scanDefault) {
    return this.store.scanIds(after, limit);
  }
  public findChainGaps() {
    return this.store.findChainGaps();
  }
  public async audit(bound: number): Promise<
    readonly {
      readonly seq: bigint;
      readonly capsuleId: string;
      readonly result?: VerificationResult;
      readonly error?: string;
    }[]
  > {
    if (bound < 1 || bound > limits.scanMax)
      throw new LedgerError("invalid", "invalid audit bound");
    const records = await this.store.scan(0n, bound);
    if (
      records.length === bound &&
      (await this.store.scan(BigInt(bound), 1)).length !== 0
    )
      throw new LedgerError("invalid", "ledger exceeds audit bound");
    const decoded: Array<ParsedJson | undefined> = [];
    const errors: Array<string | undefined> = [];
    for (const record of records)
      try {
        decoded.push(decodeCapsuleJson(record.capsule));
        errors.push(undefined);
      } catch (error) {
        decoded.push(undefined);
        errors.push(String(error));
      }
    const valid = decoded.filter(
      (value): value is ParsedJson => value !== undefined,
    );
    const verified = verifyStore(valid, this.registryExtensions);
    let verifiedIndex = 0;
    return records.map((record, index) => {
      const error = errors[index];
      if (error !== undefined)
        return { seq: record.seq, capsuleId: record.capsuleId, error };
      return {
        seq: record.seq,
        capsuleId: record.capsuleId,
        result: verified[verifiedIndex++]!,
      };
    });
  }
}
