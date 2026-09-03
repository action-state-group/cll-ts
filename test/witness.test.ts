import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpWitnessClient, CllError, limits } from "../src/index.js";

const client = () =>
  new HttpWitnessClient("anchor", new URL("https://anchor.example"), 1_000);
const response = (
  body: string | ReadableStream<Uint8Array>,
  status = 200,
): Response =>
  new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });

afterEach(() => vi.unstubAllGlobals());

describe("capsule-anchor HTTP client", () => {
  it("bounds a streaming receipt before buffering it", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(limits.receipt));
        controller.enqueue(Uint8Array.of(0));
        controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response(body)),
    );
    await expect(client().submit(Uint8Array.of(1))).rejects.toMatchObject({
      code: "rejected",
      message: "witness response too large",
    } satisfies Partial<CllError>);
  });

  it.each([408, 429, 500, 503])(
    "classifies HTTP %i as retryable contention",
    async (status) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => response("failure", status)),
      );
      await expect(client().submit(Uint8Array.of(1))).rejects.toMatchObject({
        code: "contention",
      } satisfies Partial<CllError>);
    },
  );

  it("classifies other 4xx responses as permanent rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response("failure", 400)),
    );
    await expect(client().submit(Uint8Array.of(1))).rejects.toMatchObject({
      code: "rejected",
    } satisfies Partial<CllError>);
  });

  it("does not follow witness redirects", async () => {
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) =>
        response("redirect", 302),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(client().submit(Uint8Array.of(1))).rejects.toMatchObject({
      code: "rejected",
    } satisfies Partial<CllError>);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
  });

  it.each([
    "ftp://anchor.example",
    "https://user@anchor.example",
    "https://anchor.example?query=1",
    "https://anchor.example#fragment",
  ])("rejects an unsafe base URL %s", (url) => {
    expect(() => new HttpWitnessClient("anchor", new URL(url))).toThrow(
      "witness base URL",
    );
  });

  it.each([
    ["not JSON", "invalid witness JSON response"],
    [
      JSON.stringify({
        entry_hash_scheme: "legacy",
        entry_hash: "11".repeat(32),
        tree_size: 1,
        leaf_index: 0,
        receipt_b64: "x===",
      }),
      "invalid witness receipt_b64",
    ],
    [
      JSON.stringify({
        entry_hash_scheme: "legacy",
        entry_hash: "11".repeat(32),
        tree_size: 1,
        leaf_index: 1,
        receipt_b64: "AQ==",
      }),
      "invalid witness tree position",
    ],
  ])("rejects malformed success payloads", async (body, message) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response(body)),
    );
    await expect(client().submit(Uint8Array.of(1))).rejects.toMatchObject({
      code: "rejected",
      message,
    } satisfies Partial<CllError>);
  });
});
