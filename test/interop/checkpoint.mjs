import { readFile, writeFile } from "node:fs/promises";
import { createEd25519Identity } from "capsule-emit-ts";
import { MmrTree, signCheckpoint, verifyCheckpoint } from "../../dist/index.js";

const [mode, path] = process.argv.slice(2);
if ((mode !== "write" && mode !== "verify") || path === undefined) {
  throw new Error("usage: checkpoint.mjs <write|verify> <checkpoint.cose>");
}

if (mode === "write") {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const identity = createEd25519Identity(seed);
  const tree = new MmrTree();
  tree.append(Uint8Array.from({ length: 32 }, () => 0x11));
  const checkpoint = signCheckpoint({
    logId: "interop-log",
    mmrSize: tree.size,
    peaks: tree.peakHashes(),
    previousSize: 0n,
    previousPeaks: [],
    timestamp: "2026-08-27T12:34:56Z",
    identity,
  });
  await writeFile(path, checkpoint.cose, { mode: 0o600 });
} else if (!verifyCheckpoint(await readFile(path))) {
  throw new Error("TypeScript rejected checkpoint");
}
