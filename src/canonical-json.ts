const encoder = new TextEncoder();

function render(value: unknown): string {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value))
      throw new TypeError("canonical JSON only accepts safe integers");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) return `[${value.map(render).join(",")}]`;
  if (typeof value !== "object" || value === undefined)
    throw new TypeError("unsupported canonical JSON value");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${render(record[key])}`)
    .join(",")}}`;
}

/** RFC 8785 bytes for the integer-only checkpoint projection. */
export const canonicalJson = (value: unknown): Uint8Array =>
  encoder.encode(render(value));
