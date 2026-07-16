import { createHash } from "node:crypto";

const SHA256 = /^[a-f0-9]{64}$/;

export function sealModelReceipt(body) {
  const copy = structuredClone(body);
  delete copy.receiptSha256;
  return { ...copy, receiptSha256: sha256(stableJson(copy)) };
}

export function validateModelReceipt(receipt, { output, prompt, schema, images, model, modelVersion } = {}) {
  const allowed = new Set([
    "schemaVersion", "kind", "sequence", "modelRequested", "modelReturned", "systemFingerprint",
    "modelCatalogVersion", "modelCatalogSha256", "promptSha256", "schemaSha256", "images",
    "outputSha256", "upstreamResponseSha256", "rateLimit", "attempts", "usage", "completedAt", "receiptSha256",
  ]);
  const body = { ...receipt }; delete body.receiptSha256;
  const expectedImages = (images || []).map(({ name, bytes, sha256 }) => ({ name, bytes, sha256 }));
  if (Object.keys(receipt || {}).some((key) => !allowed.has(key))
    || receipt?.schemaVersion !== 1 || receipt.kind !== "github-models-multimodal-receipt"
    || !Number.isInteger(receipt.sequence) || receipt.sequence < 1
    || receipt.modelRequested !== model || typeof receipt.modelReturned !== "string" || !receipt.modelReturned
    || receipt.modelCatalogVersion !== modelVersion || !SHA256.test(receipt.modelCatalogSha256 || "")
    || receipt.promptSha256 !== sha256(prompt || "") || receipt.schemaSha256 !== sha256(stableJson(schema))
    || stableJson(receipt.images) !== stableJson(expectedImages)
    || receipt.outputSha256 !== sha256(output || "") || !SHA256.test(receipt.upstreamResponseSha256 || "")
    || !validRateLimit(receipt.rateLimit)
    || !Number.isInteger(receipt.attempts) || receipt.attempts < 1 || receipt.attempts > 8
    || !validIso(receipt.completedAt) || receipt.receiptSha256 !== sha256(stableJson(body))) {
    throw new Error("GitHub Models receipt is missing, substituted, or does not bind the exact prompt/schema/images/output.");
  }
  return receipt;
}

export function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
export function stableJson(value) { if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`; if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`; return JSON.stringify(value); }
function validIso(value) { return typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value; }
function validRateLimit(value) { return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length > 0 && Object.entries(value).every(([key, item]) => /^(x-ratelimit-[a-z-]+|retry-after)$/.test(key) && typeof item === "string" && item.length > 0); }
