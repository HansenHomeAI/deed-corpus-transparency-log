import { sha256 } from "./model-receipt.mjs";

// GitHub Models currently enforces an 8,000-input-token request cap for
// GPT-4.1. Six high-detail deed bands (about 2,550 x 1,900 each) leave bounded
// room for the transcription prompt and strict JSON schema. Larger source
// selections must be split/refused before inference, never optimistically sent.
export const MODEL_MAX_IMAGES = 6;
export const MODEL_MAX_IMAGE_BYTES = 25 * 1024 * 1024;
export const MODEL_MAX_AGGREGATE_IMAGE_BYTES = 128 * 1024 * 1024;

export function validateBrokerRequest(body, { maxAggregateBytes = MODEL_MAX_AGGREGATE_IMAGE_BYTES } = {}) {
  const allowed = new Set(["schemaVersion", "prompt", "schema", "images"]);
  if (Object.keys(body || {}).some((key) => !allowed.has(key)) || body?.schemaVersion !== 1
    || typeof body.prompt !== "string" || body.prompt.length < 1 || body.prompt.length > 100_000
    || !body.schema || typeof body.schema !== "object" || Array.isArray(body.schema)
    || !Array.isArray(body.images) || body.images.length < 1 || body.images.length > MODEL_MAX_IMAGES) {
    throw new Error("Broker request schema is invalid.");
  }
  let total = 0;
  const images = body.images.map((image) => {
    const allowedImage = new Set(["name", "mediaType", "bytes", "sha256", "contentBase64"]);
    if (Object.keys(image || {}).some((key) => !allowedImage.has(key)) || !/^[A-Za-z0-9._-]{1,180}\.png$/.test(image?.name || "")
      || image.mediaType !== "image/png" || !Number.isInteger(image.bytes) || image.bytes < 1 || image.bytes > MODEL_MAX_IMAGE_BYTES
      || !/^[a-f0-9]{64}$/.test(image.sha256 || "") || !canonicalBase64(image.contentBase64 || "")) {
      throw new Error("Broker image is malformed.");
    }
    const bytes = Buffer.from(image.contentBase64, "base64");
    total += bytes.length;
    if (bytes.length !== image.bytes || sha256(bytes) !== image.sha256 || total > maxAggregateBytes) {
      throw new Error("Broker image commitment or aggregate limit failed.");
    }
    return image;
  });
  return { prompt: body.prompt, schema: body.schema, images, aggregateImageBytes: total };
}

function canonicalBase64(value) { return typeof value === "string" && /^[A-Za-z0-9+/]*={0,2}$/.test(value) && Buffer.from(value, "base64").toString("base64") === value; }
