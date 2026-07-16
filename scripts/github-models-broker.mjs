#!/usr/bin/env node

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { sealModelReceipt } from "./model-receipt.mjs";
import { validateBrokerRequest } from "./model-broker-contract.mjs";

const tokenFile = argument("--token-file");
const configPath = argument("--config");
const receiptPath = argument("--receipts");
const model = optionalArgument("--model") || "openai/gpt-4.1";
const expectedModelVersion = argument("--model-version");
const token = readFileSync(tokenFile, "utf8").trim();
if (!token) throw new Error("GitHub Models broker token file is empty.");
rmSync(tokenFile, { force: true });
const brokerSecret = randomBytes(32).toString("hex");
const catalog = await fetchCatalog(model, expectedModelVersion);
let sequence = 0;

const server = createServer(async (request, response) => {
  try {
    if (!loopback(request.socket.remoteAddress) || request.method !== "POST" || request.url !== "/v1/codex-vision") {
      return send(response, 404, { error: "not found" });
    }
    if (!secretMatches(request.headers.authorization, brokerSecret)) return send(response, 401, { error: "unauthorized" });
    const body = await readJsonBody(request, 450 * 1024 * 1024);
    const validated = validateBrokerRequest(body);
    const requestSequence = ++sequence;
    const content = [
      { type: "text", text: validated.prompt },
      ...validated.images.map((image) => ({
        type: "image_url",
        image_url: { url: `data:${image.mediaType};base64,${image.contentBase64}`, detail: "high" },
      })),
    ];
    const payload = {
      model,
      messages: [
        { role: "system", content: "Return only JSON that conforms exactly to the supplied response schema. Never infer unreadable deed text." },
        { role: "user", content },
      ],
      response_format: {
        type: "json_schema",
        json_schema: { name: "deed_transcription", strict: true, schema: validated.schema },
      },
      temperature: 0,
      max_tokens: 32768,
    };
    const { upstream, responseText, attempts } = await invokeModel(payload);
    const completion = JSON.parse(responseText);
    const output = completion?.choices?.[0]?.message?.content;
    if (typeof output !== "string" && (!output || typeof output !== "object")) {
      throw new Error("GitHub Models response omitted structured output.");
    }
    const outputText = JSON.stringify(typeof output === "string" ? JSON.parse(output) : output);
    const receipt = sealModelReceipt({
      schemaVersion: 1,
      kind: "github-models-multimodal-receipt",
      sequence: requestSequence,
      modelRequested: model,
      modelReturned: completion.model || null,
      systemFingerprint: completion.system_fingerprint || null,
      modelCatalogVersion: catalog.version,
      modelCatalogSha256: catalog.catalogSha256,
      promptSha256: sha256(validated.prompt),
      schemaSha256: sha256(stableJson(validated.schema)),
      images: validated.images.map((image) => ({ name: image.name, bytes: image.bytes, sha256: image.sha256 })),
      outputSha256: sha256(outputText),
      upstreamResponseSha256: sha256(responseText),
      rateLimit: rateLimitHeaders(upstream.headers),
      attempts,
      usage: sanitizeUsage(completion.usage),
      completedAt: new Date().toISOString(),
    });
    writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`, { flag: "a", mode: 0o600 });
    return send(response, 200, { output: outputText, receipt });
  } catch (error) {
    return send(response, 400, { error: error instanceof Error ? error.message : String(error) });
  }
});

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  writeFileSync(configPath, `${JSON.stringify({
    schemaVersion: 1,
    endpoint: `http://127.0.0.1:${address.port}/v1/codex-vision`,
    bearer: brokerSecret,
    model,
    modelVersion: catalog.version,
  })}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, port: address.port, model, configPath, receiptPath })}\n`);
});

async function fetchCatalog(modelId, expectedVersion) {
  const response = await fetch("https://models.github.ai/catalog/models", {
    headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2026-03-10" },
    signal: AbortSignal.timeout(60_000),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`GitHub Models catalog returned HTTP ${response.status}.`);
  const models = JSON.parse(text);
  const selected = models.find((candidate) => candidate?.id === modelId);
  if (!selected || selected.version !== expectedVersion || !selected.supported_input_modalities?.includes("image")
    || !selected.supported_output_modalities?.includes("text")) {
    throw new Error("Pinned GitHub Models id/version is absent or no longer multimodal.");
  }
  return { version: selected.version, catalogSha256: sha256(text) };
}

async function invokeModel(payload) {
  for (let attempt = 1; attempt <= 8; attempt += 1) {
    const upstream = await fetch("https://models.github.ai/inference/chat/completions", {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2026-03-10",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10 * 60 * 1000),
    });
    const responseText = await upstream.text();
    if (upstream.ok) return { upstream, responseText, attempts: attempt };
    if (![408, 429, 500, 502, 503, 504].includes(upstream.status) || attempt === 8) {
      throw new Error(`GitHub Models returned HTTP ${upstream.status}: ${responseText.slice(0, 300)}`);
    }
    const retryAfter = Number(upstream.headers.get("retry-after"));
    const delay = Number.isFinite(retryAfter) && retryAfter > 0
      ? Math.min(retryAfter * 1000, 120_000)
      : Math.min(750 * (2 ** (attempt - 1)), 60_000) + Math.floor(Math.random() * 500);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }
  throw new Error("GitHub Models retry loop exhausted.");
}

function sanitizeUsage(usage) {
  if (!usage || typeof usage !== "object") return null;
  return Object.fromEntries(Object.entries(usage).filter(([key, value]) => /^[a-z_]+$/.test(key) && Number.isFinite(value)));
}
function rateLimitHeaders(headers) { return Object.fromEntries([...headers.entries()].filter(([key, value]) => (key.startsWith("x-ratelimit-") || key === "retry-after") && value)); }

async function readJsonBody(request, limit) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > limit) throw new Error("Broker request exceeds byte limit.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function secretMatches(header, expected) {
  const actual = String(header || "").replace(/^Bearer /, "");
  const left = Buffer.from(actual); const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function loopback(address) { return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1"; }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value) { if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`; if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`; return JSON.stringify(value); }
function send(response, status, value) { response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" }); response.end(`${JSON.stringify(value)}\n`); }
function argument(name) { const index = process.argv.indexOf(name); if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`); return process.argv[index + 1]; }
function optionalArgument(name) { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; }
