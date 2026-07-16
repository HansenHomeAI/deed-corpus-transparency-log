#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import { validateModelReceipt } from "./model-receipt.mjs";

const root = resolve(argument("--root"));
const output = resolve(argument("--out"));
const responsePath = join(root, "result.json");
const promptPath = `${responsePath}.prompt.txt`;
const receiptPath = `${responsePath}.model-receipt.json`;
const schemaPath = join(root, "schema.json");
const aggregatePath = join(root, "model-receipts.jsonl");
const images = Array.from({ length: 6 }, (_, index) => {
  const path = join(root, `smoke-${String(index).padStart(2, "0")}.png`);
  const content = readFileSync(path);
  return { name: basename(path), bytes: content.length, sha256: sha256(content) };
});
const receiptBytes = readFileSync(receiptPath);
const receipt = JSON.parse(receiptBytes.toString("utf8"));
const aggregateLines = readFileSync(aggregatePath, "utf8").trim().split(/\r?\n/).filter(Boolean);
if (aggregateLines.length !== 1 || stableJson(JSON.parse(aggregateLines[0])) !== stableJson(receipt)
  || receipt.sequence !== 1) throw new Error("Hosted smoke broker aggregate is missing, duplicated, or substituted.");
validateModelReceipt(receipt, {
  output: readFileSync(responsePath),
  prompt: readFileSync(promptPath),
  schema: JSON.parse(readFileSync(schemaPath, "utf8")),
  images,
  model: "openai/gpt-4.1",
  modelVersion: "2025-04-14",
});
const expected = new Set([
  "schema.json", "result.json", "result.json.prompt.txt", "result.json.model-receipt.json", "model-receipts.jsonl",
  ...images.map((image) => image.name),
]);
const actual = readdirSync(root).sort();
if (actual.length !== expected.size || actual.some((name) => !expected.has(name))) {
  throw new Error("Hosted smoke evidence contains missing or extra files.");
}
const files = actual.map((name) => {
  const bytes = readFileSync(join(root, name));
  return { path: name, bytes: bytes.length, sha256: sha256(bytes) };
});
const index = {
  schemaVersion: 1,
  kind: "spaceport-hosted-model-six-high-detail-band-smoke",
  repository: process.env.GITHUB_REPOSITORY,
  workflow: ".github/workflows/hosted-model-smoke.yml",
  workflowTip: process.env.GITHUB_SHA,
  workflowRunId: process.env.GITHUB_RUN_ID,
  runnerEnvironment: process.env.SPACEPORT_RUNNER_ENVIRONMENT,
  runnerOs: process.env.RUNNER_OS,
  model: "openai/gpt-4.1",
  modelCatalogVersion: "2025-04-14",
  imageCount: images.length,
  brokerReceiptSha256: receipt.receiptSha256,
  files,
  fileRootSha256: sha256(stableJson(files)),
};
if (index.repository !== "HansenHomeAI/deed-corpus-transparency-log"
  || !/^[a-f0-9]{40}$/.test(index.workflowTip || "") || !/^[1-9][0-9]*$/.test(index.workflowRunId || "")
  || index.runnerEnvironment !== "github-hosted" || index.runnerOs !== "macOS") {
  throw new Error("Hosted smoke environment is not the protected public macOS runner.");
}
writeFileSync(output, `${JSON.stringify(index, null, 2)}\n`, { flag: "wx", mode: 0o600 });
process.stdout.write(`${JSON.stringify({ ok: true, imageCount: 6, fileRootSha256: index.fileRootSha256 })}\n`);

function argument(name) { const index = process.argv.indexOf(name); if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`); return process.argv[index + 1]; }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value) { if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`; if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`; return JSON.stringify(value); }
