#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const SHA256 = /^[a-f0-9]{64}$/;
const ZERO = "0".repeat(64);
const KINDS = new Set([
  "legacy-quarantine",
  "assign",
  "truth-seal",
  "source-release",
  "consume",
  "execution-seal",
  "judge-challenge",
  "judge-seal",
]);

const fileIndex = process.argv.indexOf("--file");
const requestIndex = process.argv.indexOf("--request-base64url");
if (fileIndex < 0 || requestIndex < 0) throw new Error("usage: append-anchor --file anchors.json --request-base64url <request>");
const path = process.argv[fileIndex + 1];
const request = JSON.parse(Buffer.from(process.argv[requestIndex + 1], "base64url").toString("utf8"));
const log = JSON.parse(readFileSync(path, "utf8"));
validateLog(log);
const currentRoot = rootSha256(log);
const last = log.events.at(-1);
if (request?.schemaVersion !== 1 || !KINDS.has(request.kind)
  || request.expectedAnchorRootSha256 !== currentRoot
  || request.previousPrivateRegistryRootSha256 !== (last?.privateRegistryRootSha256 || ZERO)
  || !SHA256.test(request.privateRegistryRootSha256 || "")
  || request.privateRegistryRootSha256 === request.previousPrivateRegistryRootSha256
  || !Number.isInteger(request.privateRegistryEventCount) || request.privateRegistryEventCount <= (last?.privateRegistryEventCount || 0)
  || !SHA256.test(request.requestNonce || "")) {
  throw new Error("Anchor request is invalid, stale, non-monotonic, or disconnected from the latest public root.");
}
const event = {
  schemaVersion: 1,
  sequence: log.events.length + 1,
  previousAnchorEventSha256: last?.anchorEventSha256 || ZERO,
  previousPrivateRegistryRootSha256: request.previousPrivateRegistryRootSha256,
  privateRegistryRootSha256: request.privateRegistryRootSha256,
  privateRegistryEventCount: request.privateRegistryEventCount,
  kind: request.kind,
  requestNonce: request.requestNonce,
  issuedAt: new Date().toISOString(),
};
event.anchorEventSha256 = eventSha256(event);
log.events.push(event);
validateLog(log);
writeFileSync(path, `${JSON.stringify(log, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ ok: true, event, anchorRootSha256: rootSha256(log) }, null, 2)}\n`);

function validateLog(value) {
  if (value?.schemaVersion !== 1 || value.log !== "spaceport-deed-corpus-registry-roots"
    || value.sourceRepository !== "HansenHomeAI/Autodesk-automation" || !Array.isArray(value.events)) {
    throw new Error("Transparency log schema is invalid.");
  }
  let priorEvent = ZERO;
  let priorPrivate = ZERO;
  let priorCount = 0;
  let priorTime = -Infinity;
  for (let index = 0; index < value.events.length; index += 1) {
    const event = value.events[index] || {};
    const time = Date.parse(event.issuedAt || "");
    if (event.schemaVersion !== 1 || event.sequence !== index + 1 || event.previousAnchorEventSha256 !== priorEvent
      || event.previousPrivateRegistryRootSha256 !== priorPrivate || event.anchorEventSha256 !== eventSha256(event)
      || !SHA256.test(event.privateRegistryRootSha256 || "") || event.privateRegistryRootSha256 === priorPrivate
      || !Number.isInteger(event.privateRegistryEventCount) || event.privateRegistryEventCount <= priorCount
      || !KINDS.has(event.kind) || !SHA256.test(event.requestNonce || "") || !Number.isFinite(time) || time < priorTime) {
      throw new Error(`Transparency event ${index + 1} breaks the append-only chain.`);
    }
    priorEvent = event.anchorEventSha256;
    priorPrivate = event.privateRegistryRootSha256;
    priorCount = event.privateRegistryEventCount;
    priorTime = time;
  }
}
function eventSha256(event) { const copy = { ...event }; delete copy.anchorEventSha256; return sha256(stableJson(copy)); }
function rootSha256(value) { return sha256(stableJson(value)); }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
