#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { createFileSet, encryptBundle } from "./official-evaluator-core.mjs";
import {
  REVIEW_MODELS, buildAssessmentPrompt, buildAssessmentSchema, buildReviewIndex,
  normalizeAssessment, reconcilePropertyIdentity, sealCallReceipt, sha256, stableJson,
  validateCatalogModels, validateProtectedReviewerEnvironment, validateReviewDispatchRequest,
  validateReviewIndex, validateReviewRequest,
} from "./protected-refusal-review-core.mjs";

const command = process.argv[2];
if (command === "write-request") writeRequest();
else if (command === "verify-input-release") verifyInputRelease();
else if (command === "verify-source") verifySource();
else if (command === "review") await review();
else if (command === "validate-index") validateIndex();
else if (command === "encrypt-evidence") encryptEvidence();
else throw new Error("usage: protected-refusal-reviewer write-request|verify-input-release|verify-source|review|validate-index|encrypt-evidence");

function writeRequest() {
  const request = validateReviewDispatchRequest({
    schemaVersion: 1, kind: "spaceport-protected-refusal-review-request",
    requestId: requiredEnv("REQUEST_ID"), verifierPolicyTip: requiredEnv("VERIFIER_POLICY_TIP"),
    inputReleaseId: requiredEnv("INPUT_RELEASE_ID"), sourceAssetId: requiredEnv("SOURCE_ASSET_ID"),
    sourceBundleSha256: requiredEnv("SOURCE_BUNDLE_SHA256"), reviewRequestSha256: requiredEnv("REVIEW_REQUEST_SHA256"),
    requesterPublicKeyPemBase64: requiredEnv("REQUESTER_PUBLIC_KEY_PEM_BASE64"),
    requesterPublicKeySha256: requiredEnv("REQUESTER_PUBLIC_KEY_SHA256"),
  });
  const { hosted, requesterPublicKeyPem, ...stored } = request;
  writeFileSync(argument("--out"), `${JSON.stringify(stored, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, requestId: request.requestId, hosted })}\n`);
}

function verifyInputRelease() {
  const request = loadRequest();
  const release = JSON.parse(readFileSync(argument("--release"), "utf8"));
  const tag = `deed-refusal-review-input-${request.requestId}`;
  const asset = (release.assets || []).find((item) => String(item.id) === String(request.sourceAssetId));
  if (String(release.id) !== String(request.inputReleaseId) || release.tag_name !== tag || release.name !== tag
    || release.draft !== true || release.prerelease !== false || release.target_commitish !== request.verifierPolicyTip
    || !Array.isArray(release.assets) || release.assets.length !== 1 || asset?.name !== "source.bundle"
    || asset?.state !== "uploaded" || asset?.content_type !== "application/octet-stream" || !Number.isInteger(asset?.size)
    || asset.size < 9) throw new Error("Encrypted refusal-review input release or asset provenance is invalid.");
  process.stdout.write(`${JSON.stringify({ ok: true, releaseId: release.id, sourceAssetId: asset.id })}\n`);
}

function verifySource() {
  const request = loadRequest();
  const root = resolve(argument("--root"));
  const reviewPath = join(root, "review-request.json");
  const bytes = readFileSync(reviewPath);
  if (sha256(bytes) !== request.reviewRequestSha256) throw new Error("Review-request bytes do not match dispatch commitment.");
  const review = validateReviewRequest(JSON.parse(bytes), { requestId: request.requestId,
    root: (path) => readFileSync(safePath(root, path)) });
  const expected = new Set(["review-request.json", ...review.cases.map((item) => item.sourcePath)]);
  const receipt = JSON.parse(readFileSync(join(root, ".source-fileset-receipt.json"), "utf8"));
  const actual = new Set((receipt.files || []).map((file) => file.path));
  if (receipt.role !== "source" || receipt.requestId !== request.requestId || actual.size !== expected.size
    || [...expected].some((path) => !actual.has(path))) throw new Error("Materialized source role contains missing or extra files.");
  process.stdout.write(`${JSON.stringify({ ok: true, cases: review.cases.length, productCodeMounted: false })}\n`);
}

async function review() {
  const request = loadRequest();
  const root = resolve(argument("--root"));
  const out = resolve(argument("--out"));
  const tokenPath = resolve(argument("--token-file"));
  const challengePath = resolve(argument("--challenge-file"));
  const token = readFileSync(tokenPath, "utf8").trim();
  const challenge = readFileSync(challengePath);
  rmSync(tokenPath, { force: true }); rmSync(challengePath, { force: true });
  if (!token || challenge.length !== 32) throw new Error("Protected model token or workflow challenge is invalid.");
  const challengeSha256 = sha256(challenge);
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const reviewBytes = readFileSync(join(root, "review-request.json"));
  if (sha256(reviewBytes) !== request.reviewRequestSha256) throw new Error("Review request changed after dispatch.");
  const reviewRequest = validateReviewRequest(JSON.parse(reviewBytes), { requestId: request.requestId,
    root: (path) => readFileSync(safePath(root, path)) });
  const { text: catalogText, value: catalog } = await fetchCatalog(token);
  validateCatalogModels(catalog);
  writeFileSync(join(out, "github-models-catalog.json"), catalogText, { flag: "wx", mode: 0o600 });
  const catalogSha256 = sha256(catalogText);
  const caseResults = [];
  for (const candidate of reviewRequest.cases) {
    const caseOut = join(out, "cases", candidate.caseId);
    mkdirSync(caseOut, { recursive: true, mode: 0o700 });
    const images = renderAllPages(safePath(root, candidate.sourcePath), join(caseOut, "rendered"));
    if (images.length !== candidate.selector.pages.length) throw new Error(`Selector is not the complete PDF page set for ${candidate.caseId}.`);
    const calls = []; const assessments = [];
    for (const model of REVIEW_MODELS) {
      const modelOut = join(caseOut, slug(model.provider)); mkdirSync(modelOut, { recursive: true, mode: 0o700 });
      const schema = buildAssessmentSchema(images.length);
      const prompt = buildAssessmentPrompt({ requestId: request.requestId, challengeSha256, candidate, model });
      const imageManifest = images.map((image, index) => ({ page: index + 1, name: image.name,
        bytes: image.bytes.length, sha256: sha256(image.bytes) }));
      writeFileSync(join(modelOut, "prompt.txt"), `${prompt}\n`, { flag: "wx", mode: 0o600 });
      writeFileSync(join(modelOut, "schema.json"), `${JSON.stringify(schema, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      writeFileSync(join(modelOut, "images.json"), `${JSON.stringify(imageManifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      const sessionId = randomBytes(32);
      const result = await invokeModel({ token, model, prompt, schema, images });
      writeFileSync(join(modelOut, "raw-response.json"), result.raw, { flag: "wx", mode: 0o600 });
      const assessment = normalizeAssessment(result.output, candidate);
      const outputBytes = `${JSON.stringify(assessment, null, 2)}\n`;
      writeFileSync(join(modelOut, "output.json"), outputBytes, { flag: "wx", mode: 0o600 });
      const receipt = sealCallReceipt({
        requestId: request.requestId, caseId: candidate.caseId, challengeSha256,
        modelRequested: model.model, modelVersion: model.version, provider: model.provider,
        modelReturned: result.completion.model, callId: result.completion.id,
        sessionIdSha256: sha256(sessionId), promptSha256: sha256(`${prompt}\n`),
        schemaSha256: sha256(`${JSON.stringify(schema, null, 2)}\n`),
        imageManifestSha256: sha256(`${JSON.stringify(imageManifest, null, 2)}\n`),
        outputSha256: sha256(outputBytes), rawResponseSha256: sha256(result.raw),
        catalogSha256, catalogVersion: model.version, attempts: result.attempts, completedAt: new Date().toISOString(),
      });
      writeFileSync(join(modelOut, "call-receipt.json"), `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      calls.push(receipt); assessments.push(assessment);
    }
    if (new Set(calls.map((call) => call.modelReturned)).size !== 2) throw new Error("Returned model identities are not distinct.");
    const property = reconcilePropertyIdentity(assessments[0].propertyIdentity, assessments[1].propertyIdentity);
    writeFileSync(join(caseOut, "property-identity-evidence.json"), `${JSON.stringify(property.propertyIdentityEvidence, null, 2)}\n`,
      { flag: "wx", mode: 0o600 });
    caseResults.push({
      caseId: candidate.caseId, corpusId: candidate.corpusId,
      assignmentEventSha256: candidate.assignmentEventSha256, sourceSha256: candidate.sourceSha256,
      selectorSha256: candidate.selectorSha256,
      expectedFailureCandidateSha256: candidate.expectedFailureCandidateSha256,
      expectedFailureCode: candidate.expectedFailureCandidate.code,
      assessmentSha256s: assessments.map((assessment) => sha256(`${JSON.stringify(assessment, null, 2)}\n`)),
      callReceiptSha256s: calls.map((call) => call.receiptSha256), calls,
      propertyIdentityEvidenceSha256: property.propertyIdentityEvidenceSha256,
      propertyGroupSha256: property.propertyGroupSha256,
      status: "approved", critical: 0, major: 0,
    });
  }
  const hosted = validateProtectedReviewerEnvironment();
  const index = buildReviewIndex({ request, challengeSha256, catalogSha256, cases: caseResults, hosted });
  const indexPath = join(out, "review-index.json");
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  validateReviewIndex(index, request);
  process.stdout.write(`${JSON.stringify({ ok: true, cases: caseResults.length, reviewIndexSha256: sha256(readFileSync(indexPath)), indexPath })}\n`);
}

function validateIndex() {
  const request = loadRequest(); const bytes = readFileSync(argument("--index"));
  const index = JSON.parse(bytes); const result = validateReviewIndex(index, request);
  if (result.reviewIndexSha256 !== sha256(bytes)) throw new Error("Review index bytes are not canonical.");
  process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
}

function encryptEvidence() {
  const request = loadRequest(); const root = resolve(argument("--root"));
  const paths = listFiles(root); const fileSet = createFileSet({ role: "evidence", requestId: request.requestId, root, paths });
  const bytes = encryptBundle(fileSet, request.requesterPublicKeyPem, request.requesterPublicKeySha256);
  const out = argument("--out"); writeFileSync(out, bytes, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, files: fileSet.files.length, evidenceRootSha256: fileSet.fileRootSha256,
    encryptedBundleSha256: sha256(bytes), output: out })}\n`);
}

async function fetchCatalog(token) {
  const response = await fetch("https://models.github.ai/catalog/models", { headers: headers(token), signal: AbortSignal.timeout(60_000) });
  const text = await response.text(); if (!response.ok) throw new Error(`GitHub Models catalog returned HTTP ${response.status}.`);
  return { text, value: JSON.parse(text) };
}

async function invokeModel({ token, model, prompt, schema, images }) {
  const content = [{ type: "text", text: `${prompt}\n\nJSON schema:\n${JSON.stringify(schema)}` },
    ...images.map((image) => ({ type: "image_url", image_url: { url: `data:image/png;base64,${image.bytes.toString("base64")}`, detail: "high" } }))];
  const payload = { model: model.model, messages: [
    { role: "system", content: "Return only one JSON object. Inspect every image; never infer unreadable deed text." },
    { role: "user", content },
  ], response_format: { type: "json_object" }, temperature: 0, max_tokens: 10000 };
  for (let attempt = 1; attempt <= 8; attempt += 1) {
    const response = await fetch("https://models.github.ai/inference/chat/completions", {
      method: "POST", headers: { ...headers(token), "Content-Type": "application/json" },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(10 * 60_000),
    });
    const raw = await response.text();
    if (response.ok) {
      const completion = JSON.parse(raw); const contentValue = completion?.choices?.[0]?.message?.content;
      if (!completion?.id || !completion?.model || (typeof contentValue !== "string" && typeof contentValue !== "object")) {
        throw new Error("GitHub Models response omitted call, returned-model, or content identity.");
      }
      const output = typeof contentValue === "string" ? parseJsonObject(contentValue) : contentValue;
      return { raw, completion, output, attempts: attempt };
    }
    if (![408, 429, 500, 502, 503, 504].includes(response.status) || attempt === 8) {
      throw new Error(`GitHub Models ${model.model} returned HTTP ${response.status}: ${raw.slice(0, 500)}`);
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, Math.min(750 * (2 ** (attempt - 1)), 60_000)));
  }
  throw new Error("GitHub Models retry loop exhausted.");
}

function renderAllPages(pdf, out) {
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const info = execFileSync("pdfinfo", [pdf], { encoding: "utf8" });
  const pages = Number(/^Pages:\s+(\d+)$/m.exec(info)?.[1]);
  if (!Number.isInteger(pages) || pages < 1 || pages > 200) throw new Error("PDF page count is invalid.");
  execFileSync("pdftoppm", ["-png", "-r", "180", pdf, join(out, "page")], { stdio: ["ignore", "ignore", "pipe"], maxBuffer: 100 * 1024 * 1024 });
  const names = readdirSync(out).filter((name) => /^page-\d+\.png$/.test(name)).sort();
  if (names.length !== pages) throw new Error("Complete all-page rendering failed.");
  return names.map((name) => ({ name, bytes: readFileSync(join(out, name)) }));
}

function parseJsonObject(text) {
  const trimmed = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const value = JSON.parse(trimmed); if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Model output is not a JSON object.");
  return value;
}
function headers(token) { return { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2026-03-10" }; }
function loadRequest() { return validateReviewDispatchRequest(JSON.parse(readFileSync(argument("--request"), "utf8"))); }
function safePath(root, value) { const path = resolve(root, value); if (path === root || !path.startsWith(`${root}/`)) throw new Error("Path escaped review root."); return path; }
function listFiles(root) { return readdirSync(root, { withFileTypes: true }).flatMap((entry) => { const path = join(root, entry.name); if (entry.isDirectory()) return listFiles(path); if (!entry.isFile()) return []; if (statSync(path).size > 512 * 1024 * 1024) throw new Error("Evidence file exceeds limit."); return [path]; }).sort(); }
function slug(value) { return value.toLowerCase().replace(/[^a-z0-9]+/g, "-"); }
function argument(name) { const i = process.argv.indexOf(name); if (i < 0 || !process.argv[i + 1]) throw new Error(`missing ${name}`); return process.argv[i + 1]; }
function requiredEnv(name) { if (!process.env[name]) throw new Error(`missing ${name}`); return process.env[name]; }
