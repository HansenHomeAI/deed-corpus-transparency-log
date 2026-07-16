#!/usr/bin/env node

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  createFileSet,
  encryptBundle,
  INPUT_RELEASE_REPOSITORY,
  sha256,
  stableJson,
  validateEvaluationRequest,
  validateExecutionIndexForAttestation,
} from "./official-evaluator-core.mjs";

const command = process.argv[2];
if (command === "write-request") {
  const request = validateEvaluationRequest({
    schemaVersion: 1,
    requestId: requiredEnv("REQUEST_ID"),
    mode: requiredEnv("EVALUATION_MODE"),
    campaign: requiredEnv("CAMPAIGN"),
    productCodeTip: requiredEnv("PRODUCT_CODE_TIP"),
    verifierPolicyTip: requiredEnv("VERIFIER_POLICY_TIP"),
    inputReleaseId: requiredEnv("INPUT_RELEASE_ID"),
    sourceAssetId: requiredEnv("SOURCE_ASSET_ID"),
    sourceBundleSha256: requiredEnv("SOURCE_BUNDLE_SHA256"),
    truthAssetId: requiredEnv("TRUTH_ASSET_ID"),
    truthBundleSha256: requiredEnv("TRUTH_BUNDLE_SHA256"),
    requesterPublicKeyPemBase64: requiredEnv("REQUESTER_PUBLIC_KEY_PEM_BASE64"),
    requesterPublicKeySha256: requiredEnv("REQUESTER_PUBLIC_KEY_SHA256"),
  });
  const { hosted, requesterPublicKeyPem, ...publicRequest } = request;
  writeFileSync(argument("--out"), `${JSON.stringify(publicRequest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, requestId: request.requestId, hosted })}\n`);
} else if (command === "verify-input-release") {
  const request = loadRequest();
  const release = JSON.parse(readFileSync(argument("--release"), "utf8"));
  const expectedTag = `deed-evaluator-input-${request.requestId}`;
  const source = (release.assets || []).find((asset) => String(asset.id) === String(request.sourceAssetId));
  const truth = (release.assets || []).find((asset) => String(asset.id) === String(request.truthAssetId));
  if (String(release.id) !== String(request.inputReleaseId) || release.tag_name !== expectedTag || release.name !== expectedTag
    || release.draft !== true || release.prerelease !== false || release.target_commitish !== request.verifierPolicyTip
    || !Array.isArray(release.assets) || release.assets.length !== 2
    || !assetOk(source, "source.bundle", expectedTag) || !assetOk(truth, "truth.bundle", expectedTag)) {
    throw new Error("Encrypted input release or asset provenance is invalid.");
  }
  process.stdout.write(`${JSON.stringify({ ok: true, releaseId: release.id, tag: expectedTag,
    sourceAssetId: source.id, truthAssetId: truth.id })}\n`);
} else if (command === "verify-source") {
  const request = loadRequest();
  const root = resolve(argument("--root"));
  const manifestPath = join(root, "private-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.cohort !== request.mode || manifest.codeTip !== request.productCodeTip
    || !Array.isArray(manifest.entries) || manifest.entries.length !== (request.mode === "final" ? 50 : manifest.entries.length)
    || (request.mode === "fail-safe" && manifest.entries.length < 20)
    || manifest.entries.some((entry) => request.mode === "final"
      ? entry.expectedOutcome !== "positive"
      : entry.expectedOutcome !== "refusal" || !entry.expectedFailureCode)) {
    throw new Error("Source manifest does not match the requested official evaluation mode and product tip.");
  }
  for (const entry of manifest.entries) {
    const source = privatePath(root, entry?.source?.path);
    const truth = privatePath(root, entry?.truth?.path);
    const bytes = readFileSync(source);
    if (sha256(bytes) !== entry.source.sha256 || bytes.length !== entry.source.bytes) throw new Error("Source bytes fail the manifest commitment.");
    try { readFileSync(truth); throw new Error("Truth bytes were mounted during the source-only execution phase."); }
    catch (error) { if (error?.code !== "ENOENT") throw error; }
  }
  const expected = new Set(["private-manifest.json", ...manifest.entries.map((entry) => entry.source.path)]);
  if (request.mode === "final") expected.add("intake-seal.json");
  verifyMaterializedRole(root, "source", request.requestId, expected);
  process.stdout.write(`${JSON.stringify({ ok: true, manifestPath, cohort: manifest.cohort, entries: manifest.entries.length, truthMounted: false })}\n`);
} else if (command === "verify-truth") {
  const request = loadRequest();
  const root = resolve(argument("--root"));
  const manifest = JSON.parse(readFileSync(join(root, "private-manifest.json"), "utf8"));
  if (manifest.cohort !== request.mode || manifest.codeTip !== request.productCodeTip) throw new Error("Truth verification request does not match manifest.");
  for (const entry of manifest.entries) {
    const source = readFileSync(privatePath(root, entry.source.path));
    const truth = readFileSync(privatePath(root, entry.truth.path));
    if (sha256(source) !== entry.source.sha256 || source.length !== entry.source.bytes
      || sha256(truth) !== entry.truth.sha256 || truth.length !== entry.truth.bytes) {
      throw new Error("Post-seal source or truth bytes fail the frozen manifest commitment.");
    }
  }
  const expected = new Set();
  for (const entry of manifest.entries) {
    expected.add(entry.truth.path);
    const truthPath = privatePath(root, entry.truth.path);
    const truth = JSON.parse(readFileSync(truthPath, "utf8"));
    for (const record of [...(truth.receiptFiles || []), ...(truth.evidenceFiles || [])]) {
      if (!record || typeof record.path !== "string") throw new Error("Truth packet evidence path is invalid.");
      const absolute = resolve(dirname(truthPath), record.path);
      if (absolute === root || !absolute.startsWith(`${root}${sep}`)) throw new Error("Truth packet evidence path escaped the evaluation root.");
      expected.add(relative(root, absolute).split(sep).join("/"));
    }
  }
  verifyMaterializedRole(root, "truth", request.requestId, expected);
  process.stdout.write(`${JSON.stringify({ ok: true, entries: manifest.entries.length, truthMounted: true })}\n`);
} else if (command === "validate-index") {
  const request = loadRequest();
  const bytes = readFileSync(argument("--index"));
  const validation = validateExecutionIndexForAttestation(bytes, request);
  const manifest = JSON.parse(readFileSync(join(resolve(argument("--root")), "private-manifest.json"), "utf8"));
  if (validation.executionCount !== manifest.entries?.length * 3) {
    throw new Error("Execution index does not contain exactly three trials for every frozen manifest entry.");
  }
  process.stdout.write(`${JSON.stringify({ ok: true, ...validation }, null, 2)}\n`);
} else if (command === "encrypt-evidence") {
  const request = loadRequest();
  const root = resolve(argument("--root"));
  const manifest = JSON.parse(readFileSync(join(root, "private-manifest.json"), "utf8"));
  const excluded = new Set((manifest.entries || []).flatMap((entry) => [entry?.source?.path, entry?.truth?.path])
    .filter((path) => typeof path === "string").map((path) => privatePath(root, path)));
  const truthReceipt = JSON.parse(readFileSync(join(root, ".truth-fileset-receipt.json"), "utf8"));
  for (const file of truthReceipt.files || []) excluded.add(privatePath(root, file.path));
  const paths = listFiles(root).filter((path) => !excluded.has(path));
  const fileSet = createFileSet({ role: "evidence", requestId: request.requestId, root, paths });
  const bytes = encryptBundle(fileSet, Buffer.from(request.requesterPublicKeyPemBase64, "base64").toString("utf8"),
    request.requesterPublicKeySha256);
  const output = argument("--out");
  writeFileSync(output, bytes, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, requestId: request.requestId, files: fileSet.files.length,
    evidenceRootSha256: fileSet.fileRootSha256, encryptedBundleSha256: sha256(bytes), output })}\n`);
} else {
  throw new Error("usage: official-deed-evaluator write-request|verify-source|verify-truth|validate-index|encrypt-evidence ...");
}

function loadRequest() { return validateEvaluationRequest(JSON.parse(readFileSync(argument("--request"), "utf8"))); }
function privatePath(root, value) {
  if (typeof value !== "string" || !value || isAbsolute(value)) throw new Error("Manifest private path is invalid.");
  const path = resolve(root, value);
  if (path === root || !path.startsWith(`${root}${sep}`)) throw new Error("Manifest private path escaped the evaluation root.");
  return path;
}
function listFiles(root) {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    if (entry.isDirectory()) return listFiles(path);
    if (!entry.isFile()) return [];
    if (statSync(path).size > 512 * 1024 * 1024) throw new Error(`Evidence file exceeds byte limit: ${relative(root, path)}`);
    return [path];
  }).sort();
}
function verifyMaterializedRole(root, role, requestId, expectedPaths) {
  const receipt = JSON.parse(readFileSync(join(root, `.${role}-fileset-receipt.json`), "utf8"));
  const files = receipt.files?.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })) || [];
  const actual = new Set(files.map((file) => file.path));
  if (receipt.schemaVersion !== 1 || receipt.kind !== "spaceport-deed-evaluator-materialized-file-set"
    || receipt.role !== role || receipt.requestId !== requestId
    || receipt.fileRootSha256 !== sha256(stableJson([...files].sort((left, right) => left.path.localeCompare(right.path))))
    || actual.size !== files.length || actual.size !== expectedPaths.size
    || [...expectedPaths].some((path) => !actual.has(path))) {
    throw new Error(`Materialized ${role} file set contains missing, extra, replayed, or substituted paths.`);
  }
}
function assetOk(asset, name, tag) {
  return asset?.name === name && asset.state === "uploaded" && asset.content_type === "application/octet-stream"
    && Number.isInteger(asset.size) && asset.size > 8
    && asset.url === `https://api.github.com/repos/${INPUT_RELEASE_REPOSITORY}/releases/assets/${asset.id}`
    && asset.browser_download_url === `https://github.com/${INPUT_RELEASE_REPOSITORY}/releases/download/${tag}/${name}`;
}
function argument(name) { const index = process.argv.indexOf(name); if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`); return process.argv[index + 1]; }
function requiredEnv(name) { if (!process.env[name]) throw new Error(`missing ${name}`); return process.env[name]; }
