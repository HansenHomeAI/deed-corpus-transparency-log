import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  createFileSet,
  decryptBundle,
  encryptBundle,
  materializeFileSet,
  OFFICIAL_WORKFLOW_REF,
  sha256,
  stableJson,
  validateEvaluationRequest,
  validateExecutionIndexForAttestation,
  validateFileSet,
  validateHostedEnvironment,
} from "./official-evaluator-core.mjs";
import { sealModelReceipt, validateModelReceipt } from "./model-receipt.mjs";
import { MODEL_MAX_AGGREGATE_IMAGE_BYTES, MODEL_MAX_IMAGES, validateBrokerRequest } from "./model-broker-contract.mjs";

const repository = resolve(import.meta.dirname, "..");
const workflow = readFileSync(join(repository, ".github/workflows/official-deed-evaluator.yml"), "utf8");
const shimSource = readFileSync(join(repository, "scripts/codex-models-shim.mjs"), "utf8");
const evaluator = join(repository, "scripts/official-deed-evaluator.mjs");
const deedBundle = join(repository, "scripts/deed-bundle.mjs");
const keys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const hostedEnv = {
  GITHUB_ACTIONS: "true",
  GITHUB_REPOSITORY: "HansenHomeAI/deed-corpus-transparency-log",
  RUNNER_OS: "macOS",
  SPACEPORT_RUNNER_ENVIRONMENT: "github-hosted",
  SPACEPORT_EVALUATOR_WORKFLOW_REF: OFFICIAL_WORKFLOW_REF,
  GITHUB_SHA: "a".repeat(40), GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1",
};
const request = {
  schemaVersion: 1,
  requestId: "b".repeat(64), mode: "final", campaign: "final",
  productCodeTip: "c".repeat(40), verifierPolicyTip: hostedEnv.GITHUB_SHA,
  inputReleaseId: "99", sourceAssetId: "100", sourceBundleSha256: "d".repeat(64),
  truthAssetId: "101", truthBundleSha256: "e".repeat(64),
  requesterPublicKeyPemBase64: Buffer.from(keys.publicKey).toString("base64"),
  requesterPublicKeySha256: sha256(Buffer.from(keys.publicKey)),
};

test("hosted environment and request require exact public main policy identity", () => {
  assert.equal(validateHostedEnvironment(hostedEnv).ok, true);
  assert.equal(validateEvaluationRequest(request, { env: hostedEnv }).hosted.verifierPolicyTip, hostedEnv.GITHUB_SHA);
  for (const patch of [
    { GITHUB_ACTIONS: "false" }, { GITHUB_REPOSITORY: "attacker/repo" }, { RUNNER_OS: "Linux" },
    { SPACEPORT_RUNNER_ENVIRONMENT: "self-hosted" }, { SPACEPORT_EVALUATOR_WORKFLOW_REF: "attacker/workflow" },
    { GITHUB_SHA: "f".repeat(40) },
  ]) {
    assert.throws(() => validateEvaluationRequest(request, { env: { ...hostedEnv, ...patch } }));
  }
  assert.throws(() => validateEvaluationRequest({ ...request, verifierPolicyTip: "f".repeat(40) }, { env: hostedEnv }));
  assert.throws(() => validateEvaluationRequest({ ...request, truthAssetId: request.sourceAssetId }, { env: hostedEnv }));
  assert.throws(() => validateEvaluationRequest({ ...request, truthBundleSha256: request.sourceBundleSha256 }, { env: hostedEnv }));
  assert.throws(() => validateEvaluationRequest({ ...request, campaign: "replacement-final" }, { env: hostedEnv }));
  assert.throws(() => validateEvaluationRequest({ ...request, requesterPublicKeySha256: "0".repeat(64) }, { env: hostedEnv }));
});

test("hybrid bundle round trips committed bytes and rejects tamper, replay, wrong role, and wrong key", () => {
  const root = mkdtempSync(join(tmpdir(), "deed-bundle-source-"));
  mkdirSync(join(root, "sources"));
  writeFileSync(join(root, "sources", "one.pdf"), "%PDF-1.7\nprivate deed\n");
  const fileSet = createFileSet({ role: "source", requestId: request.requestId, root, paths: [join(root, "sources", "one.pdf")] });
  const encrypted = encryptBundle(fileSet, keys.publicKey, "bundle-key-1");
  const decrypted = decryptBundle(encrypted, keys.privateKey, "bundle-key-1", { expectedRole: "source", expectedRequestId: request.requestId });
  assert.deepEqual(decrypted, fileSet);
  const output = mkdtempSync(join(tmpdir(), "deed-bundle-output-"));
  materializeFileSet(decrypted, output, { expectedRole: "source", expectedRequestId: request.requestId });
  assert.equal(readFileSync(join(output, "sources", "one.pdf"), "utf8"), "%PDF-1.7\nprivate deed\n");

  const tampered = Buffer.from(encrypted); tampered[tampered.length - 1] ^= 1;
  assert.throws(() => decryptBundle(tampered, keys.privateKey, "bundle-key-1"), /authentication/);
  assert.throws(() => decryptBundle(encrypted, keys.privateKey, "wrong-key-id"), /key id/);
  assert.throws(() => decryptBundle(encrypted, keys.privateKey, "bundle-key-1", { expectedRole: "truth" }), /schema/);
  assert.throws(() => decryptBundle(encrypted, keys.privateKey, "bundle-key-1", { expectedRequestId: "f".repeat(64) }), /schema/);
  const other = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  assert.throws(() => decryptBundle(encrypted, other.privateKey, "bundle-key-1"), /unwrap/);
});

test("bundle CLI writes a role-bound materialization receipt for exact-path boundary checks", () => {
  const root = mkdtempSync(join(tmpdir(), "deed-bundle-cli-"));
  mkdirSync(join(root, "sources")); writeFileSync(join(root, "sources", "one.pdf"), "%PDF-1.7\n");
  const publicKey = join(root, "public.pem"); const privateKey = join(root, "private.pem");
  writeFileSync(publicKey, keys.publicKey); writeFileSync(privateKey, keys.privateKey);
  const paths = join(root, "paths.json"); writeFileSync(paths, JSON.stringify(["sources/one.pdf"]));
  const bundle = join(root, "source.bundle");
  let child = spawnSync(process.execPath, [deedBundle, "pack", "--role", "source", "--request-id", request.requestId,
    "--root", root, "--paths-json", paths, "--public-key", publicKey, "--key-id", "bundle-key", "--out", bundle], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  const output = mkdtempSync(join(tmpdir(), "deed-bundle-cli-output-"));
  child = spawnSync(process.execPath, [deedBundle, "unpack", "--bundle", bundle, "--private-key", privateKey,
    "--key-id", "bundle-key", "--role", "source", "--request-id", request.requestId, "--out", output], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  const receipt = JSON.parse(readFileSync(join(output, ".source-fileset-receipt.json"), "utf8"));
  assert.deepEqual(receipt.files.map((file) => file.path), ["sources/one.pdf"]);
  assert.equal(receipt.requestId, request.requestId);
});

test("file sets reject traversal, duplicate paths, malformed bytes, and replacement", () => {
  const valid = {
    schemaVersion: 1, kind: "spaceport-deed-evaluator-file-set", role: "truth", requestId: request.requestId,
    files: [{ path: "truth/one.json", bytes: 2, sha256: sha256("{}"), contentBase64: Buffer.from("{}").toString("base64") }],
  };
  valid.fileRootSha256 = sha256(stableJson(valid.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 }))));
  assert.equal(validateFileSet(valid).role, "truth");
  assert.throws(() => validateFileSet({ ...valid, files: [{ ...valid.files[0], path: "../one" }] }), /unsafe/);
  assert.throws(() => validateFileSet({ ...valid, files: [valid.files[0], valid.files[0]] }), /unsafe/);
  assert.throws(() => validateFileSet({ ...valid, files: [{ ...valid.files[0], bytes: 3 }] }), /commitment/);
  const output = mkdtempSync(join(tmpdir(), "deed-bundle-replace-"));
  mkdirSync(join(output, "truth")); writeFileSync(join(output, "truth", "one.json"), "occupied");
  assert.throws(() => materializeFileSet(valid, output), /replace/);
});

test("execution index binds exact tips, workflow, campaign, count, and aggregate root", () => {
  const body = {
    schemaVersion: 1, domain: "deed-corpus-pre-truth-execution-index-v1",
    manifestSha256: "1".repeat(64), intakeSealSha256: "2".repeat(64), codeTip: request.productCodeTip,
    productSourceTreeSha256: "3".repeat(64), verifierPolicyTip: request.verifierPolicyTip,
    evaluatorWorkflowRef: OFFICIAL_WORKFLOW_REF, evaluatorRunId: "123", campaign: request.campaign,
    consumeEventSha256: "4".repeat(64), executions: Array.from({ length: 150 }, (_, index) => ({ index })),
  };
  const exact = { ...body, executionRootSha256: sha256(stableJson(body)) };
  assert.equal(validateExecutionIndexForAttestation(Buffer.from(JSON.stringify(exact)), request).executionCount, 150);
  for (const patch of [
    { codeTip: "f".repeat(40) }, { verifierPolicyTip: "f".repeat(40) },
    { evaluatorWorkflowRef: "attacker/workflow" }, { campaign: "replay" }, { executions: body.executions.slice(1) },
    { executionRootSha256: "0".repeat(64) },
  ]) assert.throws(() => validateExecutionIndexForAttestation(Buffer.from(JSON.stringify({ ...exact, ...patch })), request));
});

test("per-call model receipt binds exact model, prompt, schema, images, and output", () => {
  const expected = {
    output: "{\"entries\":[],\"unresolved\":[]}", prompt: "read deed", schema: { type: "object" },
    images: [{ name: "crop.png", bytes: 3, sha256: sha256("png") }], model: "openai/gpt-4.1", modelVersion: "2025-04-14",
  };
  const receipt = sealModelReceipt({
    schemaVersion: 1, kind: "github-models-multimodal-receipt", sequence: 1,
    modelRequested: expected.model, modelReturned: expected.model, systemFingerprint: null,
    modelCatalogVersion: expected.modelVersion, modelCatalogSha256: "c".repeat(64),
    promptSha256: sha256(expected.prompt), schemaSha256: sha256(stableJson(expected.schema)),
    images: expected.images, outputSha256: sha256(expected.output), upstreamResponseSha256: "a".repeat(64),
    rateLimit: { "x-ratelimit-limit": "1000", "x-ratelimit-remaining": "999" },
    attempts: 1, usage: { prompt_tokens: 10 }, completedAt: "2026-07-15T00:00:00.000Z",
  });
  assert.equal(validateModelReceipt(receipt, expected).receiptSha256, receipt.receiptSha256);
  for (const mutation of [
    ({ ...receipt, outputSha256: "b".repeat(64) }),
    ({ ...receipt, modelReturned: null }),
    ({ ...receipt, images: [] }),
    (({ receiptSha256, ...missing }) => missing)(receipt),
  ]) assert.throws(() => validateModelReceipt(mutation, expected), /missing, substituted/);
  assert.throws(() => validateModelReceipt(receipt, { ...expected, output: "substituted" }), /missing, substituted/);
  assert.match(shimSource, /writeFileSync\(`\$\{responsePath\}\.prompt\.txt`, prompt/);
  assert.match(shimSource, /writeFileSync\(responsePath, body\.output/);
  assert.match(shimSource, /writeFileSync\(`\$\{responsePath\}\.model-receipt\.json`/);
});

test("broker accepts exactly 80 committed images and enforces aggregate bytes before inference", () => {
  const image = (index) => ({ name: `crop-${index}.png`, mediaType: "image/png", bytes: 1,
    sha256: sha256(Buffer.from([index % 256])), contentBase64: Buffer.from([index % 256]).toString("base64") });
  const body = { schemaVersion: 1, prompt: "read", schema: { type: "object" },
    images: Array.from({ length: MODEL_MAX_IMAGES }, (_, index) => image(index)) };
  assert.equal(validateBrokerRequest(body).images.length, 80);
  assert.equal(MODEL_MAX_AGGREGATE_IMAGE_BYTES, 256 * 1024 * 1024);
  assert.throws(() => validateBrokerRequest({ ...body, images: [...body.images, image(81)] }), /schema/);
  assert.throws(() => validateBrokerRequest({ ...body, images: body.images.slice(0, 5) }, { maxAggregateBytes: 4 }), /aggregate/);
});

test("source verification proves all truth paths absent, then truth verification proves exact post-seal bytes", () => {
  const root = mkdtempSync(join(tmpdir(), "deed-source-boundary-"));
  mkdirSync(join(root, "sources"));
  const source = Buffer.from("%PDF-1.7\nsource\n");
  const truth = Buffer.from("{\"truth\":true}\n");
  writeFileSync(join(root, "sources", "one.pdf"), source);
  writeFileSync(join(root, "intake-seal.json"), "{}\n");
  const entries = Array.from({ length: 50 }, (_, index) => ({
    caseId: `case-${index}`, expectedOutcome: "positive", source: { path: "sources/one.pdf", sha256: sha256(source), bytes: source.length },
    truth: { path: "truth/one.json", sha256: sha256(truth), bytes: truth.length },
  }));
  writeFileSync(join(root, "private-manifest.json"), JSON.stringify({ cohort: "final", codeTip: request.productCodeTip, entries }));
  writeRoleReceipt(root, "source", ["private-manifest.json", "intake-seal.json", "sources/one.pdf"]);
  const requestPath = join(root, "request.json"); writeFileSync(requestPath, JSON.stringify(request));
  let child = spawnEvaluator(["verify-source", "--request", requestPath, "--root", root]);
  assert.equal(child.status, 0, child.stderr);
  writeFileSync(join(root, "unlisted-truth.txt"), "hidden");
  writeRoleReceipt(root, "source", ["private-manifest.json", "intake-seal.json", "sources/one.pdf", "unlisted-truth.txt"]);
  child = spawnEvaluator(["verify-source", "--request", requestPath, "--root", root]);
  assert.notEqual(child.status, 0);
  rmSync(join(root, "unlisted-truth.txt"));
  rmSync(join(root, ".source-fileset-receipt.json"));
  writeRoleReceipt(root, "source", ["private-manifest.json", "intake-seal.json", "sources/one.pdf"]);
  mkdirSync(join(root, "truth")); writeFileSync(join(root, "truth", "one.json"), truth);
  writeRoleReceipt(root, "truth", ["truth/one.json"]);
  child = spawnEvaluator(["verify-source", "--request", requestPath, "--root", root]);
  assert.notEqual(child.status, 0);
  child = spawnEvaluator(["verify-truth", "--request", requestPath, "--root", root]);
  assert.equal(child.status, 0, child.stderr);
  writeFileSync(join(root, "truth", "one.json"), "tampered");
  child = spawnEvaluator(["verify-truth", "--request", requestPath, "--root", root]);
  assert.notEqual(child.status, 0);
});

test("scoped draft input release binds exact request tag, verifier target, asset ids, names, and repository", () => {
  const root = mkdtempSync(join(tmpdir(), "deed-release-provenance-"));
  const requestPath = join(root, "request.json"); writeFileSync(requestPath, JSON.stringify(request));
  const tag = `deed-evaluator-input-${request.requestId}`;
  const asset = (id, name) => ({
    id: Number(id), name, state: "uploaded", content_type: "application/octet-stream", size: 100,
    url: `https://api.github.com/repos/HansenHomeAI/deed-corpus-transparency-log/releases/assets/${id}`,
    browser_download_url: `https://github.com/HansenHomeAI/deed-corpus-transparency-log/releases/download/${tag}/${name}`,
  });
  const exact = { id: Number(request.inputReleaseId), tag_name: tag, name: tag, draft: true, prerelease: false,
    target_commitish: request.verifierPolicyTip, assets: [asset(request.sourceAssetId, "source.bundle"), asset(request.truthAssetId, "truth.bundle")] };
  const releasePath = join(root, "release.json"); writeFileSync(releasePath, JSON.stringify(exact));
  let child = spawnEvaluator(["verify-input-release", "--request", requestPath, "--release", releasePath]);
  assert.equal(child.status, 0, child.stderr);
  for (const mutation of [
    { tag_name: "replay" }, { name: "replay" }, { draft: false }, { target_commitish: "f".repeat(40) },
    { assets: [asset(request.sourceAssetId, "source.bundle"), asset(request.truthAssetId, "source.bundle")] },
  ]) {
    writeFileSync(releasePath, JSON.stringify({ ...exact, ...mutation }));
    child = spawnEvaluator(["verify-input-release", "--request", requestPath, "--release", releasePath]);
    assert.notEqual(child.status, 0);
  }
});

test("workflow statically enforces hosted ordering, credential isolation, pinned actions, and ciphertext-only upload", () => {
  assert.match(workflow, /run-name: deed-evaluator-\$\{\{ inputs\.request_id \}\}/);
  assert.match(workflow, /runs-on: macos-15/);
  assert.match(workflow, /permissions:[\s\S]*contents: read/);
  assert.match(workflow, /permissions:[\s\S]*actions: write/);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,200}contents: write/);
  assert.match(workflow, /group: deed-corpus-evaluator-\$\{\{ inputs\.request_id \}\}/);
  assert.doesNotMatch(workflow, /group: deed-corpus-encrypted-custody-registry/);
  assert.match(workflow, /SPACEPORT_RUNNER_ENVIRONMENT: github-hosted/);
  assert.match(workflow, /test "\$VERIFIER_POLICY_TIP" = "\$GITHUB_SHA"/);
  assert.match(workflow, /ssh-key: \$\{\{ secrets\.DEED_PRODUCT_READONLY_DEPLOY_KEY \}\}/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /actions\/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4\.1\.1/);
  assert.match(workflow, /--deny-self-hosted-runners --bundle/);
  assert.match(workflow, /env -i HOME="\$HOME" PATH="\$PATH"/);
  assert.match(workflow, /unset MODEL_TOKEN GITHUB_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL/);
  assert.match(workflow, /DEED_REGISTRY_RESPONSE_PRIVATE_KEY_PATH: \$\{\{ runner\.temp \}\}\/deed-evaluator\/registry-response-private\.pem/);
  assert.match(workflow, /DEED_REGISTRY_RESPONSE_PUBLIC_KEY_PATH: \$\{\{ runner\.temp \}\}\/deed-evaluator\/registry-response-public\.pem/);
  assert.match(workflow, /DEED_REGISTRY_REQUEST_PUBLIC_KEY_PATH: \$\{\{ github\.workspace \}\}\/keys\/deed-registry-request-public\.pem/);
  assert.match(workflow, /DEED_REGISTRY_REQUEST_KEY_ID: deed-registry-request-20260715-8444a5d9/);
  assert.match(workflow, /CODEX_HOME: \$\{\{ runner\.temp \}\}\/deed-evaluator\/empty-codex-home/);
  assert.match(workflow, /install -m 0600 scripts\/model-receipt\.mjs scripts\/model-broker-contract\.mjs "\$HOME\/\.local\/bin\/"/);
  assert.match(workflow, /--model-version 2025-04-14/);
  assert.match(workflow, /Synthetic eighty-image maximum-cardinality multimodal smoke/);
  assert.match(workflow, /test -s "\$smoke\/result\.json\.model-receipt\.json"/);
  assert.match(workflow, /cp -R "\$root\/model-smoke" "\$campaign\/model-smoke"/);
  assert.match(workflow, /cp "\$root\/model-receipts\.jsonl" "\$campaign\/model-receipts\.jsonl"/);
  assert.match(workflow, /GH_TOKEN: \$\{\{ github\.token \}\}/);
  assert.doesNotMatch(workflow, /DEED_PRODUCT_READONLY_TOKEN/);
  assert.match(workflow, /repos\/HansenHomeAI\/deed-corpus-transparency-log\/releases\/\$INPUT_RELEASE_ID/);
  assert.match(workflow, /releases\/assets\/\$SOURCE_ASSET_ID/);
  assert.match(workflow, /releases\/assets\/\$TRUTH_ASSET_ID/);
  assert.match(workflow, /--resume-stage seal-only/);
  assert.match(workflow, /--resume-stage grade/);
  assert.match(workflow, /product-execute\.stderr\.log/);
  assert.match(workflow, /product-seal\.stderr\.log/);
  assert.match(workflow, /product-grade\.stderr\.log/);
  assert.match(workflow, /name: Upload ciphertext evidence only[\s\S]*path: \$\{\{ runner\.temp \}\}\/deed-evaluator\/evidence\.bundle/);
  assert.doesNotMatch(workflow, /actions\/upload-artifact@[\s\S]{0,300}(source\.bundle|truth\.bundle|private-manifest)/);
  assert.match(workflow, /rm -rf "\$root"/);
  const order = [
    "materialize source only", "execute all source-only product trials", "Attest the one exact execution index",
    "verify retained Sigstore bundle and append execution seal", "Decrypt truth only after", "Grade the post-seal campaign",
    "Encrypt all returned evidence", "Upload ciphertext evidence only",
  ].map((label) => workflow.indexOf(label));
  assert.ok(order.every((value) => value >= 0));
  assert.deepEqual(order, [...order].sort((left, right) => left - right));
});

function spawnEvaluator(args) {
  return spawnSync(process.execPath, [evaluator, ...args], { encoding: "utf8", env: { ...process.env, ...hostedEnv } });
}

function writeRoleReceipt(root, role, paths) {
  const files = paths.sort().map((path) => { const bytes = readFileSync(join(root, path)); return { path, bytes: bytes.length, sha256: sha256(bytes) }; });
  writeFileSync(join(root, `.${role}-fileset-receipt.json`), JSON.stringify({ schemaVersion: 1,
    kind: "spaceport-deed-evaluator-materialized-file-set", role, requestId: request.requestId,
    fileRootSha256: sha256(stableJson(files)), files }));
}
