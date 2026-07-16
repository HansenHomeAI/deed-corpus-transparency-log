import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, posix, resolve, sep } from "node:path";

export const OFFICIAL_REPOSITORY = "HansenHomeAI/deed-corpus-transparency-log";
export const OFFICIAL_WORKFLOW = ".github/workflows/official-deed-evaluator.yml";
export const OFFICIAL_WORKFLOW_REF = `${OFFICIAL_REPOSITORY}/${OFFICIAL_WORKFLOW}@refs/heads/main`;
export const PRODUCT_REPOSITORY = "HansenHomeAI/Autodesk-automation";
export const BUNDLE_ALGORITHM = "RSA-OAEP-256+A256GCM";
export const BUNDLE_MAGIC = Buffer.from("DCB1");
export const BUNDLE_SCHEMA_VERSION = 1;

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const REQUEST_ID = /^[a-f0-9]{64}$/;
const SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/;
const KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_FILE_COUNT = 20_000;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_FILESET_BYTES = 2 * 1024 * 1024 * 1024;

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function validateHostedEnvironment(env = process.env) {
  const result = {
    ok: env.GITHUB_ACTIONS === "true"
      && env.GITHUB_REPOSITORY === OFFICIAL_REPOSITORY
      && env.RUNNER_OS === "macOS"
      && env.SPACEPORT_RUNNER_ENVIRONMENT === "github-hosted"
      && env.SPACEPORT_EVALUATOR_WORKFLOW_REF === OFFICIAL_WORKFLOW_REF
      && GIT_SHA.test(env.GITHUB_SHA || "")
      && /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID || "")
      && /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT || ""),
    repository: env.GITHUB_REPOSITORY || null,
    verifierPolicyTip: env.GITHUB_SHA || null,
    workflowRef: env.SPACEPORT_EVALUATOR_WORKFLOW_REF || null,
    runnerOs: env.RUNNER_OS || null,
    runnerEnvironment: env.SPACEPORT_RUNNER_ENVIRONMENT || null,
    runId: env.GITHUB_RUN_ID || null,
    runAttempt: env.GITHUB_RUN_ATTEMPT || null,
  };
  if (!result.ok) throw new Error("Official evaluation requires the exact protected public workflow on a GitHub-hosted macOS runner.");
  return result;
}

export function validateEvaluationRequest(request, { env = process.env } = {}) {
  const hosted = validateHostedEnvironment(env);
  const allowed = new Set([
    "schemaVersion", "requestId", "mode", "campaign", "productCodeTip", "verifierPolicyTip",
    "inputReleaseId", "sourceAssetId", "sourceBundleSha256", "truthAssetId", "truthBundleSha256",
    "requesterPublicKeyPemBase64", "requesterPublicKeySha256",
  ]);
  const unexpected = Object.keys(request || {}).filter((field) => !allowed.has(field));
  let requesterKey;
  try {
    requesterKey = Buffer.from(request?.requesterPublicKeyPemBase64 || "", "base64");
  } catch {
    requesterKey = Buffer.alloc(0);
  }
  if (unexpected.length || request?.schemaVersion !== 1 || !REQUEST_ID.test(request.requestId || "")
    || !["final", "fail-safe"].includes(request.mode) || !SLUG.test(request.campaign || "")
    || !GIT_SHA.test(request.productCodeTip || "") || request.verifierPolicyTip !== hosted.verifierPolicyTip
    || request.campaign !== (request.mode === "final" ? "final" : "raw-fail-safe")
    || !/^[1-9][0-9]*$/.test(String(request.inputReleaseId || ""))
    || !/^[1-9][0-9]*$/.test(String(request.sourceAssetId || ""))
    || !/^[1-9][0-9]*$/.test(String(request.truthAssetId || ""))
    || request.sourceAssetId === request.truthAssetId
    || !SHA256.test(request.sourceBundleSha256 || "") || !SHA256.test(request.truthBundleSha256 || "")
    || request.sourceBundleSha256 === request.truthBundleSha256
    || requesterKey.length < 256 || sha256(requesterKey) !== request.requesterPublicKeySha256) {
    throw new Error("Official evaluator request is invalid, stale, or not bound to this exact verifier policy tip.");
  }
  return { ...structuredClone(request), hosted, requesterPublicKeyPem: requesterKey.toString("utf8") };
}

export function createFileSet({ role, requestId, root, paths }) {
  if (!["source", "truth", "evidence"].includes(role) || !REQUEST_ID.test(requestId || "")
    || !Array.isArray(paths) || paths.length < 1 || paths.length > MAX_FILE_COUNT) {
    throw new Error("File-set role, request id, or file list is invalid.");
  }
  const absoluteRoot = resolve(root);
  const files = paths.map((inputPath) => {
    const absolute = resolve(inputPath);
    const path = safeRelativePath(absoluteRoot, absolute);
    const content = readFileSync(absolute);
    if (content.length > MAX_FILE_BYTES) throw new Error(`File exceeds evaluator limit: ${path}`);
    return { path, bytes: content.length, sha256: sha256(content), contentBase64: content.toString("base64") };
  }).sort((left, right) => left.path.localeCompare(right.path));
  if (new Set(files.map((file) => file.path)).size !== files.length) throw new Error("File-set paths must be unique.");
  const fileRootSha256 = sha256(stableJson(files.map(({ path, bytes, sha256: digest }) => ({ path, bytes, sha256: digest }))));
  const result = { schemaVersion: 1, kind: "spaceport-deed-evaluator-file-set", role, requestId, fileRootSha256, files };
  validateFileSet(result, { expectedRole: role, expectedRequestId: requestId });
  return result;
}

export function validateFileSet(fileSet, { expectedRole, expectedRequestId } = {}) {
  const allowed = new Set(["schemaVersion", "kind", "role", "requestId", "fileRootSha256", "files"]);
  if (Object.keys(fileSet || {}).some((key) => !allowed.has(key)) || fileSet?.schemaVersion !== 1
    || fileSet.kind !== "spaceport-deed-evaluator-file-set"
    || !["source", "truth", "evidence"].includes(fileSet.role)
    || (expectedRole && fileSet.role !== expectedRole)
    || !REQUEST_ID.test(fileSet.requestId || "")
    || (expectedRequestId && fileSet.requestId !== expectedRequestId)
    || !Array.isArray(fileSet.files) || fileSet.files.length < 1 || fileSet.files.length > MAX_FILE_COUNT) {
    throw new Error("Decrypted evaluator file-set schema is invalid.");
  }
  const seen = new Set();
  let total = 0;
  const roots = [];
  for (const file of fileSet.files) {
    const keys = new Set(["path", "bytes", "sha256", "contentBase64"]);
    if (Object.keys(file || {}).some((key) => !keys.has(key)) || !safeBundlePath(file?.path) || seen.has(file.path)
      || !Number.isInteger(file.bytes) || file.bytes < 0 || file.bytes > MAX_FILE_BYTES
      || !SHA256.test(file.sha256 || "") || !canonicalBase64(file.contentBase64 || "")) {
      throw new Error("Decrypted evaluator file-set contains an unsafe or malformed file.");
    }
    const content = Buffer.from(file.contentBase64, "base64");
    if (content.length !== file.bytes || sha256(content) !== file.sha256) {
      throw new Error(`Decrypted evaluator file bytes fail their commitment: ${file.path}`);
    }
    total += content.length;
    if (total > MAX_FILESET_BYTES) throw new Error("Decrypted evaluator file-set exceeds the aggregate byte limit.");
    seen.add(file.path);
    roots.push({ path: file.path, bytes: file.bytes, sha256: file.sha256 });
  }
  roots.sort((left, right) => left.path.localeCompare(right.path));
  if (fileSet.fileRootSha256 !== sha256(stableJson(roots))) throw new Error("Decrypted evaluator file-set root is invalid.");
  return fileSet;
}

export function materializeFileSet(fileSet, destination, expectations = {}) {
  validateFileSet(fileSet, expectations);
  const root = resolve(destination);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  for (const file of fileSet.files) {
    const output = resolve(root, ...file.path.split("/"));
    if (output !== root && !output.startsWith(`${root}${sep}`)) throw new Error("File-set materialization escaped its root.");
    if (existsSync(output)) throw new Error(`File-set cannot replace an existing path: ${file.path}`);
    mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
    writeFileSync(output, Buffer.from(file.contentBase64, "base64"), { flag: "wx", mode: 0o600 });
  }
  return { root, fileRootSha256: fileSet.fileRootSha256, files: fileSet.files.length };
}

export function encryptBundle(fileSet, publicKeyPem, keyId, { key = randomBytes(32), iv = randomBytes(12) } = {}) {
  validateFileSet(fileSet);
  if (!KEY_ID.test(keyId || "") || !Buffer.isBuffer(key) || key.length !== 32 || !Buffer.isBuffer(iv) || iv.length !== 12) {
    throw new Error("Bundle encryption key id, AES key, or IV is invalid.");
  }
  const plaintext = Buffer.from(`${JSON.stringify(fileSet)}\n`, "utf8");
  const headerBase = {
    schemaVersion: BUNDLE_SCHEMA_VERSION,
    algorithm: BUNDLE_ALGORITHM,
    keyId,
    plaintextSha256: sha256(plaintext),
    plaintextBytes: plaintext.length,
    encryptedKeyBase64url: publicEncrypt({
      key: publicKeyPem, oaepHash: "sha256", padding: constants.RSA_PKCS1_OAEP_PADDING,
    }, key).toString("base64url"),
    ivBase64url: iv.toString("base64url"),
  };
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(stableJson(headerBase), "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const header = { ...headerBase, authTagBase64url: cipher.getAuthTag().toString("base64url") };
  const headerBytes = Buffer.from(`${JSON.stringify(header)}\n`, "utf8");
  const length = Buffer.alloc(4); length.writeUInt32BE(headerBytes.length);
  return Buffer.concat([BUNDLE_MAGIC, length, headerBytes, ciphertext]);
}

export function decryptBundle(bytes, privateKeyPem, expectedKeyId, expectations = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 32 || !bytes.subarray(0, 4).equals(BUNDLE_MAGIC)) {
    throw new Error("Encrypted evaluator bundle magic is invalid.");
  }
  const headerLength = bytes.readUInt32BE(4);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES || bytes.length <= 8 + headerLength) {
    throw new Error("Encrypted evaluator bundle header length is invalid.");
  }
  let header;
  try { header = JSON.parse(bytes.subarray(8, 8 + headerLength).toString("utf8")); }
  catch { throw new Error("Encrypted evaluator bundle header is not JSON."); }
  const allowed = new Set([
    "schemaVersion", "algorithm", "keyId", "plaintextSha256", "plaintextBytes",
    "encryptedKeyBase64url", "ivBase64url", "authTagBase64url",
  ]);
  if (Object.keys(header || {}).some((key) => !allowed.has(key)) || header.schemaVersion !== BUNDLE_SCHEMA_VERSION
    || header.algorithm !== BUNDLE_ALGORITHM || header.keyId !== expectedKeyId
    || !SHA256.test(header.plaintextSha256 || "") || !Number.isInteger(header.plaintextBytes)
    || header.plaintextBytes < 1 || header.plaintextBytes > MAX_FILESET_BYTES * 2
    || !canonicalBase64url(header.encryptedKeyBase64url) || !canonicalBase64url(header.ivBase64url)
    || !canonicalBase64url(header.authTagBase64url)) {
    throw new Error("Encrypted evaluator bundle header or key id is invalid.");
  }
  const iv = Buffer.from(header.ivBase64url, "base64url");
  const tag = Buffer.from(header.authTagBase64url, "base64url");
  if (iv.length !== 12 || tag.length !== 16) throw new Error("Encrypted evaluator bundle IV or tag is invalid.");
  let key;
  try {
    key = privateDecrypt({ key: privateKeyPem, oaepHash: "sha256", padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(header.encryptedKeyBase64url, "base64url"));
  } catch { throw new Error("Encrypted evaluator bundle key unwrap failed."); }
  const { authTagBase64url, ...headerBase } = header;
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(stableJson(headerBase), "utf8"));
  decipher.setAuthTag(tag);
  let plaintext;
  try { plaintext = Buffer.concat([decipher.update(bytes.subarray(8 + headerLength)), decipher.final()]); }
  catch { throw new Error("Encrypted evaluator bundle authentication failed."); }
  if (plaintext.length !== header.plaintextBytes || sha256(plaintext) !== header.plaintextSha256) {
    throw new Error("Encrypted evaluator bundle plaintext commitment failed.");
  }
  let fileSet;
  try { fileSet = JSON.parse(plaintext.toString("utf8")); }
  catch { throw new Error("Decrypted evaluator bundle is not a JSON file-set."); }
  return validateFileSet(fileSet, expectations);
}

export function validateExecutionIndexForAttestation(indexBytes, request) {
  let index;
  try { index = JSON.parse(indexBytes.toString("utf8")); }
  catch { throw new Error("Execution index is not JSON."); }
  const expectedCount = request.mode === "final" ? 150 : null;
  if (index?.schemaVersion !== 1 || index.codeTip !== request.productCodeTip
    || index.verifierPolicyTip !== request.verifierPolicyTip
    || index.evaluatorWorkflowRef !== OFFICIAL_WORKFLOW_REF
    || index.campaign !== request.campaign || !Array.isArray(index.executions)
    || (expectedCount !== null && index.executions.length !== expectedCount)
    || index.executions.length < (request.mode === "fail-safe" ? 60 : 150)) {
    throw new Error("Execution index is not bound to the exact request, product tip, verifier tip, workflow, and trial count.");
  }
  const body = { ...index }; delete body.executionRootSha256;
  if (index.executionRootSha256 !== sha256(stableJson(body))) throw new Error("Execution index aggregate root is invalid.");
  return { index, sha256: sha256(indexBytes), executionCount: index.executions.length };
}

function safeRelativePath(root, path) {
  if (path === root || !path.startsWith(`${root}${sep}`)) throw new Error("File is outside its declared file-set root.");
  const relative = path.slice(root.length + 1).split(sep).join("/");
  if (!safeBundlePath(relative)) throw new Error("File-set path is unsafe.");
  return relative;
}

function safeBundlePath(path) {
  if (typeof path !== "string" || !path || path.length > 1024 || path.includes("\\") || path.includes("\0")
    || path.startsWith("/") || /^[A-Za-z]:/.test(path)) return false;
  const normalized = posix.normalize(path);
  return normalized === path && !path.split("/").some((part) => !part || part === "." || part === "..");
}

function canonicalBase64(value) {
  return typeof value === "string" && /^[A-Za-z0-9+/]*={0,2}$/.test(value)
    && Buffer.from(value, "base64").toString("base64") === value;
}

function canonicalBase64url(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value)
    && Buffer.from(value, "base64url").toString("base64url") === value;
}
