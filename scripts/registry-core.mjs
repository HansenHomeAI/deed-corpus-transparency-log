import {
  createCipheriv,
  createDecipheriv,
  createHash,
  constants,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  appendCorpusRegistryEvent,
  CORPUS_EVENT_TYPES,
  corpusRegistryRootSha256,
  validateCorpusRegistry,
} from "./corpus-registry-semantics.mjs";

export const ZERO_SHA256 = "0".repeat(64);
export const SHA256 = /^[a-f0-9]{64}$/;
export const STATE_ALGORITHM = "AES-256-GCM";
export const REQUEST_ALGORITHM = "RSA-OAEP-256+A256GCM";
export const INDEX_LOG = "spaceport-deed-corpus-encrypted-custody-registry";
export const STATE_REGISTRY = "spaceport-deed-corpus-encrypted-state";
export const SOURCE_REPOSITORY = "HansenHomeAI/Autodesk-automation";

export class CorpusRegistrySemanticError extends Error {
  constructor(errors) {
    super("Encrypted semantic append was rejected by the detailed corpus state machine.");
    this.name = "CorpusRegistrySemanticError";
    this.errors = structuredClone(errors);
  }
}

const STATE_MAGIC = Buffer.from("DCR2");
const STATE_FORMAT_VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_REQUEST_BYTES = 32 * 1024;
const MAX_REQUEST_ENVELOPE_CHARS = 60 * 1024;
const MAX_RECEIPT_BYTES = 32 * 1024 * 1024;
const MAX_RECEIPT_ARTIFACT_BYTES = 64 * 1024 * 1024;
const REJECTION_PADDING_BLOCK_BYTES = 1024 * 1024;
const REJECTION_PADDING_HEADROOM_BYTES = 512 * 1024;
const PADDED_PAYLOAD_KIND = "spaceport-deed-corpus-padded-payload";

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

export function indexSha256(index) {
  return sha256(stableJson(index));
}

export function envelopeSha256(envelope) {
  const copy = { ...envelope };
  delete copy.envelopeSha256;
  return sha256(stableJson(copy));
}

function legacyAnchorEventSha256(event) {
  const copy = { ...event };
  delete copy.anchorEventSha256;
  return sha256(stableJson(copy));
}

export function ciphertextPath(ciphertextDirectory, sequence) {
  return join(ciphertextDirectory, `${String(sequence).padStart(6, "0")}.bin`);
}

export function emptyPublicIndex() {
  return { schemaVersion: 2, log: INDEX_LOG, envelopes: [] };
}

export function validatePublicIndex(index, { ciphertextDirectory, requireCiphertexts = true } = {}) {
  if (index?.schemaVersion !== 2 || index.log !== INDEX_LOG || !Array.isArray(index.envelopes)) {
    throw new Error("Encrypted custody index schema is invalid.");
  }
  let priorEnvelope = ZERO_SHA256;
  let priorTime = -Infinity;
  const allowed = new Set([
    "sequence",
    "previousEnvelopeSha256",
    "ciphertextSha256",
    "ciphertextBytes",
    "algorithm",
    "keyId",
    "issuedAt",
    "workflowRunId",
    "envelopeSha256",
  ]);
  for (const [offset, envelope] of index.envelopes.entries()) {
    const unexpected = Object.keys(envelope || {}).filter((key) => !allowed.has(key));
    const time = Date.parse(envelope?.issuedAt || "");
    if (unexpected.length > 0 || envelope?.sequence !== offset + 1
      || envelope.previousEnvelopeSha256 !== priorEnvelope
      || !SHA256.test(envelope.ciphertextSha256 || "")
      || !Number.isInteger(envelope.ciphertextBytes) || envelope.ciphertextBytes <= STATE_MAGIC.length + 1 + IV_BYTES + TAG_BYTES
      || envelope.algorithm !== STATE_ALGORITHM
      || !/^[A-Za-z0-9._:-]{1,128}$/.test(envelope.keyId || "")
      || !Number.isFinite(time) || time < priorTime
      || !/^[0-9]+$/.test(envelope.workflowRunId || "")
      || envelope.envelopeSha256 !== envelopeSha256(envelope)) {
      throw new Error(`Encrypted custody envelope ${offset + 1} breaks the public chain.`);
    }
    if (requireCiphertexts) {
      if (!ciphertextDirectory) throw new Error("A ciphertext directory is required to verify public bytes.");
      const path = ciphertextPath(ciphertextDirectory, envelope.sequence);
      if (!existsSync(path)) throw new Error(`Ciphertext ${envelope.sequence} is missing.`);
      const bytes = readFileSync(path);
      if (bytes.length !== envelope.ciphertextBytes || sha256(bytes) !== envelope.ciphertextSha256) {
        throw new Error(`Ciphertext ${envelope.sequence} does not match its public commitment.`);
      }
    }
    priorEnvelope = envelope.envelopeSha256;
    priorTime = time;
  }
  if (requireCiphertexts) {
    const expected = new Set(index.envelopes.map((envelope) => `${String(envelope.sequence).padStart(6, "0")}.bin`));
    const actual = readdirSync(ciphertextDirectory).filter((name) => name !== ".gitkeep");
    if (actual.some((name) => !expected.has(name)) || actual.length !== expected.size) {
      throw new Error("Ciphertext directory contains missing, unindexed, or non-canonical public files.");
    }
  }
  return index;
}

export function validateCanonicalIndexBytes(bytes, index) {
  const canonical = Buffer.from(`${JSON.stringify(index, null, 2)}\n`, "utf8");
  if (!Buffer.from(bytes).equals(canonical)) throw new Error("Public index bytes are not canonical JSON.");
  return index;
}

export function validateLegacyLog(log) {
  if (log?.schemaVersion !== 1 || log.log !== "spaceport-deed-corpus-registry-roots"
    || log.sourceRepository !== SOURCE_REPOSITORY || !Array.isArray(log.events)) {
    throw new Error("Frozen legacy transparency log schema is invalid.");
  }
  let priorEvent = ZERO_SHA256;
  let priorPrivate = ZERO_SHA256;
  let priorCount = 0;
  let priorTime = -Infinity;
  for (const [offset, event] of log.events.entries()) {
    const time = Date.parse(event?.issuedAt || "");
    if (event?.schemaVersion !== 1 || event.sequence !== offset + 1
      || event.previousAnchorEventSha256 !== priorEvent
      || event.previousPrivateRegistryRootSha256 !== priorPrivate
      || event.anchorEventSha256 !== legacyAnchorEventSha256(event)
      || !SHA256.test(event.privateRegistryRootSha256 || "")
      || event.privateRegistryRootSha256 === priorPrivate
      || !Number.isInteger(event.privateRegistryEventCount) || event.privateRegistryEventCount <= priorCount
      || !CORPUS_EVENT_TYPES.has(event.kind) || !SHA256.test(event.requestNonce || "")
      || !Number.isFinite(time) || time < priorTime) {
      throw new Error(`Frozen public anchor ${offset + 1} breaks its canonical chain.`);
    }
    priorEvent = event.anchorEventSha256;
    priorPrivate = event.privateRegistryRootSha256;
    priorCount = event.privateRegistryEventCount;
    priorTime = time;
  }
  return log;
}

export function createGenesisState(privateRegistry, legacyLog, migrationAuthority, now = new Date()) {
  validateLegacyLog(legacyLog);
  validateAuthority(migrationAuthority, { genesis: true });
  const registryFields = new Set(["schemaVersion", "campaign", "repository", "ref", "events"]);
  const detailed = validateCorpusRegistry({ registry: privateRegistry });
  const lastAnchor = legacyLog.events.at(-1);
  if (Object.keys(privateRegistry || {}).some((key) => !registryFields.has(key))
    || !detailed.ok || detailed.eventCount < 1 || lastAnchor?.privateRegistryRootSha256 !== detailed.rootSha256
    || lastAnchor?.privateRegistryEventCount !== detailed.eventCount) {
    throw new Error("Private genesis is incomplete or disconnected from the frozen public prefix.");
  }
  validateAnchorBindings(privateRegistry, legacyLog);
  const state = {
    schemaVersion: 3,
    state: STATE_REGISTRY,
    frozenPublicAnchorPrefix: structuredClone(legacyLog),
    genesis: {
      privateRegistryRootSha256: detailed.rootSha256,
      privateRegistryEventCount: detailed.eventCount,
      publicAnchorRootSha256: sha256(stableJson(legacyLog)),
      publicAnchorEventSha256: lastAnchor.anchorEventSha256,
      migratedAt: now.toISOString(),
      authority: structuredClone(migrationAuthority),
    },
    encryptedAppendStartIndex: detailed.eventCount,
    registry: structuredClone(privateRegistry),
  };
  validatePlaintextRegistry(state);
  return state;
}

export function validatePlaintextRegistry(state) {
  const stateFields = new Set([
    "schemaVersion", "state", "frozenPublicAnchorPrefix", "genesis", "encryptedAppendStartIndex", "registry",
  ]);
  if (Object.keys(state || {}).some((key) => !stateFields.has(key))
    || state?.schemaVersion !== 3 || state.state !== STATE_REGISTRY
    || !Number.isInteger(state.encryptedAppendStartIndex) || state.encryptedAppendStartIndex < 1
    || !isPlainObject(state.registry) || !isPlainObject(state.genesis)) {
    throw new Error("Decrypted custody registry schema is invalid.");
  }
  validateLegacyLog(state.frozenPublicAnchorPrefix);
  const checked = validateCorpusRegistry({ registry: state.registry });
  const registryFields = new Set(["schemaVersion", "campaign", "repository", "ref", "events"]);
  const genesisFields = new Set([
    "privateRegistryRootSha256", "privateRegistryEventCount", "publicAnchorRootSha256",
    "publicAnchorEventSha256", "migratedAt", "authority",
  ]);
  const lastAnchor = state.frozenPublicAnchorPrefix.events.at(-1);
  if (!checked.ok || Object.keys(state.registry).some((key) => !registryFields.has(key))
    || Object.keys(state.genesis).some((key) => !genesisFields.has(key))
    || state.encryptedAppendStartIndex !== state.genesis.privateRegistryEventCount
    || state.registry.events.length < state.encryptedAppendStartIndex
    || state.genesis.privateRegistryRootSha256
      !== corpusRegistryRootSha256({ ...state.registry, events: state.registry.events.slice(0, state.encryptedAppendStartIndex) })
    || state.genesis.privateRegistryEventCount !== lastAnchor?.privateRegistryEventCount
    || state.genesis.privateRegistryRootSha256 !== lastAnchor?.privateRegistryRootSha256
    || state.genesis.publicAnchorRootSha256 !== sha256(stableJson(state.frozenPublicAnchorPrefix))
    || state.genesis.publicAnchorEventSha256 !== lastAnchor?.anchorEventSha256
    || !validIso(state.genesis.migratedAt)) {
    throw new Error("Decrypted state fails detailed genesis or corpus semantics.");
  }
  validateAuthority(state.genesis.authority, { genesis: true });
  validateAnchorBindings(state.registry, state.frozenPublicAnchorPrefix);
  for (const event of state.registry.events.slice(state.encryptedAppendStartIndex)) validateAuthority(event.authority);
  return state;
}

function validateAnchorBindings(registry, log) {
  for (const [offset, anchor] of log.events.entries()) {
    const count = anchor.privateRegistryEventCount;
    const prefix = { ...registry, events: registry.events.slice(0, count) };
    if (count < 1 || count > registry.events.length || corpusRegistryRootSha256(prefix) !== anchor.privateRegistryRootSha256
      || registry.events[count - 1]?.eventType !== anchor.kind) {
      throw new Error(`Frozen public anchor ${offset + 1} is not bound to its exact detailed private-registry prefix.`);
    }
  }
}

function validateAuthority(authority, { genesis = false } = {}) {
  if (authority?.schemaVersion !== 1 || authority.provider !== "github-actions"
    || authority.repository !== "HansenHomeAI/deed-corpus-transparency-log"
    || authority.workflow !== (genesis
      ? ".github/workflows/migrate-encrypted-genesis.yml"
      : ".github/workflows/append-encrypted-registry.yml")
    || !/^[0-9]+$/.test(authority.workflowRunId || "")
    || !/^[0-9]+$/.test(authority.workflowRunAttempt || "")
    || (!genesis && (authority.workflowRef
      !== "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/append-encrypted-registry.yml@refs/heads/main"
      || !/^[a-f0-9]{40}$/.test(authority.workflowTip || "")))) {
    throw new Error("A protected workflow authority is required for every encrypted-registry event.");
  }
}

export function validateAppendIntent(intent, expectedIndexSha256, state) {
  const protectedFields = new Set([
    "requestNonce", "oneUseNonce", "challengeNonce", "issuedAt", "consumedAt", "releasedAt",
    "sealedAt", "challengedAt", "releaseAuthority", "authority", "sequence", "previousEventSha256",
    "eventSha256", "workflowRunId", "workflowRunAttempt",
  ]);
  const allowedFields = new Set(["schemaVersion", "expectedPublicIndexSha256", "eventData", "response"]);
  const eventFields = new Set(["eventType", "caseId", "corpusId", "payload"]);
  const responseFields = new Set(["algorithm", "keyId", "publicKeyPem"]);
  if (Object.keys(intent || {}).some((field) => !allowedFields.has(field))
    || !isPlainObject(intent?.eventData)
    || Object.keys(intent.eventData).some((field) => !eventFields.has(field))
    || !isPlainObject(intent.eventData.payload) || !isPlainObject(intent?.response)
    || Object.keys(intent.response).some((field) => !responseFields.has(field))
    || containsProtectedKey(intent.eventData, protectedFields)) {
    throw new Error("The request attempts to supply workflow-owned chronology or authority fields.");
  }
  if (intent?.schemaVersion !== 4 || !CORPUS_EVENT_TYPES.has(intent.eventData.eventType)
    || intent.expectedPublicIndexSha256 !== expectedIndexSha256
    || intent.response.algorithm !== REQUEST_ALGORITHM
    || !/^[A-Za-z0-9._:-]{1,128}$/.test(intent.response.keyId || "")
    || typeof intent.response.publicKeyPem !== "string" || !intent.response.publicKeyPem.includes("PUBLIC KEY")
    || Buffer.byteLength(stableJson(intent.eventData)) > MAX_REQUEST_BYTES) {
    throw new Error("Encrypted append intent is invalid or stale.");
  }
  if (intent.eventData.eventType === "source-release") {
    const releaseFields = Object.keys(intent.eventData.payload);
    if (releaseFields.length !== 1 || releaseFields[0] !== "productCodeTip"
      || !/^[a-f0-9]{40}$/.test(intent.eventData.payload.productCodeTip || "")) {
      throw new Error("Source release callers may supply only productCodeTip; all custody fields are workflow-derived.");
    }
  } else if (intent.eventData.eventType === "review-seal") {
    const fields = new Set(["reviewRequestId", "reviewerWorkflowRunId", "reviewerWorkflowRunAttempt", "verifierPolicyTip"]);
    if (!hasExactKeys(intent.eventData.payload, fields)
      || !SHA256.test(intent.eventData.payload.reviewRequestId || "")
      || !/^[1-9][0-9]*$/.test(intent.eventData.payload.reviewerWorkflowRunId || "")
      || !/^[1-9][0-9]*$/.test(intent.eventData.payload.reviewerWorkflowRunAttempt || "")
      || !/^[a-f0-9]{40}$/.test(intent.eventData.payload.verifierPolicyTip || "")) {
      throw new Error("Review-seal callers may supply only one exact protected workflow reference; review facts are workflow-derived.");
    }
  }
  return intent;
}

function containsProtectedKey(value, protectedFields) {
  if (Array.isArray(value)) return value.some((item) => containsProtectedKey(item, protectedFields));
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(([key, item]) => protectedFields.has(key) || containsProtectedKey(item, protectedFields));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value, allowed) {
  return isPlainObject(value) && Object.keys(value).length === allowed.size
    && Object.keys(value).every((key) => allowed.has(key));
}

export function appendPlaintextEvent(state, intent, authority, now = new Date(), nonce = randomBytes(32).toString("hex"),
  { derivedReviewEvent = null } = {}) {
  validatePlaintextRegistry(state);
  validateAuthority(authority);
  if (!SHA256.test(nonce)) throw new Error("Workflow nonce must be 32 random bytes encoded as hex.");
  const before = structuredClone(state.registry);
  let event = structuredClone(intent.eventData);
  if (event.eventType === "review-seal") {
    const reference = event;
    if (!isPlainObject(derivedReviewEvent) || derivedReviewEvent.eventType !== "review-seal"
      || derivedReviewEvent.caseId !== reference.caseId || derivedReviewEvent.corpusId !== reference.corpusId
      || derivedReviewEvent.payload?.reviewerWorkflowRunId !== reference.payload.reviewerWorkflowRunId
      || derivedReviewEvent.payload?.reviewerWorkflowRunAttempt !== reference.payload.reviewerWorkflowRunAttempt
      || derivedReviewEvent.payload?.verifierPolicyTip !== reference.payload.verifierPolicyTip) {
      throw new Error("Review-seal append requires exact protected-workflow-derived evidence; caller facts are never accepted.");
    }
    event = structuredClone(derivedReviewEvent);
  } else if (derivedReviewEvent !== null) {
    throw new Error("Derived review evidence may be supplied only for review-seal append.");
  }
  event.issuedAt = now.toISOString();
  event.authority = structuredClone(authority);
  if (event.eventType === "source-release") {
    const assignment = [...before.events].reverse().find((candidate) => candidate.eventType === "assign"
      && candidate.caseId === event.caseId && candidate.corpusId === event.corpusId);
    const cohortRelease = before.events.find((candidate) => candidate.eventType === "source-release"
      && candidate.corpusId === event.corpusId);
    const priorReleaseCount = before.events.filter((candidate) => candidate.eventType === "source-release"
      && candidate.caseId === event.caseId && candidate.corpusId === event.corpusId).length;
    event.payload = {
      productCodeTip: event.payload.productCodeTip,
      assignmentEventSha256: assignment?.eventSha256,
      sourceSha256: assignment?.payload?.sourceSha256,
      encryptedSourceBundleRootSha256: assignment?.payload?.encryptedSourceBundleRootSha256,
      custodianIdentitySha256: assignment?.payload?.custodianIdentitySha256,
      priorReleaseCount,
      // The first protected handoff freezes the cohort. Every later case in
      // that corpus inherits the same workflow-owned freeze timestamp, so a
      // multi-case manifest has one canonical freeze without trusting caller
      // chronology.
      frozenAt: cohortRelease?.payload?.frozenAt || event.issuedAt,
      releaseTarget: "official-challenged-runner",
      releaseAuthority: "protected-custodian-workflow",
      releasedAt: event.issuedAt,
    };
  } else if (event.eventType === "consume") {
    event.payload.oneUseNonce = nonce;
    event.payload.consumedAt = event.issuedAt;
  } else if (["review-seal", "execution-seal", "judge-seal"].includes(event.eventType)) {
    event.payload.sealedAt = event.issuedAt;
  } else if (event.eventType === "judge-challenge") {
    event.payload.challengeNonce = nonce;
    event.payload.challengedAt = event.issuedAt;
  }
  const next = appendCorpusRegistryEvent(before, event);
  const checked = validateCorpusRegistry({ registry: next, previousRegistry: before });
  if (!checked.ok) throw new CorpusRegistrySemanticError(checked.errors);
  state.registry = next;
  validatePlaintextRegistry(state);
  return next.events.at(-1);
}

export function buildProtectedAppendReceipt({ intent, event, state, authority, publicCommitment }) {
  validatePlaintextRegistry(state);
  validateAuthority(authority);
  const requestSha256 = sha256(stableJson(intent));
  const registryValidation = validateCorpusRegistry({ registry: state.registry });
  if (!registryValidation.ok) throw new Error("Protected receipt cannot bind an invalid corpus registry.");
  const receipt = {
    schemaVersion: 1,
    kind: "spaceport-deed-corpus-protected-append-receipt",
    bindingNonce: randomBytes(32).toString("hex"),
    requestSha256,
    eventType: event.eventType,
    corpusId: event.corpusId,
    campaign: event.payload?.campaign || null,
    eventSha256: event.eventSha256,
    registryRootSha256: registryValidation.rootSha256,
    registryEventCount: registryValidation.eventCount,
    registry: structuredClone(state.registry),
    issuedAt: event.issuedAt,
    authority: {
      repository: authority.repository,
      workflow: authority.workflow,
      workflowRef: authority.workflowRef,
      workflowTip: authority.workflowTip,
      verifierPolicyTip: event.payload?.verifierPolicyTip || authority.workflowTip,
      workflowRunId: authority.workflowRunId,
      workflowRunAttempt: authority.workflowRunAttempt,
    },
    publicCommitment: structuredClone(publicCommitment),
    workflowOwned: workflowOwnedReceiptFields(event),
    execution: event.eventType === "execution-seal" ? {
      executionRootSha256: event.payload.executionRootSha256,
      executionIndexSha256: event.payload.executionIndexSha256,
      executionCount: event.payload.executionCount,
      productCodeTip: event.payload.productCodeTip || null,
      verifierPolicyTip: event.payload.verifierPolicyTip || null,
      executionAttestationSubjectSha256: event.payload.executionAttestationSubjectSha256 || null,
      executionAttestationBundleRootSha256: event.payload.executionAttestationBundleRootSha256 || null,
    } : null,
  };
  validateProtectedReceipt(receipt, { expectedRequestSha256: requestSha256,
    expectedCiphertextSha256: publicCommitment.ciphertextSha256 });
  const receiptBytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  const envelopeBase64url = encryptHybridPayload(receipt, intent.response.publicKeyPem, intent.response.keyId,
    MAX_RECEIPT_BYTES, "Protected append receipt exceeds the 32-megabyte limit.", { exactPlaintextBytes: receiptBytes });
  const encrypted = {
    schemaVersion: 1,
    kind: "spaceport-deed-corpus-encrypted-append-receipt",
    algorithm: REQUEST_ALGORITHM,
    keyId: intent.response.keyId,
    responseForRequestSha256: requestSha256,
    plaintextReceiptSha256: sha256(receiptBytes),
    envelopeBase64url,
  };
  const bytes = Buffer.from(`${JSON.stringify(encrypted, null, 2)}\n`, "utf8");
  return { requestSha256, receipt, receiptBytes, encrypted, bytes, encryptedReceiptSha256: sha256(bytes) };
}

export function buildProtectedAppendRejectionReceipt({ intent, state, authority, publicCommitment, errors, rejectedAt }) {
  validatePlaintextRegistry(state);
  validateAuthority(authority);
  const requestSha256 = sha256(stableJson(intent));
  const registryValidation = validateCorpusRegistry({ registry: state.registry });
  if (!registryValidation.ok) throw new Error("Protected rejection receipt cannot bind an invalid corpus registry.");
  const receipt = {
    schemaVersion: 1,
    kind: "spaceport-deed-corpus-protected-append-rejection-receipt",
    bindingNonce: randomBytes(32).toString("hex"),
    requestSha256,
    eventType: intent.eventData.eventType,
    caseId: intent.eventData.caseId,
    corpusId: intent.eventData.corpusId,
    errors: structuredClone(errors),
    registryRootSha256: registryValidation.rootSha256,
    registryEventCount: registryValidation.eventCount,
    registry: structuredClone(state.registry),
    rejectedAt,
    authority: {
      repository: authority.repository,
      workflow: authority.workflow,
      workflowRef: authority.workflowRef,
      workflowTip: authority.workflowTip,
      workflowRunId: authority.workflowRunId,
      workflowRunAttempt: authority.workflowRunAttempt,
    },
    publicCommitment: structuredClone(publicCommitment),
  };
  validateProtectedRejectionReceipt(receipt, { expectedRequestSha256: requestSha256,
    expectedCiphertextSha256: publicCommitment.ciphertextSha256 });
  const receiptBytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  const envelopeBase64url = encryptHybridPayload(receipt, intent.response.publicKeyPem, intent.response.keyId,
    MAX_RECEIPT_BYTES, "Protected rejection receipt exceeds the 32-megabyte limit.", {
      paddedPlaintextBytes: rejectionPaddedPlaintextBytes(receipt.registry),
      exactPlaintextBytes: receiptBytes,
    });
  const encrypted = {
    schemaVersion: 1,
    kind: "spaceport-deed-corpus-encrypted-append-receipt",
    algorithm: REQUEST_ALGORITHM,
    keyId: intent.response.keyId,
    responseForRequestSha256: requestSha256,
    plaintextReceiptSha256: sha256(receiptBytes),
    envelopeBase64url,
  };
  const bytes = Buffer.from(`${JSON.stringify(encrypted, null, 2)}\n`, "utf8");
  return { requestSha256, receipt, receiptBytes, encrypted, bytes, encryptedReceiptSha256: sha256(bytes) };
}

export function decryptProtectedAppendReceipt(bytes, privateKeyPem, expectedKeyId,
  { expectedRequestSha256, expectedCiphertextSha256, expectedSignerDigest = null, returnReceiptBytes = false } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_RECEIPT_ARTIFACT_BYTES) {
    throw new Error("Encrypted receipt exceeds the 64-megabyte artifact limit.");
  }
  let encrypted;
  try { encrypted = JSON.parse(Buffer.from(bytes).toString("utf8")); }
  catch { throw new Error("Encrypted receipt is not valid JSON."); }
  const fields = new Set(["schemaVersion", "kind", "algorithm", "keyId", "responseForRequestSha256",
    "plaintextReceiptSha256", "envelopeBase64url"]);
  if (Object.keys(encrypted || {}).some((key) => !fields.has(key))
    || encrypted?.schemaVersion !== 1 || encrypted.kind !== "spaceport-deed-corpus-encrypted-append-receipt"
    || encrypted.algorithm !== REQUEST_ALGORITHM || encrypted.keyId !== expectedKeyId
    || encrypted.responseForRequestSha256 !== expectedRequestSha256
    || !SHA256.test(encrypted.plaintextReceiptSha256 || "")
    || Buffer.from(bytes).toString("utf8") !== `${JSON.stringify(encrypted, null, 2)}\n`) {
    throw new Error("Encrypted receipt schema, key, request binding, or canonical bytes are invalid.");
  }
  const plaintext = decryptHybridPayload(encrypted.envelopeBase64url, privateKeyPem, expectedKeyId,
    MAX_RECEIPT_BYTES, "Decrypted protected append receipt exceeds the 32-megabyte limit.", {
      returnPlaintextBytes: true,
    });
  let receiptBytes = plaintext;
  let paddedPlaintextBytes = null;
  if (encrypted.plaintextReceiptSha256 !== sha256(receiptBytes)) {
    let padded;
    try { padded = JSON.parse(plaintext.toString("utf8")); }
    catch { throw new Error("Attested encrypted wrapper does not bind the decrypted receipt bytes."); }
    const paddedFields = new Set(["schemaVersion", "kind", "payloadBase64url", "padding"]);
    if (!hasExactKeys(padded, paddedFields) || padded.schemaVersion !== 1 || padded.kind !== PADDED_PAYLOAD_KIND
      || !isCanonicalBase64url(padded.payloadBase64url) || typeof padded.padding !== "string"
      || !/^0*$/.test(padded.padding) || !plaintext.equals(Buffer.from(`${JSON.stringify(padded)}\n`, "utf8"))) {
      throw new Error("Attested encrypted wrapper does not bind the decrypted receipt bytes.");
    }
    paddedPlaintextBytes = plaintext.length;
    receiptBytes = Buffer.from(padded.payloadBase64url, "base64url");
    if (receiptBytes.length > MAX_RECEIPT_BYTES || encrypted.plaintextReceiptSha256 !== sha256(receiptBytes)) {
      throw new Error("Attested encrypted wrapper does not bind the decrypted receipt bytes.");
    }
  }
  let receipt;
  try { receipt = JSON.parse(receiptBytes.toString("utf8")); }
  catch { throw new Error("Decrypted protected append receipt is not valid JSON."); }
  if (receipt?.kind === "spaceport-deed-corpus-protected-append-rejection-receipt") {
    if (paddedPlaintextBytes !== rejectionPaddedPlaintextBytes(receipt.registry)) {
      throw new Error("Protected rejection receipt lacks its fixed authenticated padding class.");
    }
    validateProtectedRejectionReceipt(receipt, { expectedRequestSha256, expectedCiphertextSha256, expectedSignerDigest });
  } else {
    if (paddedPlaintextBytes !== null) throw new Error("Successful protected append receipts must not be padded.");
    validateProtectedReceipt(receipt, { expectedRequestSha256, expectedCiphertextSha256, expectedSignerDigest });
  }
  return returnReceiptBytes ? { receipt, receiptBytes } : receipt;
}

function validateProtectedRejectionReceipt(receipt,
  { expectedRequestSha256, expectedCiphertextSha256, expectedSignerDigest = null }) {
  const fields = new Set([
    "schemaVersion", "kind", "bindingNonce", "requestSha256", "eventType", "caseId", "corpusId", "errors",
    "registryRootSha256", "registryEventCount", "registry", "rejectedAt", "authority", "publicCommitment",
  ]);
  const authorityFields = new Set([
    "repository", "workflow", "workflowRef", "workflowTip", "workflowRunId", "workflowRunAttempt",
  ]);
  const commitmentFields = new Set(["sequence", "publicIndexSha256", "envelopeSha256", "ciphertextSha256"]);
  const authority = receipt?.authority || {};
  const commitment = receipt?.publicCommitment || {};
  const checked = validateCorpusRegistry({ registry: receipt?.registry });
  const errorsValid = Array.isArray(receipt?.errors) && receipt.errors.length > 0
    && receipt.errors.every((error) => error && typeof error === "object" && !Array.isArray(error)
      && Object.keys(error).length === 2 && typeof error.code === "string" && error.code.length > 0
      && typeof error.message === "string" && error.message.length > 0);
  if (!hasExactKeys(receipt, fields) || !hasExactKeys(authority, authorityFields)
    || !hasExactKeys(commitment, commitmentFields) || !checked.ok || !errorsValid
    || receipt.schemaVersion !== 1 || receipt.kind !== "spaceport-deed-corpus-protected-append-rejection-receipt"
    || !SHA256.test(receipt.bindingNonce || "")
    || receipt.requestSha256 !== expectedRequestSha256 || !CORPUS_EVENT_TYPES.has(receipt.eventType)
    || (receipt.caseId !== null && !/^dp-[a-f0-9]{12}$/.test(receipt.caseId || ""))
    || (receipt.corpusId !== null && !/^corpus-[a-f0-9]{16}$/.test(receipt.corpusId || ""))
    || receipt.registryRootSha256 !== checked.rootSha256 || receipt.registryEventCount !== checked.eventCount
    || !validIso(receipt.rejectedAt) || authority.repository !== "HansenHomeAI/deed-corpus-transparency-log"
    || authority.workflow !== ".github/workflows/append-encrypted-registry.yml"
    || authority.workflowRef
      !== "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/append-encrypted-registry.yml@refs/heads/main"
    || !/^[a-f0-9]{40}$/.test(authority.workflowTip || "")
    || (expectedSignerDigest !== null && authority.workflowTip !== expectedSignerDigest)
    || !/^[0-9]+$/.test(authority.workflowRunId || "") || !/^[0-9]+$/.test(authority.workflowRunAttempt || "")
    || !Number.isInteger(commitment.sequence) || commitment.sequence < 1
    || !SHA256.test(commitment.publicIndexSha256 || "") || !SHA256.test(commitment.envelopeSha256 || "")
    || !SHA256.test(commitment.ciphertextSha256 || "") || commitment.ciphertextSha256 !== expectedCiphertextSha256) {
    throw new Error("Protected rejection receipt failed its request, registry, authority, or public commitment binding.");
  }
}

function workflowOwnedReceiptFields(event) {
  if (event.eventType === "consume") return { oneUseNonce: event.payload.oneUseNonce, consumedAt: event.payload.consumedAt };
  if (["review-seal", "execution-seal", "judge-seal"].includes(event.eventType)) return { sealedAt: event.payload.sealedAt };
  if (event.eventType === "judge-challenge") return { challengeNonce: event.payload.challengeNonce, challengedAt: event.payload.challengedAt };
  if (event.eventType === "source-release") return { frozenAt: event.payload.frozenAt, releasedAt: event.payload.releasedAt };
  return {};
}

function validateProtectedReceipt(receipt, { expectedRequestSha256, expectedCiphertextSha256, expectedSignerDigest = null }) {
  const commitment = receipt?.publicCommitment || {};
  const authority = receipt?.authority || {};
  const receiptFields = new Set([
    "schemaVersion", "kind", "bindingNonce", "requestSha256", "eventType", "corpusId", "campaign", "eventSha256",
    "registryRootSha256", "registryEventCount", "registry", "issuedAt", "authority", "publicCommitment", "workflowOwned", "execution",
  ]);
  const authorityFields = new Set([
    "repository", "workflow", "workflowRef", "workflowTip", "verifierPolicyTip", "workflowRunId", "workflowRunAttempt",
  ]);
  const commitmentFields = new Set(["sequence", "publicIndexSha256", "envelopeSha256", "ciphertextSha256"]);
  const workflowOwnedFields = receipt?.eventType === "consume" ? new Set(["oneUseNonce", "consumedAt"])
    : receipt?.eventType === "judge-challenge" ? new Set(["challengeNonce", "challengedAt"])
      : receipt?.eventType === "source-release" ? new Set(["frozenAt", "releasedAt"])
        : (["review-seal", "execution-seal", "judge-seal"].includes(receipt?.eventType))
          ? new Set(["sealedAt"]) : new Set();
  const executionFields = new Set([
    "executionRootSha256", "executionIndexSha256", "executionCount", "productCodeTip", "verifierPolicyTip",
    "executionAttestationSubjectSha256", "executionAttestationBundleRootSha256",
  ]);
  const receiptBytes = Buffer.byteLength(JSON.stringify(receipt || {}), "utf8");
  const registryValidation = validateCorpusRegistry({ registry: receipt?.registry });
  const registryTip = receipt?.registry?.events?.at?.(-1);
  if (!hasExactKeys(receipt, receiptFields) || !hasExactKeys(authority, authorityFields)
    || !hasExactKeys(commitment, commitmentFields) || !hasExactKeys(receipt?.workflowOwned, workflowOwnedFields)
    || (receipt?.eventType === "execution-seal" && !hasExactKeys(receipt?.execution, executionFields))
    || receiptBytes > MAX_RECEIPT_BYTES || !registryValidation.ok
    || receipt?.schemaVersion !== 1 || receipt.kind !== "spaceport-deed-corpus-protected-append-receipt"
    || !SHA256.test(receipt.bindingNonce || "")
    || receipt.requestSha256 !== expectedRequestSha256 || !CORPUS_EVENT_TYPES.has(receipt.eventType)
    || (receipt.corpusId !== null && !/^corpus-[a-f0-9]{16}$/.test(receipt.corpusId || ""))
    || !SHA256.test(receipt.eventSha256 || "") || !SHA256.test(receipt.registryRootSha256 || "")
    || !Number.isInteger(receipt.registryEventCount) || receipt.registryEventCount < 1 || !validIso(receipt.issuedAt)
    || receipt.registryRootSha256 !== registryValidation.rootSha256
    || receipt.registryEventCount !== registryValidation.eventCount
    || registryTip?.eventSha256 !== receipt.eventSha256 || registryTip?.eventType !== receipt.eventType
    || registryTip?.corpusId !== receipt.corpusId || registryTip?.issuedAt !== receipt.issuedAt
    || receipt.campaign !== (registryTip?.payload?.campaign || null)
    || registryTip?.authority?.repository !== authority.repository
    || registryTip?.authority?.workflow !== authority.workflow
    || registryTip?.authority?.workflowRef !== authority.workflowRef
    || registryTip?.authority?.workflowTip !== authority.workflowTip
    || registryTip?.authority?.workflowRunId !== authority.workflowRunId
    || registryTip?.authority?.workflowRunAttempt !== authority.workflowRunAttempt
    || authority.verifierPolicyTip !== (registryTip?.payload?.verifierPolicyTip || authority.workflowTip)
    || authority.repository !== "HansenHomeAI/deed-corpus-transparency-log"
    || authority.workflow !== ".github/workflows/append-encrypted-registry.yml"
    || authority.workflowRef
      !== "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/append-encrypted-registry.yml@refs/heads/main"
    || !/^[a-f0-9]{40}$/.test(authority.workflowTip || "")
    || (expectedSignerDigest !== null && authority.workflowTip !== expectedSignerDigest)
    || !/^[a-f0-9]{40}$/.test(authority.verifierPolicyTip || "")
    || !/^[0-9]+$/.test(authority.workflowRunId || "") || !/^[0-9]+$/.test(authority.workflowRunAttempt || "")
    || !Number.isInteger(commitment.sequence) || commitment.sequence < 1
    || !SHA256.test(commitment.publicIndexSha256 || "") || !SHA256.test(commitment.envelopeSha256 || "")
    || !SHA256.test(commitment.ciphertextSha256 || "") || commitment.ciphertextSha256 !== expectedCiphertextSha256) {
    throw new Error("Protected receipt failed its request, event, registry, authority, or public commitment binding.");
  }
  if (receipt.eventType === "consume"
    && (!SHA256.test(receipt.workflowOwned?.oneUseNonce || "") || receipt.workflowOwned?.consumedAt !== receipt.issuedAt)) {
    throw new Error("Protected consume receipt lacks its workflow nonce or timestamp.");
  }
  if (["review-seal", "execution-seal", "judge-seal"].includes(receipt.eventType)
    && receipt.workflowOwned?.sealedAt !== receipt.issuedAt) {
    throw new Error("Protected seal receipt lacks its workflow timestamp.");
  }
  if (receipt.eventType === "judge-challenge"
    && (!SHA256.test(receipt.workflowOwned?.challengeNonce || "") || receipt.workflowOwned?.challengedAt !== receipt.issuedAt)) {
    throw new Error("Protected judge receipt lacks its workflow nonce or timestamp.");
  }
  if (receipt.eventType === "source-release"
    && (!validIso(receipt.workflowOwned?.frozenAt)
      || Date.parse(receipt.workflowOwned.frozenAt) > Date.parse(receipt.issuedAt)
      || receipt.workflowOwned?.releasedAt !== receipt.issuedAt)) {
    throw new Error("Protected release receipt lacks its workflow timestamps.");
  }
  if (receipt.eventType === "execution-seal") {
    const execution = receipt.execution || {};
    const optionalCertification = [execution.productCodeTip, execution.verifierPolicyTip,
      execution.executionAttestationSubjectSha256, execution.executionAttestationBundleRootSha256];
    const certificationOk = optionalCertification.every((value) => value === null)
      || (/^[a-f0-9]{40}$/.test(execution.productCodeTip || "")
        && /^[a-f0-9]{40}$/.test(execution.verifierPolicyTip || "")
        && execution.executionAttestationSubjectSha256 === execution.executionIndexSha256
        && SHA256.test(execution.executionAttestationBundleRootSha256 || ""));
    if (!SHA256.test(execution.executionRootSha256 || "") || !SHA256.test(execution.executionIndexSha256 || "")
      || !Number.isInteger(execution.executionCount) || execution.executionCount < 1 || !certificationOk) {
      throw new Error("Protected execution receipt lacks exact execution or hosted-certification bindings.");
    }
  } else if (receipt.execution !== null) {
    throw new Error("Only execution-seal receipts may carry execution bindings.");
  }
}

function validIso(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function decodeAesKey(base64) {
  const key = Buffer.from(base64 || "", "base64");
  if (key.length !== 32 || key.toString("base64") !== base64) {
    throw new Error("REGISTRY_AES_KEY_BASE64 must be the canonical base64 encoding of exactly 32 bytes.");
  }
  return key;
}

export function encryptState(state, key, iv = randomBytes(IV_BYTES)) {
  validatePlaintextRegistry(state);
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("AES-256-GCM requires a 32-byte key.");
  if (!Buffer.isBuffer(iv) || iv.length !== IV_BYTES) throw new Error("AES-GCM requires a 12-byte IV.");
  const plaintext = Buffer.from(`${JSON.stringify(state)}\n`, "utf8");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(STATE_MAGIC);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([STATE_MAGIC, Buffer.from([STATE_FORMAT_VERSION]), iv, tag, ciphertext]);
}

export function decryptState(bytes, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("AES-256-GCM requires a 32-byte key.");
  const minimum = STATE_MAGIC.length + 1 + IV_BYTES + TAG_BYTES + 1;
  if (!Buffer.isBuffer(bytes) || bytes.length < minimum || !bytes.subarray(0, 4).equals(STATE_MAGIC)
    || bytes[4] !== STATE_FORMAT_VERSION) {
    throw new Error("Encrypted registry state format is invalid.");
  }
  const ivStart = 5;
  const tagStart = ivStart + IV_BYTES;
  const dataStart = tagStart + TAG_BYTES;
  const decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(ivStart, tagStart));
  decipher.setAAD(STATE_MAGIC);
  decipher.setAuthTag(bytes.subarray(tagStart, dataStart));
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(bytes.subarray(dataStart)), decipher.final()]);
  } catch {
    throw new Error("Encrypted registry state authentication failed.");
  }
  let state;
  try {
    state = JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("Decrypted registry state is not valid JSON.");
  }
  return validatePlaintextRegistry(state);
}

export function encryptRequest(intent, publicKeyPem, keyId) {
  const encoded = encryptHybridPayload(intent, publicKeyPem, keyId, MAX_REQUEST_BYTES,
    "Append request exceeds the 32-kilobyte plaintext limit.");
  if (encoded.length > MAX_REQUEST_ENVELOPE_CHARS) {
    throw new Error("Encrypted append request exceeds the 60-kilobyte workflow-dispatch limit.");
  }
  return encoded;
}

function encryptHybridPayload(value, publicKeyPem, keyId, maximumPlaintextBytes, sizeError,
  { paddedPlaintextBytes = null, exactPlaintextBytes = null } = {}) {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId || "")) throw new Error("A non-sensitive request key id is required.");
  const requestKey = randomBytes(32);
  const iv = randomBytes(IV_BYTES);
  let plaintext = exactPlaintextBytes === null
    ? Buffer.from(`${JSON.stringify(value)}\n`, "utf8") : Buffer.from(exactPlaintextBytes);
  if (paddedPlaintextBytes !== null) {
    if (!Number.isInteger(paddedPlaintextBytes) || paddedPlaintextBytes < 1 || paddedPlaintextBytes > maximumPlaintextBytes) {
      throw new Error("Protected receipt padding target is invalid.");
    }
    const wrapper = { schemaVersion: 1, kind: PADDED_PAYLOAD_KIND,
      payloadBase64url: plaintext.toString("base64url"), padding: "" };
    const emptyBytes = Buffer.from(`${JSON.stringify(wrapper)}\n`, "utf8");
    if (emptyBytes.length > paddedPlaintextBytes) throw new Error(sizeError);
    wrapper.padding = "0".repeat(paddedPlaintextBytes - emptyBytes.length);
    plaintext = Buffer.from(`${JSON.stringify(wrapper)}\n`, "utf8");
    if (plaintext.length !== paddedPlaintextBytes) throw new Error("Protected receipt padding is not exact.");
  }
  if (plaintext.length > maximumPlaintextBytes) throw new Error(sizeError);
  const cipher = createCipheriv("aes-256-gcm", requestKey, iv);
  const aad = Buffer.from(`${REQUEST_ALGORITHM}:${keyId}`, "utf8");
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope = {
    schemaVersion: 1,
    algorithm: REQUEST_ALGORITHM,
    keyId,
    encryptedKeyBase64url: publicEncrypt({ key: publicKeyPem, oaepHash: "sha256", padding: constants.RSA_PKCS1_OAEP_PADDING }, requestKey).toString("base64url"),
    ivBase64url: iv.toString("base64url"),
    authTagBase64url: cipher.getAuthTag().toString("base64url"),
    ciphertextBase64url: ciphertext.toString("base64url"),
  };
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

export function decryptRequest(encoded, privateKeyPem, expectedKeyId) {
  if (typeof encoded !== "string" || encoded.length > MAX_REQUEST_ENVELOPE_CHARS) {
    throw new Error("Encrypted append request exceeds the 60-kilobyte workflow-dispatch limit.");
  }
  return decryptHybridPayload(encoded, privateKeyPem, expectedKeyId, MAX_REQUEST_BYTES,
    "Decrypted append request exceeds the 32-kilobyte plaintext limit.");
}

function decryptHybridPayload(encoded, privateKeyPem, expectedKeyId, maximumPlaintextBytes, sizeError,
  { allowPadded = false, returnPaddingMetadata = false, returnPlaintextBytes = false } = {}) {
  let envelope;
  try {
    const bytes = Buffer.from(encoded || "", "base64url");
    if (bytes.toString("base64url") !== encoded) throw new Error();
    envelope = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("Encrypted request envelope is not canonical base64url JSON.");
  }
  const envelopeFields = new Set([
    "schemaVersion", "algorithm", "keyId", "encryptedKeyBase64url", "ivBase64url",
    "authTagBase64url", "ciphertextBase64url",
  ]);
  if (Object.keys(envelope || {}).some((key) => !envelopeFields.has(key))
    || envelope?.schemaVersion !== 1 || envelope.algorithm !== REQUEST_ALGORITHM
    || envelope.keyId !== expectedKeyId || !isCanonicalBase64url(envelope.encryptedKeyBase64url)
    || !isCanonicalBase64url(envelope.ivBase64url) || !isCanonicalBase64url(envelope.authTagBase64url)
    || !isCanonicalBase64url(envelope.ciphertextBase64url)) {
    throw new Error("Encrypted request envelope schema or key id is invalid.");
  }
  let requestKey;
  try {
    requestKey = privateDecrypt({ key: privateKeyPem, oaepHash: "sha256", padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.encryptedKeyBase64url, "base64url"));
  } catch {
    throw new Error("RSA-OAEP request-key decryption failed.");
  }
  if (requestKey.length !== 32) throw new Error("Decrypted request key is not 256 bits.");
  const iv = Buffer.from(envelope.ivBase64url, "base64url");
  const tag = Buffer.from(envelope.authTagBase64url, "base64url");
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error("Encrypted request IV or tag length is invalid.");
  const decipher = createDecipheriv("aes-256-gcm", requestKey, iv);
  decipher.setAAD(Buffer.from(`${REQUEST_ALGORITHM}:${envelope.keyId}`, "utf8"));
  decipher.setAuthTag(tag);
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertextBase64url, "base64url")), decipher.final()]);
  } catch {
    throw new Error("Encrypted request authentication failed.");
  }
  if (plaintext.length > maximumPlaintextBytes) throw new Error(sizeError);
  if (returnPlaintextBytes) return plaintext;
  try {
    let valueBytes = plaintext;
    let value = JSON.parse(valueBytes.toString("utf8"));
    let paddedPlaintextBytes = null;
    if (value?.kind === PADDED_PAYLOAD_KIND) {
      const fields = new Set(["schemaVersion", "kind", "payloadBase64url", "padding"]);
      if (!allowPadded || !hasExactKeys(value, fields) || value.schemaVersion !== 1
        || !isCanonicalBase64url(value.payloadBase64url)
        || typeof value.padding !== "string" || !/^0*$/.test(value.padding)) {
        throw new Error("invalid padded payload");
      }
      paddedPlaintextBytes = plaintext.length;
      valueBytes = Buffer.from(value.payloadBase64url, "base64url");
      if (valueBytes.length > maximumPlaintextBytes) throw new Error(sizeError);
      value = JSON.parse(valueBytes.toString("utf8"));
    }
    return returnPaddingMetadata ? { value, valueBytes, paddedPlaintextBytes } : value;
  } catch {
    throw new Error("Decrypted append request is not valid JSON.");
  }
}

export function rejectionPaddedPlaintextBytes(registry) {
  const registryBytes = Buffer.byteLength(JSON.stringify(registry || {}), "utf8");
  // Rejection padding carries the exact retained receipt bytes as base64url,
  // so reserve its 4/3 expansion without depending on the error class or the
  // rejected candidate's private fields.
  const encodedRegistryCeiling = Math.ceil((registryBytes * 4) / 3);
  const target = Math.ceil((encodedRegistryCeiling + REJECTION_PADDING_HEADROOM_BYTES) / REJECTION_PADDING_BLOCK_BYTES)
    * REJECTION_PADDING_BLOCK_BYTES;
  if (target < 1 || target > MAX_RECEIPT_BYTES) {
    throw new Error("Protected rejection receipt cannot fit its fixed authenticated padding class.");
  }
  return target;
}

function isCanonicalBase64url(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  return Buffer.from(value, "base64url").toString("base64url") === value;
}
