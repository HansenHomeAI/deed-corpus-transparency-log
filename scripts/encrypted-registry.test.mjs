import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  appendCorpusRegistryEvent,
  corpusRegistryRootSha256,
  validateCorpusRegistry,
} from "./corpus-registry-semantics.mjs";
import {
  ciphertextPath,
  decryptProtectedAppendReceipt,
  decryptRequest,
  decryptState,
  emptyPublicIndex,
  encryptRequest,
  indexSha256,
  rejectionPaddedPlaintextBytes,
  sha256,
  validatePublicIndex,
} from "./registry-core.mjs";

const repository = dirname(dirname(new URL(import.meta.url).pathname));
const appendScript = join(repository, "scripts/append-encrypted-registry.mjs");
const migrationScript = join(repository, "scripts/migrate-encrypted-genesis.mjs");
const verifyScript = join(repository, "scripts/verify-index.mjs");
const encryptStateScript = join(repository, "scripts/encrypt-state.mjs");
const decryptStateScript = join(repository, "scripts/decrypt-state.mjs");
const encryptRequestScript = join(repository, "scripts/encrypt-request.mjs");
const decryptReceiptScript = join(repository, "scripts/decrypt-receipt.mjs");
const appendWorkflow = readFileSync(join(repository, ".github/workflows/append-encrypted-registry.yml"), "utf8");
const migrationWorkflow = readFileSync(join(repository, ".github/workflows/migrate-encrypted-genesis.yml"), "utf8");
const REQUEST_KEY_ID = "test-request-key-2026-07";
const STATE_KEY_ID = "test-state-key-2026-07";
const RESPONSE_KEY_ID = "test-response-key-2026-07";
const CORPUS_ID = `corpus-${hash("corpus").slice(0, 16)}`;
const requestKeys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const responseKeys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

test("registry workflows refuse non-main or stale refs before loading protected key material", () => {
  for (const workflow of [appendWorkflow, migrationWorkflow]) {
    const guard = workflow.indexOf("Refuse any unprotected or stale workflow ref");
    const secretUse = workflow.search(/secrets\.(DEED_REGISTRY_REQUEST_PRIVATE_KEY_PEM|DEED_REGISTRY_AES_KEY_BASE64|DEED_REGISTRY_SOURCE_TOKEN)/);
    assert.ok(guard >= 0 && secretUse > guard);
    assert.match(workflow, /test "\$GITHUB_REF" = refs\/heads\/main/);
    assert.match(workflow, /test "\$\(git rev-parse FETCH_HEAD\)" = "\$GITHUB_SHA"/);
  }
  const upload = appendWorkflow.indexOf("Upload replay-addressed encrypted receipt artifact");
  const rejection = appendWorkflow.indexOf("Fail the append after retaining its encrypted rejection receipt");
  const cleanup = appendWorkflow.indexOf("Remove secret key material");
  assert.ok(upload >= 0 && rejection > upload && cleanup > rejection);
  assert.match(appendWorkflow, /if: steps\.append\.outputs\.appended == 'false'[\s\S]*?exit 1/);
  assert.match(appendWorkflow, /name: Remove secret key material\n\s+if: always\(\)/);
});

test("same-prefix semantic rejection diagnostics have an indistinguishable fixed encrypted size", () => {
  const buildAfterAssignment = (kind) => {
    const fixture = createFixture();
    const first = assignmentBody(0);
    assert.equal(append(fixture, intentFor(fixture, first), "7101").status, 0);
    const current = latestState(fixture).registry.events.at(-1);
    const body = kind === "invalid"
      ? assignmentBody(1, { custodyMode: "untrusted" })
      : assignmentBody(1, { sourceSha256: current.payload.sourceSha256 });
    const intent = intentFor(fixture, body);
    const result = append(fixture, intent, kind === "invalid" ? "7102" : "7103");
    assertEncryptedRejection(result, intent, fixture,
      kind === "invalid" ? "REGISTRY_ASSIGN_INVALID" : "REGISTRY_CROSS_CORPUS_REUSE");
    return { bytes: readFileSync(join(result.receiptDirectory, "receipt.encrypted.json")), fixture, intent, result };
  };
  const invalid = buildAfterAssignment("invalid");
  const duplicate = buildAfterAssignment("duplicate");
  assert.equal(invalid.bytes.length, duplicate.bytes.length);
  assert.ok(invalid.bytes.length > 1024 * 1024);
  for (const code of ["REGISTRY_ASSIGN_INVALID", "REGISTRY_CROSS_CORPUS_REUSE"]) {
    assert.equal(invalid.bytes.includes(Buffer.from(code)), false);
    assert.equal(duplicate.bytes.includes(Buffer.from(code)), false);
  }

  const pristineBodies = [
    [assignmentBody(0, { custodyMode: "untrusted" }), "REGISTRY_ASSIGN_INVALID"],
    [truthBody({ caseId: caseId(0), corpusId: CORPUS_ID, eventSha256: hash("missing") }), "REGISTRY_TRUTH_SEAL_INVALID"],
    [sourceReleaseBody({ caseId: caseId(0), corpusId: CORPUS_ID }), "REGISTRY_SOURCE_RELEASE_INVALID"],
    [consumeBody([]), "REGISTRY_CONSUME_INVALID"],
    [executionBody(hash("missing-consume")), "REGISTRY_EXECUTION_SEAL_INVALID"],
    [challengeBody(hash("missing-execution")), "REGISTRY_JUDGE_CHALLENGE_INVALID"],
    [judgeSealBody(hash("missing-challenge")), "REGISTRY_JUDGE_SEAL_INVALID"],
  ];
  const pristineSizes = pristineBodies.map(([body, code], offset) => {
    const fixture = createFixture();
    const intent = intentFor(fixture, body);
    const result = append(fixture, intent, String(7300 + offset));
    assertEncryptedRejection(result, intent, fixture, code);
    return readFileSync(join(result.receiptDirectory, "receipt.encrypted.json")).length;
  });
  assert.equal(new Set(pristineSizes).size, 1);

  const buildMultiError = (multi) => {
    const fixture = createFixture();
    const sharedInstrument = hash("padding-shared-instrument");
    for (let index = 0; index < 2; index += 1) {
      assert.equal(append(fixture, intentFor(fixture,
        assignmentBody(index, { instrumentIdHash: sharedInstrument })), String(7400 + index)).status, 0);
    }
    const first = latestState(fixture).registry.events.find((event) => event.eventType === "assign");
    const body = multi
      ? assignmentBody(2, { instrumentIdHash: sharedInstrument, sourceSha256: first.payload.sourceSha256 })
      : assignmentBody(2, { custodyMode: "untrusted" });
    const intent = intentFor(fixture, body);
    const result = append(fixture, intent, multi ? "7402" : "7403");
    const receipt = assertEncryptedRejection(result, intent, fixture,
      multi ? "REGISTRY_INSTRUMENT_REUSE" : "REGISTRY_ASSIGN_INVALID");
    if (multi) assert.ok(receipt.errors.length >= 2);
    return readFileSync(join(result.receiptDirectory, "receipt.encrypted.json")).length;
  };
  assert.equal(buildMultiError(false), buildMultiError(true));

  const outer = JSON.parse(invalid.bytes.toString("utf8"));
  const envelope = JSON.parse(Buffer.from(outer.envelopeBase64url, "base64url").toString("utf8"));
  envelope.ciphertextBase64url = `${envelope.ciphertextBase64url[0] === "A" ? "B" : "A"}${envelope.ciphertextBase64url.slice(1)}`;
  outer.envelopeBase64url = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
  const tampered = Buffer.from(`${JSON.stringify(outer, null, 2)}\n`, "utf8");
  assert.throws(() => decryptProtectedAppendReceipt(tampered, responseKeys.privateKey, RESPONSE_KEY_ID, {
    expectedRequestSha256: sha256(stableJson(invalid.intent)),
    expectedCiphertextSha256: readIndex(invalid.fixture).envelopes.at(-1).ciphertextSha256,
  }), /authentication failed/i);

  assert.equal(rejectionPaddedPlaintextBytes({}), 1024 * 1024);
  assert.throws(() => rejectionPaddedPlaintextBytes({ padding: "x".repeat(32 * 1024 * 1024) }),
    /cannot fit its fixed authenticated padding class/);
});

test("decrypt CLI distinguishes a verified committed append from a verified rejected append", () => {
  const fixture = createFixture();
  const successIntent = intentFor(fixture, assignmentBody(0));
  const success = append(fixture, successIntent, "7201");
  assert.equal(success.status, 0, success.stderr);
  const successCiphertext = readIndex(fixture).envelopes.at(-1).ciphertextSha256;
  const successCli = runDecryptReceiptCli(fixture, success, successIntent, successCiphertext, "success.json");
  assert.equal(successCli.status, 0, successCli.stderr);
  assert.deepEqual(JSON.parse(successCli.stdout), {
    ok: true, verified: true, outcome: "appended", appended: true,
    output: join(fixture.directory, "success.json"), requestSha256: sha256(stableJson(successIntent)),
  });
  const successRetainedBytes = readFileSync(join(fixture.directory, "success.json"));
  const successWrapper = JSON.parse(readFileSync(join(success.receiptDirectory, "receipt.encrypted.json"), "utf8"));
  const successReceipt = JSON.parse(successRetainedBytes);
  assert.match(successReceipt.bindingNonce, /^[a-f0-9]{64}$/);
  assert.equal(successWrapper.plaintextReceiptSha256, sha256(successRetainedBytes));
  assertExactReceiptBytesRejectEquivalentRewrites(successRetainedBytes, successWrapper.plaintextReceiptSha256);

  const assignment = latestState(fixture).registry.events.at(-1);
  const rejectedIntent = intentFor(fixture, assignmentBody(1, { sourceSha256: assignment.payload.sourceSha256 }));
  const rejected = append(fixture, rejectedIntent, "7202");
  assertEncryptedRejection(rejected, rejectedIntent, fixture, "REGISTRY_CROSS_CORPUS_REUSE");
  const rejectedCli = runDecryptReceiptCli(fixture, rejected, rejectedIntent, successCiphertext, "rejected.json");
  assert.equal(rejectedCli.status, 2, rejectedCli.stderr);
  assert.deepEqual(JSON.parse(rejectedCli.stdout), {
    ok: false, verified: true, outcome: "rejected", appended: false,
    output: join(fixture.directory, "rejected.json"), requestSha256: sha256(stableJson(rejectedIntent)),
  });
  const rejectedRetainedBytes = readFileSync(join(fixture.directory, "rejected.json"));
  const rejectedReceipt = JSON.parse(rejectedRetainedBytes);
  const rejectedWrapper = JSON.parse(readFileSync(join(rejected.receiptDirectory, "receipt.encrypted.json"), "utf8"));
  assert.equal(rejectedReceipt.kind, "spaceport-deed-corpus-protected-append-rejection-receipt");
  assert.match(rejectedReceipt.bindingNonce, /^[a-f0-9]{64}$/);
  assert.notEqual(rejectedReceipt.bindingNonce, successReceipt.bindingNonce);
  assert.equal(rejectedWrapper.plaintextReceiptSha256, sha256(rejectedRetainedBytes));
  assertExactReceiptBytesRejectEquivalentRewrites(rejectedRetainedBytes, rejectedWrapper.plaintextReceiptSha256);
});

test("encrypted genesis preserves the complete detailed private registry and frozen public anchor prefix", () => {
  const fixture = createFixture();
  const state = latestState(fixture);
  assert.equal(state.schemaVersion, 3);
  assert.deepEqual(state.registry, fixture.genesisRegistry);
  assert.deepEqual(state.frozenPublicAnchorPrefix, fixture.legacyLog);
  assert.equal(state.genesis.privateRegistryRootSha256, corpusRegistryRootSha256(fixture.genesisRegistry));
  assert.equal(state.encryptedAppendStartIndex, fixture.genesisRegistry.events.length);
  assert.equal(JSON.stringify(readIndex(fixture)).includes("legacy-quarantine"), false);
  assert.equal(JSON.stringify(readIndex(fixture)).includes(state.genesis.privateRegistryRootSha256), false);
});

test("incomplete or disconnected private genesis is rejected without public mutation", () => {
  const complete = quarantineRegistry([
    { caseId: "legacy-a", sourceSha256: hash("legacy-a") },
    { caseId: "legacy-b", sourceSha256: hash("legacy-b") },
  ]);
  const legacyLog = anchorFor(complete);
  const incomplete = structuredClone(complete);
  incomplete.events[0].payload.records.pop();
  incomplete.events[0].eventSha256 = registryEventHash(incomplete.events[0]);
  const fixture = createUnmigratedFixture(incomplete, legacyLog);
  const result = migrate(fixture);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /incomplete|disconnected/i);
  assert.equal(readIndex(fixture).envelopes.length, 0);
  assert.equal(readFileSync(fixture.index, "utf8").includes("legacy-a"), false);
});

test("workflow append derives chronology, authority, semantic root, and count without caller root fields", () => {
  const fixture = createFixture();
  const intent = intentFor(fixture, assignmentBody(0, { split: "final" }));
  assert.deepEqual(Object.keys(intent).sort(), ["eventData", "expectedPublicIndexSha256", "response", "schemaVersion"]);
  assert.equal(append(fixture, intent, "2001").status, 0);
  let state = latestState(fixture);
  const assignment = state.registry.events.at(-1);
  assert.equal(assignment.authority.workflowRunId, "2001");
  assert.match(assignment.issuedAt, /^\d{4}-\d\d-\d\dT/);
  assert.equal(validateCorpusRegistry({ registry: state.registry }).ok, true);

  const release = sourceReleaseBody(assignment);
  assert.equal(append(fixture, intentFor(fixture, release), "2002").status, 0);
  state = latestState(fixture);
  const sealed = state.registry.events.at(-1);
  assert.equal(sealed.payload.assignmentEventSha256, assignment.eventSha256);
  assert.equal(sealed.payload.sourceSha256, assignment.payload.sourceSha256);
  assert.equal(sealed.payload.encryptedSourceBundleRootSha256, assignment.payload.encryptedSourceBundleRootSha256);
  assert.equal(sealed.payload.custodianIdentitySha256, assignment.payload.custodianIdentitySha256);
  assert.equal(sealed.payload.priorReleaseCount, 0);
  assert.equal(sealed.payload.frozenAt, sealed.issuedAt);
  assert.equal(sealed.payload.releaseTarget, "official-challenged-runner");
  assert.equal(sealed.payload.releaseAuthority, "protected-custodian-workflow");
  assert.equal(sealed.payload.releasedAt, sealed.issuedAt);
});

test("duplicate source, property, and title identities fail inside encrypted semantic append", () => {
  for (const field of ["sourceSha256", "propertyIdentitySha256", "titleChainGroupSha256"]) {
    const fixture = createFixture();
    const firstBody = assignmentBody(0);
    assert.equal(append(fixture, intentFor(fixture, firstBody)).status, 0);
    const state = latestState(fixture);
    const first = state.registry.events.at(-1);
    const duplicate = assignmentBody(1, { [field]: first.payload[field] });
    const intent = intentFor(fixture, duplicate);
    assertEncryptedRejection(append(fixture, intent, "2"), intent, fixture, "REGISTRY_CROSS_CORPUS_REUSE");
  }
});

test("instrument and source-family caps fail closed", () => {
  const instrumentFixture = createFixture();
  const sharedInstrument = hash("shared-instrument");
  for (let index = 0; index < 2; index += 1) {
    assert.equal(append(instrumentFixture, intentFor(instrumentFixture,
      assignmentBody(index, { instrumentIdHash: sharedInstrument })), String(index + 1)).status, 0);
  }
  const thirdIntent = intentFor(instrumentFixture, assignmentBody(2, { instrumentIdHash: sharedInstrument }));
  assertEncryptedRejection(append(instrumentFixture, thirdIntent, "3"), thirdIntent, instrumentFixture,
    "REGISTRY_INSTRUMENT_REUSE");

  const familyFixture = createFixture();
  const sharedFamily = `family-${hash("shared-family").slice(0, 12)}`;
  for (let index = 0; index < 5; index += 1) {
    assert.equal(append(familyFixture, intentFor(familyFixture,
      assignmentBody(index, { sourceFamilyId: sharedFamily })), String(index + 1)).status, 0);
  }
  const sixthIntent = intentFor(familyFixture, assignmentBody(5, { sourceFamilyId: sharedFamily }));
  assertEncryptedRejection(append(familyFixture, sixthIntent, "6"), sixthIntent, familyFixture,
    "REGISTRY_FAMILY_REUSE");
});

test("truth and incomplete consume chronology attacks are rejected", () => {
  const truthFixture = createFixture();
  const orphanTruth = truthBody({ caseId: caseId(0), corpusId: CORPUS_ID, eventSha256: hash("missing") });
  const truthIntent = intentFor(truthFixture, orphanTruth);
  assertEncryptedRejection(append(truthFixture, truthIntent), truthIntent, truthFixture, "REGISTRY_TRUTH_SEAL_INVALID");

  const consumeFixture = createFixture();
  assert.equal(append(consumeFixture, intentFor(consumeFixture, assignmentBody(0))).status, 0);
  const assigned = latestState(consumeFixture).registry.events.at(-1);
  const reviewAt = new Date(Date.parse(assigned.issuedAt) + 1).toISOString();
  assert.equal(append(consumeFixture, intentFor(consumeFixture, truthBody(assigned, { reviewSealedAt: reviewAt }))).status, 0);
  const consumeIntent = intentFor(consumeFixture, consumeBody([assigned.eventSha256]));
  assertEncryptedRejection(append(consumeFixture, consumeIntent, "3"), consumeIntent, consumeFixture,
    "REGISTRY_CONSUME_INVALID");
});

test("source-release callers cannot assert any state-derived custody field and valid release derives all of them", () => {
  const fixture = createFixture();
  assert.equal(append(fixture, intentFor(fixture, assignmentBody(0, { split: "final" }))).status, 0);
  const assignment = latestState(fixture).registry.events.at(-1);
  const forgedFields = {
    assignmentEventSha256: hash("forged-assignment"),
    sourceSha256: hash("forged-source"),
    encryptedSourceBundleRootSha256: hash("forged-bundle"),
    custodianIdentitySha256: hash("forged-custodian"),
    priorReleaseCount: 0,
    frozenAt: assignment.issuedAt,
    releaseTarget: "official-challenged-runner",
    releaseAuthority: "protected-custodian-workflow",
    releasedAt: assignment.issuedAt,
  };
  for (const [field, value] of Object.entries(forgedFields)) {
    const result = append(fixture, intentFor(fixture, sourceReleaseBody(assignment, { [field]: value })), "2");
    assert.notEqual(result.status, 0, field);
    assert.match(result.stderr, /only productCodeTip|workflow-owned/, field);
    assert.equal(readIndex(fixture).envelopes.length, 2, field);
  }
  assert.equal(append(fixture, intentFor(fixture, sourceReleaseBody(assignment)), "3").status, 0);
  const release = latestState(fixture).registry.events.at(-1);
  assert.deepEqual(release.payload, {
    productCodeTip: "a".repeat(40),
    assignmentEventSha256: assignment.eventSha256,
    sourceSha256: assignment.payload.sourceSha256,
    encryptedSourceBundleRootSha256: assignment.payload.encryptedSourceBundleRootSha256,
    custodianIdentitySha256: assignment.payload.custodianIdentitySha256,
    priorReleaseCount: 0,
    frozenAt: release.issuedAt,
    releaseTarget: "official-challenged-runner",
    releaseAuthority: "protected-custodian-workflow",
    releasedAt: release.issuedAt,
  });
});

test("the first protected source release freezes a corpus and every later case inherits that exact freeze", () => {
  const fixture = createFixture();
  assert.equal(append(fixture, intentFor(fixture, assignmentBody(0, { split: "final" })), "3101").status, 0);
  const firstAssignment = latestState(fixture).registry.events.at(-1);
  assert.equal(append(fixture, intentFor(fixture, assignmentBody(1, { split: "final" })), "3102").status, 0);
  const secondAssignment = latestState(fixture).registry.events.at(-1);
  assert.equal(append(fixture, intentFor(fixture, assignmentBody(2, { split: "final" })), "3103").status, 0);
  const thirdAssignment = latestState(fixture).registry.events.at(-1);

  assert.equal(append(fixture, intentFor(fixture, sourceReleaseBody(firstAssignment)), "3104").status, 0);
  const firstRelease = latestState(fixture).registry.events.at(-1);
  assert.equal(firstRelease.payload.frozenAt, firstRelease.issuedAt);
  assert.equal(append(fixture, intentFor(fixture, sourceReleaseBody(secondAssignment)), "3105").status, 0);
  const secondRelease = latestState(fixture).registry.events.at(-1);
  assert.equal(secondRelease.payload.frozenAt, firstRelease.payload.frozenAt);
  assert.equal(secondRelease.payload.releasedAt, secondRelease.issuedAt);

  const differentProductIntent = intentFor(fixture,
    sourceReleaseBody(thirdAssignment, { productCodeTip: "b".repeat(40) }));
  assertEncryptedRejection(append(fixture, differentProductIntent, "3106"), differentProductIntent, fixture,
    "REGISTRY_SOURCE_RELEASE_INVALID");
});

test("execution and judge events cannot precede their consumed, sealed, and challenged evidence", () => {
  const executionFixture = createFixture();
  const executionIntent = intentFor(executionFixture, executionBody(hash("missing-consume")));
  assertEncryptedRejection(append(executionFixture, executionIntent), executionIntent, executionFixture,
    "REGISTRY_EXECUTION_SEAL_INVALID");

  const challengeFixture = createFixture();
  const challengeIntent = intentFor(challengeFixture, challengeBody(hash("missing-execution")));
  assertEncryptedRejection(append(challengeFixture, challengeIntent), challengeIntent, challengeFixture,
    "REGISTRY_JUDGE_CHALLENGE_INVALID");

  const sealFixture = createFixture();
  const sealIntent = intentFor(sealFixture, judgeSealBody(hash("missing-challenge")));
  assertEncryptedRejection(append(sealFixture, sealIntent), sealIntent, sealFixture,
    "REGISTRY_JUDGE_SEAL_INVALID");
});

test("valid tuning consume, execution, judge challenge, and judge seal stay in strict encrypted order", () => {
  let registry = quarantineRegistry([{ caseId: "legacy-a", sourceSha256: hash("legacy-source") }]);
  const assignments = [];
  for (let index = 0; index < 20; index += 1) {
    registry = appendCorpusRegistryEvent(registry, withIssued(assignmentBody(index), iso(index * 2 + 1)));
    const assignment = registry.events.at(-1);
    assignments.push(assignment);
    registry = appendCorpusRegistryEvent(registry, withIssued(truthBody(assignment, { reviewSealedAt: iso(index * 2 + 2) }), iso(index * 2 + 2)));
  }
  assert.equal(validateCorpusRegistry({ registry }).ok, true);
  const fixture = createFixture({ registry, legacyLog: anchorFor(registry) });
  assert.equal(append(fixture, intentFor(fixture, consumeBody(assignments.map((item) => item.eventSha256))), "3001").status, 0);
  let state = latestState(fixture);
  const consume = state.registry.events.at(-1);
  assert.match(consume.payload.oneUseNonce, /^[a-f0-9]{64}$/);

  assert.equal(append(fixture, intentFor(fixture, executionBody(consume.eventSha256)), "3002").status, 0);
  state = latestState(fixture);
  const execution = state.registry.events.at(-1);
  assert.equal(append(fixture, intentFor(fixture, challengeBody(execution.eventSha256)), "3003").status, 0);
  state = latestState(fixture);
  const challenge = state.registry.events.at(-1);
  assert.match(challenge.payload.challengeNonce, /^[a-f0-9]{64}$/);
  assert.equal(append(fixture, intentFor(fixture, judgeSealBody(challenge.eventSha256, challenge)), "3004").status, 0);
  assert.equal(validateCorpusRegistry({ registry: latestState(fixture).registry }).ok, true);
});

test("encrypted append receipts bind consume nonce, execution seal, registry, authority, and opaque public commitments", () => {
  const consumeWorkflowTip = "1".repeat(40);
  const executionWorkflowTip = "2".repeat(40);
  let registry = quarantineRegistry([{ caseId: "legacy-receipt", sourceSha256: hash("legacy-receipt-source") }]);
  const assignments = [];
  for (let index = 0; index < 20; index += 1) {
    registry = appendCorpusRegistryEvent(registry, withIssued(assignmentBody(index), iso(index * 2 + 1)));
    const assignment = registry.events.at(-1);
    assignments.push(assignment);
    registry = appendCorpusRegistryEvent(registry,
      withIssued(truthBody(assignment, { reviewSealedAt: iso(index * 2 + 2) }), iso(index * 2 + 2)));
  }
  const fixture = createFixture({ registry, legacyLog: anchorFor(registry) });
  const consumeIntent = intentFor(fixture, consumeBody(assignments.map((item) => item.eventSha256)));
  const consumeResult = append(fixture, consumeIntent, "4001", consumeWorkflowTip);
  assert.equal(consumeResult.status, 0, consumeResult.stderr);
  const consumePublicResult = JSON.parse(consumeResult.stdout);
  const consumeRequestSha256 = sha256(stableJson(consumeIntent));
  assert.equal(consumePublicResult.artifactName, `deed-registry-receipt-${consumeRequestSha256}`);
  const metadata = JSON.parse(readFileSync(join(consumeResult.receiptDirectory, "receipt-metadata.json"), "utf8"));
  assert.equal(metadata.outcome, "appended");
  assert.equal(metadata.requestSha256, consumeRequestSha256);
  assert.equal(metadata.artifactName, consumePublicResult.artifactName);
  const consumeEnvelope = readIndex(fixture).envelopes.at(-1);
  const consumeReceipt = decryptReceipt(consumeResult, consumeIntent, consumeEnvelope.ciphertextSha256,
    responseKeys.privateKey, consumeWorkflowTip);
  const consumeWrapper = JSON.parse(readFileSync(join(consumeResult.receiptDirectory, "receipt.encrypted.json"), "utf8"));
  assert.equal(consumeWrapper.plaintextReceiptSha256,
    sha256(Buffer.from(`${JSON.stringify(consumeReceipt, null, 2)}\n`, "utf8")));
  assert.match(consumeReceipt.bindingNonce, /^[a-f0-9]{64}$/);
  assert.equal(consumeReceipt.eventType, "consume");
  assert.equal(consumeReceipt.requestSha256, consumeRequestSha256);
  assert.equal(consumeReceipt.eventSha256, latestState(fixture).registry.events.at(-1).eventSha256);
  assert.equal(consumeReceipt.workflowOwned.oneUseNonce, latestState(fixture).registry.events.at(-1).payload.oneUseNonce);
  assert.equal(consumeReceipt.workflowOwned.consumedAt, consumeReceipt.issuedAt);
  assert.equal(consumeReceipt.publicCommitment.envelopeSha256, consumeEnvelope.envelopeSha256);
  assert.equal(consumeReceipt.authority.workflowRunId, "4001");
  assert.equal(consumeReceipt.authority.workflowTip, consumeWorkflowTip);
  assert.equal(consumeReceipt.authority.verifierPolicyTip, consumeWorkflowTip);
  const consumeRegistryCheck = validateCorpusRegistry({ registry: consumeReceipt.registry });
  assert.equal(consumeRegistryCheck.ok, true, JSON.stringify(consumeRegistryCheck.errors));
  assert.equal(consumeRegistryCheck.rootSha256, consumeReceipt.registryRootSha256);
  assert.equal(consumeRegistryCheck.eventCount, consumeReceipt.registryEventCount);
  assert.deepEqual(consumeReceipt.registry, latestState(fixture).registry);
  const publicReceiptBytes = readFileSync(join(consumeResult.receiptDirectory, "receipt.encrypted.json"), "utf8");
  const publicReceiptMetadata = readFileSync(join(consumeResult.receiptDirectory, "receipt-metadata.json"), "utf8");
  for (const secretSemantic of ["deed-plotting-50-real", "consume", consumeReceipt.corpusId,
    consumeReceipt.registry.events.find((item) => item.eventType === "assign")?.caseId]) {
    assert.equal(publicReceiptBytes.includes(secretSemantic), false);
    assert.equal(publicReceiptMetadata.includes(secretSemantic), false);
  }

  const consumeEvent = latestState(fixture).registry.events.at(-1);
  const executionIntent = intentFor(fixture, executionBody(consumeEvent.eventSha256));
  const executionResult = append(fixture, executionIntent, "4002", executionWorkflowTip);
  assert.equal(executionResult.status, 0, executionResult.stderr);
  const executionEnvelope = readIndex(fixture).envelopes.at(-1);
  const executionReceipt = decryptReceipt(executionResult, executionIntent, executionEnvelope.ciphertextSha256,
    responseKeys.privateKey, executionWorkflowTip);
  assert.equal(executionReceipt.eventType, "execution-seal");
  assert.equal(executionReceipt.workflowOwned.sealedAt, executionReceipt.issuedAt);
  assert.equal(executionReceipt.authority.workflowTip, executionWorkflowTip);
  assert.equal(executionReceipt.authority.verifierPolicyTip, executionWorkflowTip);
  assert.equal(executionReceipt.execution.executionIndexSha256, executionBody(consumeEvent.eventSha256).payload.executionIndexSha256);
});

test("final execution seal requires product/verifier tips and exact attestation subject and bundle roots", () => {
  const { registry, consume } = finalConsumedRegistry();
  const validBody = finalExecutionBody(consume);
  const valid = appendCorpusRegistryEvent(registry, withIssued(validBody, iso(202)));
  const validCheck = validateCorpusRegistry({ registry: valid });
  assert.equal(validCheck.ok, true, JSON.stringify(validCheck.errors));

  for (const [field, value] of [
    ["productCodeTip", "b".repeat(40)],
    ["verifierPolicyTip", hash("not-a-40-hex-tip")],
    ["executionAttestationSubjectSha256", hash("wrong-subject")],
    ["executionAttestationBundleRootSha256", "not-a-sha256"],
  ]) {
    const body = finalExecutionBody(consume);
    body.payload[field] = value;
    const invalid = appendCorpusRegistryEvent(registry, withIssued(body, iso(202)));
    const checked = validateCorpusRegistry({ registry: invalid });
    assert.ok(checked.errors.some((error) => error.code === "REGISTRY_EXECUTION_SEAL_INVALID"), field);
  }
});

test("successive hosted appends separate advancing workflow signer tips from the frozen evaluator policy tip", () => {
  const evaluatorPolicyTip = "3".repeat(40);
  const executionWorkflowTip = "4".repeat(40);
  const { registry } = finalConsumedRegistry();
  const seedRegistry = structuredClone(registry);
  const consumeTemplate = seedRegistry.events.pop();
  const fixture = createFixture({ registry: seedRegistry, legacyLog: anchorFor(seedRegistry) });
  const consumeBodyForAppend = {
    eventType: consumeTemplate.eventType,
    caseId: consumeTemplate.caseId,
    corpusId: consumeTemplate.corpusId,
    payload: structuredClone(consumeTemplate.payload),
  };
  delete consumeBodyForAppend.payload.oneUseNonce;
  delete consumeBodyForAppend.payload.consumedAt;
  const consumeIntent = intentFor(fixture, consumeBodyForAppend);
  const consumeResult = append(fixture, consumeIntent, "4101", evaluatorPolicyTip);
  assert.equal(consumeResult.status, 0, consumeResult.stderr);
  const consumeEnvelope = readIndex(fixture).envelopes.at(-1);
  const consumeReceipt = decryptReceipt(consumeResult, consumeIntent, consumeEnvelope.ciphertextSha256,
    responseKeys.privateKey, evaluatorPolicyTip);
  assert.equal(consumeReceipt.authority.workflowTip, evaluatorPolicyTip);

  const consume = latestState(fixture).registry.events.at(-1);
  const executionData = finalExecutionBody(consume);
  delete executionData.payload.sealedAt;
  executionData.payload.verifierPolicyTip = evaluatorPolicyTip;
  const executionIntent = intentFor(fixture, executionData);
  const executionResult = append(fixture, executionIntent, "4102", executionWorkflowTip);
  assert.equal(executionResult.status, 0, executionResult.stderr);
  const executionEnvelope = readIndex(fixture).envelopes.at(-1);
  const executionReceipt = decryptReceipt(executionResult, executionIntent, executionEnvelope.ciphertextSha256,
    responseKeys.privateKey, executionWorkflowTip);
  assert.equal(executionReceipt.authority.workflowTip, executionWorkflowTip);
  assert.equal(executionReceipt.authority.verifierPolicyTip, evaluatorPolicyTip);
  assert.equal(executionReceipt.execution.verifierPolicyTip, evaluatorPolicyTip);
  assert.throws(() => decryptProtectedAppendReceipt(
    readFileSync(join(executionResult.receiptDirectory, "receipt.encrypted.json")), responseKeys.privateKey, RESPONSE_KEY_ID,
    { expectedRequestSha256: sha256(stableJson(executionIntent)),
      expectedCiphertextSha256: executionEnvelope.ciphertextSha256,
      expectedSignerDigest: evaluatorPolicyTip }), /authority|commitment binding/i);
});

test("fail-safe execution seal requires and accepts the same hosted certification bindings", () => {
  const { registry, consume } = failSafeConsumedRegistry();
  const validBody = failSafeExecutionBody(consume);
  const valid = appendCorpusRegistryEvent(registry, withIssued(validBody, iso(102)));
  const validCheck = validateCorpusRegistry({ registry: valid });
  assert.equal(validCheck.ok, true, JSON.stringify(validCheck.errors));

  for (const field of [
    "productCodeTip",
    "verifierPolicyTip",
    "executionAttestationSubjectSha256",
    "executionAttestationBundleRootSha256",
  ]) {
    const body = failSafeExecutionBody(consume);
    delete body.payload[field];
    const invalid = appendCorpusRegistryEvent(registry, withIssued(body, iso(102)));
    const checked = validateCorpusRegistry({ registry: invalid });
    assert.ok(checked.errors.some((error) => error.code === "REGISTRY_EXECUTION_SEAL_INVALID"), field);
  }
});

test("fail-safe truth requires a prior distinct two-system protected review and rejects property-group reuse", () => {
  let registry = quarantineRegistry([{ caseId: "legacy-review", sourceSha256: hash("legacy-review-source") }]);
  registry = appendCorpusRegistryEvent(registry, withIssued(assignmentBody(0, { split: "fail-safe" }), iso(1)));
  const first = registry.events.at(-1);
  const orphan = appendCorpusRegistryEvent(registry,
    withIssued(truthBody(first, { reviewSealedAt: iso(2), reviewSealEventSha256: hash("missing"),
      expectedFailureCandidateSha256: hash("candidate-0") }), iso(2)));
  assert.equal(validateCorpusRegistry({ registry: orphan }).ok, false);
  registry = appendCorpusRegistryEvent(registry, withIssued(reviewBody(first, 0, iso(2)), iso(2)));
  const review = registry.events.at(-1);
  registry = appendCorpusRegistryEvent(registry, withIssued(truthBody(first, { reviewSealedAt: review.issuedAt,
    reviewSealEventSha256: review.eventSha256,
    expectedFailureCandidateSha256: review.payload.expectedFailureCandidateSha256 }), iso(3)));
  assert.equal(validateCorpusRegistry({ registry }).ok, true);
  registry = appendCorpusRegistryEvent(registry, withIssued(assignmentBody(1, { split: "fail-safe" }), iso(4)));
  const second = registry.events.at(-1);
  const reused = reviewBody(second, 1, iso(5));
  reused.payload.propertyAliases = [review.payload.propertyAliases.find((alias) => alias.kind === "county-subdivision-lot"),
    reused.payload.propertyAliases.find((alias) => alias.kind === "county-subdivision-block-lot"),
    reused.payload.propertyAliases.find((alias) => alias.kind === "county-parcel")]
    .sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  registry = appendCorpusRegistryEvent(registry, withIssued(reused, iso(5)));
  const conflict = validateCorpusRegistry({ registry });
  assert.equal(conflict.ok, false);
  assert.ok(conflict.errors.some((error) => error.code === "REGISTRY_REVIEW_PROPERTY_CONFLICT"),
    "weak/shared alias with a differing parcel commitment must require adjudication, not count duplicate or distinct");
});

test("review-seal callers can submit only an exact protected-run reference, never hash-shaped review facts", () => {
  const fixture = createFixture();
  assert.equal(append(fixture, intentFor(fixture, assignmentBody(0, { split: "fail-safe" })), "6101").status, 0);
  const assignment = latestState(fixture).registry.events.at(-1);
  const forged = append(fixture, intentFor(fixture, reviewBody(assignment, 0, iso(2))), "6102");
  assert.notEqual(forged.status, 0);
  assert.match(forged.stderr, /workflow-owned|only protected workflow reference fields|protected-run reference/i);

  const referenceOnly = { eventType: "review-seal", caseId: assignment.caseId, corpusId: assignment.corpusId, payload: {
    reviewRequestId: hash("review-request-reference"), reviewerWorkflowRunId: "9000",
    reviewerWorkflowRunAttempt: "1", verifierPolicyTip: "f".repeat(40),
  } };
  const missingProtectedEvidence = append(fixture, intentFor(fixture, referenceOnly), "6103");
  assert.notEqual(missingProtectedEvidence.status, 0);
  assert.match(missingProtectedEvidence.stderr, /requires exact protected-workflow-derived evidence/i);
  assert.equal(readIndex(fixture).envelopes.length, 2);
});

test("append workflow resolves review facts from exact attested protected reviewer evidence", () => {
  for (const required of [
    "extract-protected-review-reference.mjs", "reviewerWorkflowRunId", "reviewerWorkflowRunAttempt",
    "protected-refusal-reviewer.yml", "registry-evidence.bundle", "gh attestation verify",
    "derive-review-event", "--derived-review-event",
  ]) assert.match(appendWorkflow, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(appendWorkflow, /\.status == "completed" and \.conclusion == "success"/);
  assert.match(appendWorkflow, /\.head_sha == \$tip/);
});

test("stale index, wrong keys, tampering, reorder, deletion, and caller chronology fail closed", () => {
  const fixture = createFixture();
  const stale = intentFor(fixture, assignmentBody(0));
  assert.equal(append(fixture, stale).status, 0);
  const staleResult = append(fixture, stale, "2");
  assert.notEqual(staleResult.status, 0);
  assert.match(staleResult.stderr, /stale/i);
  assert.equal(existsSync(staleResult.receiptDirectory), false);

  const latestPath = ciphertextPath(fixture.ciphertexts, readIndex(fixture).envelopes.length);
  assert.throws(() => decryptState(readFileSync(latestPath), randomBytes(32)), /authentication failed/i);
  const bytes = readFileSync(latestPath);
  bytes[bytes.length - 1] ^= 0xff;
  writeFileSync(latestPath, bytes);
  assert.throws(() => validatePublicIndex(readIndex(fixture), { ciphertextDirectory: fixture.ciphertexts }), /does not match/i);

  const reordered = createFixture();
  assert.equal(append(reordered, intentFor(reordered, assignmentBody(0))).status, 0);
  const reorderedIndex = readIndex(reordered);
  reorderedIndex.envelopes.reverse();
  writeFileSync(reordered.index, `${JSON.stringify(reorderedIndex, null, 2)}\n`);
  assert.notEqual(verify(reordered).status, 0);

  const deleted = createFixture();
  rmSync(ciphertextPath(deleted.ciphertexts, 1));
  assert.notEqual(verify(deleted).status, 0);

  const caller = createFixture();
  const forbidden = intentFor(caller, assignmentBody(0));
  forbidden.eventData.issuedAt = iso(999);
  const callerResult = append(caller, forbidden);
  assert.notEqual(callerResult.status, 0);
  assert.match(callerResult.stderr, /workflow-owned/i);
});

test("wrong RSA key, tampered request, unknown event, caller nonce, and caller roots are rejected", () => {
  const wrongKeyFixture = createFixture();
  const wrongKeys = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const validIntent = intentFor(wrongKeyFixture, assignmentBody(0));
  const wrongKeyRequest = encryptRequest(validIntent, wrongKeys.publicKey, REQUEST_KEY_ID);
  const wrongKey = appendEncoded(wrongKeyFixture, wrongKeyRequest);
  assert.notEqual(wrongKey.status, 0);
  assert.match(wrongKey.stderr, /RSA-OAEP/);

  const tamperFixture = createFixture();
  const envelope = JSON.parse(Buffer.from(encryptRequest(intentFor(tamperFixture, assignmentBody(0)),
    requestKeys.publicKey, REQUEST_KEY_ID), "base64url").toString("utf8"));
  const requestCiphertext = Buffer.from(envelope.ciphertextBase64url, "base64url");
  requestCiphertext[0] ^= 0xff;
  envelope.ciphertextBase64url = requestCiphertext.toString("base64url");
  const tampered = appendEncoded(tamperFixture, Buffer.from(JSON.stringify(envelope)).toString("base64url"));
  assert.notEqual(tampered.status, 0);
  assert.match(tampered.stderr, /authentication failed/i);

  for (const mutate of [
    (intent) => { intent.eventData.eventType = "invented-event"; },
    (intent) => { intent.eventData.payload.oneUseNonce = hash("caller-nonce"); },
    (intent) => { intent.privateRegistryRootSha256 = hash("caller-root"); },
  ]) {
    const fixture = createFixture();
    const intent = intentFor(fixture, assignmentBody(0));
    mutate(intent);
    const result = append(fixture, intent);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /invalid|workflow-owned/i);
    assert.equal(readIndex(fixture).envelopes.length, 1);
  }
});

test("receipt wrong-key, substitution, and caller-protected response fields fail closed", () => {
  const fixture = createFixture();
  const firstIntent = intentFor(fixture, assignmentBody(0));
  const firstResult = append(fixture, firstIntent, "5001");
  assert.equal(firstResult.status, 0, firstResult.stderr);
  const firstCiphertext = readIndex(fixture).envelopes.at(-1).ciphertextSha256;
  const wrongResponseKeys = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  assert.throws(() => decryptReceipt(firstResult, firstIntent, firstCiphertext, wrongResponseKeys.privateKey), /RSA-OAEP/);
  assert.throws(() => decryptProtectedAppendReceipt(
    readFileSync(join(firstResult.receiptDirectory, "receipt.encrypted.json")), responseKeys.privateKey, RESPONSE_KEY_ID,
    { expectedRequestSha256: sha256(stableJson(firstIntent)), expectedCiphertextSha256: firstCiphertext,
      expectedSignerDigest: "e".repeat(40) }), /authority|commitment binding/i);
  assert.throws(() => decryptProtectedAppendReceipt(
    Buffer.allocUnsafe((64 * 1024 * 1024) + 1), responseKeys.privateKey, RESPONSE_KEY_ID,
    { expectedRequestSha256: sha256(stableJson(firstIntent)), expectedCiphertextSha256: firstCiphertext }),
  /64-megabyte artifact limit/i);
  const forgedBinding = JSON.parse(readFileSync(join(firstResult.receiptDirectory, "receipt.encrypted.json"), "utf8"));
  forgedBinding.plaintextReceiptSha256 = hash("forged-plaintext-receipt");
  assert.throws(() => decryptProtectedAppendReceipt(
    Buffer.from(`${JSON.stringify(forgedBinding, null, 2)}\n`), responseKeys.privateKey, RESPONSE_KEY_ID,
    { expectedRequestSha256: sha256(stableJson(firstIntent)), expectedCiphertextSha256: firstCiphertext }),
  /does not bind the decrypted receipt bytes/i);

  const secondIntent = intentFor(fixture, assignmentBody(1));
  const secondResult = append(fixture, secondIntent, "5002");
  assert.equal(secondResult.status, 0, secondResult.stderr);
  const secondCiphertext = readIndex(fixture).envelopes.at(-1).ciphertextSha256;
  assert.throws(() => decryptProtectedAppendReceipt(
    readFileSync(join(firstResult.receiptDirectory, "receipt.encrypted.json")), responseKeys.privateKey, RESPONSE_KEY_ID,
    { expectedRequestSha256: sha256(stableJson(secondIntent)), expectedCiphertextSha256: secondCiphertext }), /request binding/i);

  for (const mutate of [
    (intent) => { intent.response.issuedAt = iso(999); },
    (intent) => { intent.receipt = { eventSha256: hash("caller-event") }; },
  ]) {
    const protectedFixture = createFixture();
    const intent = intentFor(protectedFixture, assignmentBody(0));
    mutate(intent);
    const result = append(protectedFixture, intent);
    assert.notEqual(result.status, 0);
    assert.equal(existsSync(result.receiptDirectory), false);
  }
});

test("request and state CLIs round-trip without command-line secrets or plaintext logs", () => {
  const fixture = createFixture();
  const publicKey = join(fixture.directory, "request-public.pem");
  const requestInput = join(fixture.directory, "request.json");
  const request = intentFor(fixture, assignmentBody(0));
  writeFileSync(publicKey, requestKeys.publicKey);
  writeFileSync(requestInput, `${JSON.stringify(request)}\n`);
  const encryptedRequest = spawnSync(process.execPath, [encryptRequestScript,
    "--input", requestInput, "--public-key", publicKey, "--key-id", REQUEST_KEY_ID,
  ], { encoding: "utf8" });
  assert.equal(encryptedRequest.status, 0, encryptedRequest.stderr);
  assert.ok(encryptedRequest.stdout.trim().length <= 60 * 1024);
  assert.deepEqual(decryptRequest(encryptedRequest.stdout.trim(), requestKeys.privateKey, REQUEST_KEY_ID), request);
  const oversizedRequest = structuredClone(request);
  oversizedRequest.eventData.payload.dispatchPadding = "x".repeat(33 * 1024);
  assert.throws(() => encryptRequest(oversizedRequest, requestKeys.publicKey, REQUEST_KEY_ID), /32-kilobyte plaintext limit/i);
  assert.throws(() => decryptRequest("A".repeat((60 * 1024) + 1), requestKeys.privateKey, REQUEST_KEY_ID),
    /60-kilobyte workflow-dispatch limit/i);

  const plaintext = join(fixture.directory, "state.json");
  const reencrypted = join(fixture.directory, "state.bin");
  const env = aesEnv(fixture);
  assert.equal(spawnSync(process.execPath, [decryptStateScript,
    "--input", ciphertextPath(fixture.ciphertexts, 1), "--output", plaintext,
  ], { encoding: "utf8", env }).status, 0);
  assert.equal(spawnSync(process.execPath, [encryptStateScript,
    "--input", plaintext, "--output", reencrypted,
  ], { encoding: "utf8", env }).status, 0);
  assert.deepEqual(decryptState(readFileSync(reencrypted), fixture.aesKey), JSON.parse(readFileSync(plaintext, "utf8")));
});

function createFixture({ registry = quarantineRegistry([{ caseId: "legacy-a", sourceSha256: hash("legacy-source") }]), legacyLog = null } = {}) {
  const fixture = createUnmigratedFixture(registry, legacyLog || anchorFor(registry));
  const result = migrate(fixture);
  assert.equal(result.status, 0, result.stderr);
  return fixture;
}

function createUnmigratedFixture(registry, legacyLog) {
  const directory = mkdtempSync(join(tmpdir(), "deed-encrypted-registry-"));
  const ciphertexts = join(directory, "ciphertexts");
  mkdirSync(ciphertexts);
  const index = join(directory, "index.json");
  const privateRegistry = join(directory, "private-registry.json");
  const legacy = join(directory, "anchors.json");
  const privateKey = join(directory, "request-private.pem");
  writeFileSync(index, `${JSON.stringify(emptyPublicIndex(), null, 2)}\n`);
  writeFileSync(privateRegistry, `${JSON.stringify(registry, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(legacy, `${JSON.stringify(legacyLog, null, 2)}\n`);
  writeFileSync(privateKey, requestKeys.privateKey, { mode: 0o600 });
  return { directory, ciphertexts, index, privateRegistry, legacy, privateKey,
    aesKey: randomBytes(32), genesisRegistry: registry, legacyLog };
}

function migrate(fixture) {
  return spawnSync(process.execPath, [migrationScript,
    "--index", fixture.index, "--ciphertext-dir", fixture.ciphertexts,
    "--private-registry", fixture.privateRegistry, "--legacy-file", fixture.legacy,
    "--state-key-id", STATE_KEY_ID, "--workflow-run-id", "1000", "--workflow-run-attempt", "1",
  ], { encoding: "utf8", env: aesEnv(fixture) });
}

function append(fixture, intent, workflowRunId = "1", workflowTip = "f".repeat(40)) {
  return appendEncoded(fixture, encryptRequest(intent, requestKeys.publicKey, REQUEST_KEY_ID), workflowRunId, workflowTip);
}

function appendEncoded(fixture, encoded, workflowRunId = "1", workflowTip = "f".repeat(40)) {
  const receiptDirectory = join(fixture.directory, `receipt-${workflowRunId}-${readIndex(fixture).envelopes.length + 1}`);
  const result = spawnSync(process.execPath, [appendScript,
    "--index", fixture.index, "--ciphertext-dir", fixture.ciphertexts,
    "--request-private-key", fixture.privateKey, "--request-base64url", encoded,
    "--request-key-id", REQUEST_KEY_ID, "--state-key-id", STATE_KEY_ID,
    "--workflow-run-id", workflowRunId, "--workflow-run-attempt", "1",
    "--workflow-ref", "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/append-encrypted-registry.yml@refs/heads/main",
    "--workflow-tip", workflowTip, "--receipt-dir", receiptDirectory,
  ], { encoding: "utf8", env: aesEnv(fixture) });
  result.receiptDirectory = receiptDirectory;
  return result;
}

function verify(fixture) {
  return spawnSync(process.execPath, [verifyScript, "--index", fixture.index, "--ciphertext-dir", fixture.ciphertexts], { encoding: "utf8" });
}

function aesEnv(fixture) {
  return { ...process.env, REGISTRY_AES_KEY_BASE64: fixture.aesKey.toString("base64") };
}

function latestState(fixture) {
  const count = readIndex(fixture).envelopes.length;
  return decryptState(readFileSync(ciphertextPath(fixture.ciphertexts, count)), fixture.aesKey);
}

function readIndex(fixture) { return JSON.parse(readFileSync(fixture.index, "utf8")); }
function intentFor(fixture, eventData, response = null) {
  return { schemaVersion: 4, expectedPublicIndexSha256: indexSha256(readIndex(fixture)), eventData,
    response: response || { algorithm: "RSA-OAEP-256+A256GCM", keyId: RESPONSE_KEY_ID, publicKeyPem: responseKeys.publicKey } };
}

function decryptReceipt(result, intent, expectedCiphertextSha256, privateKey = responseKeys.privateKey,
  expectedSignerDigest = null) {
  assert.equal(result.status, 0, result.stderr);
  const expectations = { expectedRequestSha256: sha256(stableJson(intent)), expectedCiphertextSha256 };
  if (expectedSignerDigest !== null) expectations.expectedSignerDigest = expectedSignerDigest;
  return decryptProtectedAppendReceipt(readFileSync(join(result.receiptDirectory, "receipt.encrypted.json")),
    privateKey, RESPONSE_KEY_ID, expectations);
}

function runDecryptReceiptCli(fixture, result, intent, expectedCiphertextSha256, outputName) {
  const encryptedReceiptPath = join(result.receiptDirectory, "receipt.encrypted.json");
  const encryptedReceiptBytes = readFileSync(encryptedReceiptPath);
  const bundle = { mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
    verificationMaterial: { tlogEntries: [{ logIndex: "42", integratedTime: "123456" }] } };
  const response = [{ verificationResult: {
    signature: { certificate: {
      issuer: "https://token.actions.githubusercontent.com",
      githubWorkflowRepository: "HansenHomeAI/deed-corpus-transparency-log",
      githubWorkflowRef: "refs/heads/main",
      runnerEnvironment: "github-hosted",
      buildSignerDigest: "f".repeat(40),
    } },
    statement: { subject: [{ digest: { sha256: sha256(encryptedReceiptBytes) } }] },
    verifiedTimestamps: [{}],
  }, attestation: { bundle } }];
  const bin = join(fixture.directory, `fake-gh-${outputName}`);
  mkdirSync(bin);
  const fakeGh = join(bin, "gh");
  writeFileSync(fakeGh, `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(JSON.stringify(response))});\n`);
  chmodSync(fakeGh, 0o700);
  const bundlePath = join(fixture.directory, `bundle-${outputName}`);
  const keyPath = join(fixture.directory, `response-${outputName}.pem`);
  const output = join(fixture.directory, outputName);
  writeFileSync(bundlePath, `${JSON.stringify(bundle)}\n`);
  writeFileSync(keyPath, responseKeys.privateKey, { mode: 0o600 });
  return spawnSync(process.execPath, [decryptReceiptScript,
    "--input", encryptedReceiptPath,
    "--attestation-bundle", bundlePath,
    "--private-key", keyPath,
    "--key-id", RESPONSE_KEY_ID,
    "--expected-request-sha256", sha256(stableJson(intent)),
    "--expected-ciphertext-sha256", expectedCiphertextSha256,
    "--expected-signer-digest", "f".repeat(40),
    "--output", output,
  ], { encoding: "utf8", env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}` } });
}

function assertEncryptedRejection(result, intent, fixture, expectedCode) {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.appended, false);
  const index = readIndex(fixture);
  assert.equal(output.sequence, index.envelopes.length);
  assert.equal(output.indexSha256, indexSha256(index));
  const receipt = decryptReceipt(result, intent, index.envelopes.at(-1).ciphertextSha256);
  assert.equal(receipt.kind, "spaceport-deed-corpus-protected-append-rejection-receipt");
  assert.equal(receipt.registryEventCount, latestState(fixture).registry.events.length);
  assert.ok(receipt.errors.some((error) => error.code === expectedCode), JSON.stringify(receipt.errors));
  const metadataBytes = readFileSync(join(result.receiptDirectory, "receipt-metadata.json"), "utf8");
  const metadata = JSON.parse(metadataBytes);
  assert.equal(metadata.outcome, "rejected");
  assert.equal(metadata.publicIndexSha256, indexSha256(index));
  for (const secret of [intent.eventData.caseId, intent.eventData.corpusId, expectedCode]) {
    assert.equal(metadataBytes.includes(secret), false);
  }
  return receipt;
}

function assertExactReceiptBytesRejectEquivalentRewrites(bytes, expectedSha256) {
  const text = bytes.toString("utf8");
  const original = JSON.parse(text);
  const rewrites = [
    Buffer.from(` ${text}`),
    Buffer.from(text.replace("{\n", "{\n  \"schemaVersion\": 1,\n")),
    Buffer.from(text.replace("spaceport-deed-corpus-", "\\u0073paceport-deed-corpus-")),
    Buffer.from(text.replace('"schemaVersion": 1', '"schemaVersion": 1.0')),
  ];
  for (const rewritten of rewrites) {
    assert.deepEqual(JSON.parse(rewritten), original);
    assert.notEqual(sha256(rewritten), expectedSha256);
  }
}

function emptyRegistry() {
  return { schemaVersion: 1, campaign: "deed-plotting-50-real", repository: "HansenHomeAI/Autodesk-automation",
    ref: "refs/heads/deed-corpus-registry", events: [] };
}
function quarantineRegistry(records) {
  return appendCorpusRegistryEvent(emptyRegistry(), {
    eventType: "legacy-quarantine", caseId: null, corpusId: null, issuedAt: iso(0), payload: { records },
  });
}
function anchorFor(registry) {
  const event = { schemaVersion: 1, sequence: 1, previousAnchorEventSha256: "0".repeat(64),
    previousPrivateRegistryRootSha256: "0".repeat(64), privateRegistryRootSha256: corpusRegistryRootSha256(registry),
    privateRegistryEventCount: registry.events.length, kind: registry.events.at(-1).eventType, requestNonce: hash("anchor-nonce"),
    issuedAt: iso(100) };
  event.anchorEventSha256 = hash(stableJson(event));
  return { schemaVersion: 1, log: "spaceport-deed-corpus-registry-roots",
    sourceRepository: "HansenHomeAI/Autodesk-automation", events: [event] };
}

function assignmentBody(index, overrides = {}) {
  return { eventType: "assign", caseId: caseId(index), corpusId: CORPUS_ID, payload: {
    split: "tuning", sourceSha256: hash(`source-${index}`), sourceBytes: 1000 + index,
    selectorSha256: hash(`selector-${index}`), sourceFamilyId: `family-${hash(`family-${index}`).slice(0, 12)}`,
    instrumentIdHash: hash(`instrument-${index}`), propertyIdentitySha256: hash(`property-${index}`),
    titleChainGroupSha256: hash(`title-${index}`), assignmentStatus: "sealed-untouched",
    custodyMode: overrides.split === "final" ? "exclusive-custodian" : "operator-attested",
    encryptedSourceBundleRootSha256: hash(`bundle-${index}`), custodianIdentitySha256: hash("custodian"),
    ...overrides,
  } };
}
function truthBody(assignment, overrides = {}) {
  return { eventType: "truth-seal", caseId: assignment.caseId, corpusId: assignment.corpusId, payload: {
    assignmentEventSha256: assignment.eventSha256, truthSha256: hash(`truth-${assignment.caseId}`),
    descriptionSha256: hash(`description-${assignment.caseId}`), geometrySha256: hash(`geometry-${assignment.caseId}`),
    evidenceSha256: hash(`evidence-${assignment.caseId}`), evidenceSelectorSha256: hash(`evidence-selector-${assignment.caseId}`),
    truthReceiptRootSha256: hash(`receipts-${assignment.caseId}`), measurementReceiptSha256: hash(`measurement-${assignment.caseId}`),
    productOutputAvailable: false, reviewSealedAt: new Date().toISOString(), ...overrides,
  } };
}
function reviewBody(assignment, index, sealedAt) {
  const reviewIndexSha256 = hash(`review-index-${index}`);
  return { eventType: "review-seal", caseId: assignment.caseId, corpusId: assignment.corpusId, payload: {
    assignmentEventSha256: assignment.eventSha256, sourceSha256: assignment.payload.sourceSha256,
    selectorSha256: assignment.payload.selectorSha256,
    expectedFailureCandidateSha256: hash(`candidate-${index}`), reviewRequestSha256: hash(`review-request-${index}`),
    reviewIndexSha256, reviewEvidenceRootSha256: hash(`review-evidence-${index}`),
    reviewAttestationSubjectSha256: reviewIndexSha256,
    reviewAttestationBundleRootSha256: hash(`review-attestation-${index}`), verifierPolicyTip: "f".repeat(40),
    reviewerWorkflowRef: "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/protected-refusal-reviewer.yml@refs/heads/main",
    reviewerWorkflowRunId: String(9000 + index), reviewerWorkflowRunAttempt: "1",
    protectedChallengeSha256: hash(`challenge-${index}`), semanticSystems: [
      { provider: "OpenAI", requestedModel: "openai/gpt-4.1", catalogVersion: "2025-04-14",
        returnedModel: "gpt-4.1-2025-04-14", callId: `call-openai-${index}`,
        sessionIdSha256: hash(`session-openai-${index}`), receiptSha256: hash(`receipt-openai-${index}`),
        assessmentSha256: hash(`assessment-openai-${index}`) },
      { provider: "Meta", requestedModel: "meta/llama-4-maverick-17b-128e-instruct-fp8", catalogVersion: "1",
        returnedModel: "llama-4-maverick-17b-128e-instruct-fp8", callId: `call-meta-${index}`,
        sessionIdSha256: hash(`session-meta-${index}`), receiptSha256: hash(`receipt-meta-${index}`),
        assessmentSha256: hash(`assessment-meta-${index}`) },
    ], propertyIdentityEvidenceSha256: hash(`property-evidence-${index}`),
    propertyAliases: [
      { kind: "county-parcel", strength: "strong", sha256: hash(`protected-parcel-${index}`) },
      { kind: "county-subdivision-lot", strength: "weak", sha256: hash(`protected-plat-weak-${index}`) },
      { kind: "county-subdivision-block-lot", strength: "strong", sha256: hash(`protected-plat-${index}`) },
    ].sort((a, b) => stableJson(a).localeCompare(stableJson(b))),
    propertyIdentifierCommitments: [
      { field: "block", sha256: hash(`protected-block-${index}`) },
      { field: "county", sha256: hash("protected-county") },
      { field: "lot", sha256: hash("protected-lot-7") },
      { field: "parcel", sha256: hash(`protected-parcel-value-${index}`) },
      { field: "subdivision", sha256: hash("protected-subdivision") },
    ],
    propertyAliasReceiptSha256: hash(`property-alias-receipt-${index}`), productCodeMounted: false,
    productOutputAvailable: false, geometryArtifactsExpected: 0, status: "approved", critical: 0, major: 0, sealedAt,
  } };
}
function sourceReleaseBody(assignment, overrides = {}) {
  return { eventType: "source-release", caseId: assignment.caseId, corpusId: assignment.corpusId,
    payload: { productCodeTip: "a".repeat(40), ...overrides } };
}
function consumeBody(caseEventSha256s) {
  return { eventType: "consume", caseId: null, corpusId: CORPUS_ID, payload: {
    campaign: "tuning-run", manifestSha256: hash("manifest"), intakeSealSha256: hash("intake"),
    codeTip: "a".repeat(40), split: "tuning", caseEventSha256s,
  } };
}
function executionBody(consumeEventSha256) {
  return { eventType: "execution-seal", caseId: null, corpusId: CORPUS_ID, payload: {
    campaign: "tuning-run", consumeEventSha256, manifestSha256: hash("manifest"), codeTip: "a".repeat(40),
    executionRootSha256: hash("execution-root"), executionIndexSha256: hash("execution-index"), executionCount: 60,
  } };
}
function finalConsumedRegistry() {
  let registry = quarantineRegistry([{ caseId: "legacy-final", sourceSha256: hash("legacy-final-source") }]);
  const assignments = [];
  for (let index = 0; index < 50; index += 1) {
    registry = appendCorpusRegistryEvent(registry, withIssued(assignmentBody(index, { split: "final" }), iso(index * 2 + 1)));
    const assignment = registry.events.at(-1);
    assignments.push(assignment);
    registry = appendCorpusRegistryEvent(registry,
      withIssued(truthBody(assignment, { reviewSealedAt: iso(index * 2 + 2) }), iso(index * 2 + 2)));
  }
  const frozenAt = iso(101);
  for (let index = 0; index < assignments.length; index += 1) {
    const releasedAt = iso(101 + index);
    registry = appendCorpusRegistryEvent(registry,
      withIssued(canonicalReleaseBody(assignments[index], releasedAt, frozenAt), releasedAt));
  }
  const consumedAt = iso(201);
  registry = appendCorpusRegistryEvent(registry, {
    eventType: "consume", caseId: null, corpusId: CORPUS_ID, issuedAt: consumedAt,
    payload: { campaign: "final-run", manifestSha256: hash("final-manifest"), intakeSealSha256: hash("final-intake"),
      codeTip: "a".repeat(40), split: "final", caseEventSha256s: assignments.map((item) => item.eventSha256),
      oneUseNonce: hash("final-consume-nonce"), consumedAt },
  });
  assert.equal(validateCorpusRegistry({ registry }).ok, true);
  return { registry, consume: registry.events.at(-1) };
}
function canonicalReleaseBody(assignment, issuedAt, frozenAt = issuedAt) {
  return { eventType: "source-release", caseId: assignment.caseId, corpusId: assignment.corpusId, payload: {
    productCodeTip: "a".repeat(40), assignmentEventSha256: assignment.eventSha256,
    sourceSha256: assignment.payload.sourceSha256,
    encryptedSourceBundleRootSha256: assignment.payload.encryptedSourceBundleRootSha256,
    custodianIdentitySha256: assignment.payload.custodianIdentitySha256, priorReleaseCount: 0,
    frozenAt, releaseTarget: "official-challenged-runner",
    releaseAuthority: "protected-custodian-workflow", releasedAt: issuedAt,
  } };
}
function finalExecutionBody(consume) {
  const executionIndexSha256 = hash("final-execution-index");
  return { eventType: "execution-seal", caseId: null, corpusId: CORPUS_ID, payload: {
    campaign: "final-run", consumeEventSha256: consume.eventSha256,
    manifestSha256: hash("final-manifest"), codeTip: "a".repeat(40), productCodeTip: "a".repeat(40),
    verifierPolicyTip: "c".repeat(40), executionRootSha256: hash("final-execution-root"),
    executionIndexSha256, executionCount: 150, executionAttestationSubjectSha256: executionIndexSha256,
    executionAttestationBundleRootSha256: hash("final-attestation-bundle-root"), sealedAt: iso(202),
  } };
}
function failSafeConsumedRegistry() {
  let registry = quarantineRegistry([{ caseId: "legacy-fail-safe", sourceSha256: hash("legacy-fail-safe-source") }]);
  const assignments = [];
  for (let index = 0; index < 20; index += 1) {
    registry = appendCorpusRegistryEvent(registry,
      withIssued(assignmentBody(index, { split: "fail-safe" }), iso(index * 3 + 1)));
    const assignment = registry.events.at(-1);
    assignments.push(assignment);
    registry = appendCorpusRegistryEvent(registry,
      withIssued(reviewBody(assignment, index, iso(index * 3 + 2)), iso(index * 3 + 2)));
    const review = registry.events.at(-1);
    registry = appendCorpusRegistryEvent(registry,
      withIssued(truthBody(assignment, { reviewSealedAt: review.issuedAt,
        reviewSealEventSha256: review.eventSha256,
        expectedFailureCandidateSha256: review.payload.expectedFailureCandidateSha256 }), iso(index * 3 + 3)));
  }
  const consumedAt = iso(101);
  registry = appendCorpusRegistryEvent(registry, {
    eventType: "consume", caseId: null, corpusId: CORPUS_ID, issuedAt: consumedAt,
    payload: { campaign: "fail-safe-run", manifestSha256: hash("fail-safe-manifest"),
      intakeSealSha256: hash("fail-safe-intake"), codeTip: "d".repeat(40), split: "fail-safe",
      caseEventSha256s: assignments.map((item) => item.eventSha256),
      oneUseNonce: hash("fail-safe-consume-nonce"), consumedAt },
  });
  assert.equal(validateCorpusRegistry({ registry }).ok, true);
  return { registry, consume: registry.events.at(-1) };
}
function failSafeExecutionBody(consume) {
  const executionIndexSha256 = hash("fail-safe-execution-index");
  return { eventType: "execution-seal", caseId: null, corpusId: CORPUS_ID, payload: {
    campaign: "fail-safe-run", consumeEventSha256: consume.eventSha256,
    manifestSha256: hash("fail-safe-manifest"), codeTip: "d".repeat(40), productCodeTip: "d".repeat(40),
    verifierPolicyTip: "e".repeat(40), executionRootSha256: hash("fail-safe-execution-root"),
    executionIndexSha256, executionCount: 40, executionAttestationSubjectSha256: executionIndexSha256,
    executionAttestationBundleRootSha256: hash("fail-safe-attestation-bundle-root"), sealedAt: iso(102),
  } };
}
function challengeBody(executionSealEventSha256) {
  return { eventType: "judge-challenge", caseId: null, corpusId: CORPUS_ID, payload: {
    campaign: "tuning-run", role: "numerical", executionSealEventSha256, evidenceRootSha256: hash("evidence-root"),
  } };
}
function judgeSealBody(judgeChallengeEventSha256, challenge = null) {
  const judgeChallengeSha256 = challenge ? hash(stableJson({ schemaVersion: 1, role: challenge.payload.role,
    evidenceRootSha256: challenge.payload.evidenceRootSha256,
    executionSealEventSha256: challenge.payload.executionSealEventSha256,
    judgeChallengeEventSha256: challenge.eventSha256, challengeNonce: challenge.payload.challengeNonce,
    issuedAt: challenge.issuedAt })) : hash("challenge-digest");
  return { eventType: "judge-seal", caseId: null, corpusId: CORPUS_ID, payload: {
    campaign: "tuning-run", role: "numerical", judgeChallengeEventSha256, judgeChallengeSha256,
    evidenceRootSha256: hash("evidence-root"), transcriptSha256: hash("transcript"), responseSha256: hash("response"),
    attachmentsRootSha256: hash("attachments"), sessionIdSha256: hash("session"),
  } };
}
function withIssued(body, issuedAt) { return { ...structuredClone(body), issuedAt }; }
function registryEventHash(event) { const copy = structuredClone(event); delete copy.eventSha256; return hash(stableJson(copy)); }
function caseId(index) { return `dp-${hash(`case-${index}`).slice(0, 12)}`; }
function iso(offset) { return new Date(Date.parse("2020-01-01T00:00:00.000Z") + offset * 1000).toISOString(); }
function hash(value) { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
