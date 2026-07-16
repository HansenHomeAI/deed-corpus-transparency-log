import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  REVIEW_MODELS, REVIEW_WORKFLOW_REF, buildAssessmentPrompt, buildReviewIndex, normalizeAssessment,
  reconcilePropertyIdentity, sealCallReceipt, sha256, stableJson, validateCatalogModels,
  validateReviewIndex, validateReviewRequest,
} from "./protected-refusal-review-core.mjs";

const requestId = hash("request");
const candidate = {
  caseId: "dp-0123456789ab", corpusId: "corpus-0123456789abcdef",
  assignmentEventSha256: hash("assignment"), sourceSha256: hash("source"), sourceBytes: 100,
  sourcePath: "sources/dp-0123456789ab.pdf", selector: { pages: [1, 2], tractIds: ["legal-description"],
    cropReceiptSha256: hash("crop") },
  selectorSha256: hashJson({ pages: [1, 2], tractIds: ["legal-description"], cropReceiptSha256: hash("crop") }),
  expectedFailureCandidate: { code: "PARSE_UNRESOLVED", statement: "A referenced exhibit is absent." },
};
candidate.expectedFailureCandidateSha256 = hashJson(candidate.expectedFailureCandidate);

test("review candidates bind exact source, complete ordered page selector, and expected-code candidate", () => {
  const review = { schemaVersion: 1, kind: "spaceport-refusal-truth-review-candidates", requestId,
    campaign: "deed-plotting-50-real", cases: [candidate] };
  assert.equal(validateReviewRequest(review, { requestId }).cases.length, 1);
  assert.throws(() => validateReviewRequest({ ...review, cases: [{ ...candidate, selector: {
    ...candidate.selector, pages: [1, 3] } }] }, { requestId }),
    /source, selector, or expected-code binding/);
  assert.throws(() => validateReviewRequest({ ...review, cases: [{ ...candidate, expectedFailureCandidate: {
    ...candidate.expectedFailureCandidate, code: "DOD_FAIL" } }] }, { requestId }), /source, selector, or expected-code binding/);
});

test("official live-catalog commitments require two distinct multimodal provider identities", () => {
  const catalog = REVIEW_MODELS.map((model) => ({ id: model.model, version: model.version, publisher: model.provider,
    supported_input_modalities: ["text", "image"], supported_output_modalities: ["text"] }));
  assert.deepEqual(validateCatalogModels(catalog), REVIEW_MODELS.map((model) => ({ ...model })));
  assert.throws(() => validateCatalogModels(catalog.map((entry) => ({ ...entry, publisher: "OpenAI" }))), /absent or not multimodal/);
  assert.throws(() => validateCatalogModels(catalog.map((entry) => ({ ...entry, supported_input_modalities: ["text"] }))), /not multimodal/);
});

test("assessment prompt binds protected challenge and every immutable candidate hash", () => {
  const prompt = buildAssessmentPrompt({ requestId, challengeSha256: hash("challenge"), candidate, model: REVIEW_MODELS[0] });
  for (const value of [requestId, hash("challenge"), candidate.sourceSha256, candidate.selectorSha256,
    candidate.expectedFailureCandidateSha256, "[1,2]"]) assert.match(prompt, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(prompt, /No product implementation, product output/);
});

test("two approving systems must agree on source-visible property identity", () => {
  const propertyIdentity = {
    county: "Utah County", recordingInstrument: "Entry 12345", subdivision: null,
    lot: null, block: null, parcel: "12:345:6789", tract: "Tract A",
    citations: [
      { page: 1, field: "county", visibleText: "Utah County" },
      { page: 1, field: "recordingInstrument", visibleText: "Entry 12345" },
      { page: 2, field: "parcel", visibleText: "12:345:6789" },
      { page: 2, field: "tract", visibleText: "Tract A" },
    ],
  };
  const base = { decision: "approve-refusal", expectedFailureCode: "PARSE_UNRESOLVED", pagesReviewed: [1, 2],
    analysis: "The deed references an absent exhibit needed to close the boundary.", missingInformation: ["Exhibit A"], propertyIdentity };
  const left = normalizeAssessment(base, candidate); const right = normalizeAssessment(structuredClone(base), candidate);
  const result = reconcilePropertyIdentity(left.propertyIdentity, right.propertyIdentity);
  assert.match(result.propertyIdentityEvidenceSha256, /^[a-f0-9]{64}$/);
  assert.match(result.propertyGroupSha256, /^[a-f0-9]{64}$/);
  const changed = structuredClone(right.propertyIdentity); changed.parcel = "99:999:9999";
  assert.throws(() => reconcilePropertyIdentity(left.propertyIdentity, changed), /disagreed/);
});

test("review index enforces call, session, provider, returned-model, challenge, and property-group uniqueness", () => {
  const challenge = hash("challenge");
  const calls = REVIEW_MODELS.map((model, index) => call(model, index, challenge));
  const caseResult = {
    caseId: candidate.caseId, corpusId: candidate.corpusId,
    assignmentEventSha256: candidate.assignmentEventSha256, sourceSha256: candidate.sourceSha256,
    selectorSha256: candidate.selectorSha256, expectedFailureCandidateSha256: candidate.expectedFailureCandidateSha256,
    expectedFailureCode: "PARSE_UNRESOLVED", assessmentSha256s: [hash("a1"), hash("a2")],
    callReceiptSha256s: calls.map((item) => item.receiptSha256), calls,
    propertyIdentityEvidenceSha256: hash("identity"), propertyGroupSha256: hash("group"),
    status: "approved", critical: 0, major: 0,
  };
  const request = { requestId, reviewRequestSha256: hash("review"), verifierPolicyTip: "a".repeat(40) };
  const hosted = { verifierPolicyTip: request.verifierPolicyTip, workflowRef: REVIEW_WORKFLOW_REF, runId: "123", runAttempt: "1" };
  const index = buildReviewIndex({ request, challengeSha256: challenge, catalogSha256: hash("catalog"), cases: [caseResult], hosted });
  assert.equal(validateReviewIndex(index, request).cases, 1);
  const replay = structuredClone(caseResult); replay.caseId = "dp-abcdefabcdef";
  assert.throws(() => buildReviewIndex({ request, challengeSha256: challenge, catalogSha256: hash("catalog"),
    cases: [caseResult, replay], hosted }), /receipt is invalid|independence.*property-group/);
  const sameReturned = structuredClone(caseResult); sameReturned.calls[1].modelReturned = sameReturned.calls[0].modelReturned;
  assert.throws(() => buildReviewIndex({ request, challengeSha256: challenge, catalogSha256: hash("catalog"),
    cases: [sameReturned], hosted }), /receipt is invalid|independence.*property-group/);
});

test("protected workflow has no product checkout and retains challenge, OIDC attestation, encrypted return, and cleanup gates", () => {
  const workflow = readFileSync(new URL("../.github/workflows/protected-refusal-reviewer.yml", import.meta.url), "utf8");
  assert.doesNotMatch(workflow, /repository:\s+HansenHomeAI\/Autodesk-automation/);
  for (const text of ["openssl rand 32", "actions/attest@", "gh attestation verify", "--deny-self-hosted-runners",
    "encrypt-evidence", "Upload ciphertext evidence only", "rm -rf \"$RUNNER_TEMP/deed-refusal-review\""]) assert.match(workflow, new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

function call(model, index, challenge) {
  return sealCallReceipt({ requestId, caseId: candidate.caseId, challengeSha256: challenge,
    modelRequested: model.model, modelVersion: model.version, provider: model.provider,
    modelReturned: `${model.model}-returned`, callId: `call-${index}`, sessionIdSha256: hash(`session-${index}`),
    promptSha256: hash(`prompt-${index}`), schemaSha256: hash("schema"), imageManifestSha256: hash("images"),
    outputSha256: hash(`output-${index}`), rawResponseSha256: hash(`raw-${index}`), catalogSha256: hash("catalog"),
    catalogVersion: model.version, attempts: 1, completedAt: "2026-07-15T12:00:00.000Z" });
}
function hash(value) { return sha256(value); }
function hashJson(value) { return sha256(stableJson(value)); }
