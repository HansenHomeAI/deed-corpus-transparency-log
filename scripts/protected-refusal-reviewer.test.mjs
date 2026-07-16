import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  REVIEW_MODELS, REVIEW_WORKFLOW_REF, buildAssessmentPrompt, buildReviewIndex, canonicalizePropertyIdentifier, normalizeAssessment,
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
  expectedFailureCandidate: { code: "PARSE_UNRESOLVED", stage: "analyze", category: "deed_by_reference",
    decisiveSourceObservations: ["A referenced exhibit is absent."],
    requiredMissingInformation: ["The incorporated exhibit"],
    evidenceSelectors: ["full-source-pages:1,2"], evidenceSha256: hash("evidence"),
    evidenceReceiptSha256s: [hash("receipt-a"), hash("receipt-b")], selectorReceiptSha256: hash("selector-receipt"),
    refusalFingerprintSha256: hash("refusal-fingerprint"),
    zeroGeometryPolicy: { geometryArtifactsExpected: 0, partialCertifiedGeometryAllowed: false } },
};
candidate.expectedFailureCandidateSha256 = hashJson(candidate.expectedFailureCandidate);

test("property canonicalization handles common labels without collapsing segmented identifiers", () => {
  for (const [field, left, right] of [
    ["subdivision", "Sunset Subdivision No. 2", "Sunset Subd. #2"],
    ["parcel", "Parcel ID 001-02", "APN 1-2"],
    ["lot", "Lot No. 007", "7"],
    ["block", "Block 02", "2"],
    ["county", "County of Utah", "Utah County"],
  ]) assert.equal(canonicalizePropertyIdentifier(field, left), canonicalizePropertyIdentifier(field, right), `${field} variant`);
  assert.notEqual(canonicalizePropertyIdentifier("parcel", "Parcel ID 001-02"),
    canonicalizePropertyIdentifier("parcel", "APN 102"), "segmented and concatenated parcel identifiers can be distinct");
});

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
  const base = { decision: "approve-refusal", expectedFailureCode: "PARSE_UNRESOLVED",
    expectedFailureStage: "analyze", expectedFailureCategory: "deed_by_reference",
    decisiveSourceObservationsConfirmed: ["A referenced exhibit is absent."],
    requiredMissingInformationConfirmed: ["The incorporated exhibit"],
    evidenceSelectorsConfirmed: ["full-source-pages:1,2"], zeroGeometryConfirmed: true, pagesReviewed: [1, 2],
    analysis: "The deed references an absent exhibit needed to close the boundary.", missingInformation: ["Exhibit A"], propertyIdentity };
  const left = normalizeAssessment(base, candidate); const right = normalizeAssessment(structuredClone(base), candidate);
  const result = reconcilePropertyIdentity(left.propertyIdentity, right.propertyIdentity);
  assert.match(result.propertyIdentityEvidenceSha256, /^[a-f0-9]{64}$/);
  assert.match(result.propertyAliasReceiptSha256, /^[a-f0-9]{64}$/);
  assert.ok(result.propertyAliases.some((alias) => alias.kind === "county-parcel"));
  const laterInstrumentLeft = structuredClone(left.propertyIdentity);
  const laterInstrumentRight = structuredClone(right.propertyIdentity);
  laterInstrumentLeft.recordingInstrument = "ENTRY 88888";
  laterInstrumentRight.recordingInstrument = "ENTRY 88888";
  assert.deepEqual(reconcilePropertyIdentity(laterInstrumentLeft, laterInstrumentRight).propertyAliases,
    result.propertyAliases, "same parcel/tract across recording instruments must dedupe");
  const plattedLeft = { county: "Utah County", recordingInstrument: "ENTRY 11111", subdivision: "Sunset Subdivision",
    lot: "LOT 7", block: "BLOCK 2", parcel: null, tract: null, citations: [] };
  const plattedRight = { ...plattedLeft, county: "County of Utah", subdivision: "Sunset Subd.",
    lot: "7", block: "2", recordingInstrument: "ENTRY 22222" };
  assert.deepEqual(reconcilePropertyIdentity(plattedLeft, plattedLeft).propertyAliases,
    reconcilePropertyIdentity(plattedRight, plattedRight).propertyAliases,
    "same subdivision/lot/block in separate title instruments must dedupe");
  assert.equal(reconcilePropertyIdentity({ ...plattedLeft, parcel: "APN 0012:0034:0007" },
    { ...plattedRight, parcel: "12-34-7" }).propertyAliases.filter((alias) => alias.kind === "county-parcel").length, 1,
  "county forms, prefixes, punctuation, subdivision suffixes, and numeric formatting must canonicalize");
  const basePlat = reconcilePropertyIdentity(plattedLeft, plattedLeft).propertyAliases;
  const withParcel = reconcilePropertyIdentity({ ...plattedLeft, parcel: "12:34" }, { ...plattedLeft, parcel: "12:34" }).propertyAliases;
  const withTract = reconcilePropertyIdentity({ ...plattedRight, tract: "TRACT A" }, { ...plattedRight, tract: "TRACT A" }).propertyAliases;
  const baseHashes = new Set(basePlat.map((alias) => alias.sha256));
  assert.ok(withParcel.some((alias) => baseHashes.has(alias.sha256)));
  assert.ok(withTract.some((alias) => baseHashes.has(alias.sha256)),
    "optional parcel or tract must not remove the stable subdivision/lot/block aliases");
  const blockOne = reconcilePropertyIdentity({ ...plattedLeft, block: "Block 1" }, { ...plattedLeft, block: "1" });
  const blockTwo = reconcilePropertyIdentity({ ...plattedRight, block: "BLK. 2" }, { ...plattedRight, block: "2" });
  assert.equal(blockOne.propertyAliases.find((alias) => alias.kind === "county-subdivision-lot").sha256,
    blockTwo.propertyAliases.find((alias) => alias.kind === "county-subdivision-lot").sha256);
  assert.notEqual(blockOne.propertyAliases.find((alias) => alias.kind === "county-subdivision-block-lot").sha256,
    blockTwo.propertyAliases.find((alias) => alias.kind === "county-subdivision-block-lot").sha256,
    "block-aware aliases must be stronger than the shared blockless alias");
  const tamperedBasis = structuredClone(base); tamperedBasis.expectedFailureStage = "execute";
  assert.throws(() => normalizeAssessment(tamperedBasis, candidate), /exact candidate refusal/);
  const changed = structuredClone(right.propertyIdentity); changed.parcel = "99:999:9999";
  changed.recordingInstrument = "ENTRY 99999"; changed.tract = "TRACT Z";
  assert.throws(() => reconcilePropertyIdentity(left.propertyIdentity, changed), /conflicting stable property identifiers/);
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
    propertyIdentityEvidenceSha256: hash("identity"),
    propertyAliases: [{ kind: "county-subdivision-block-lot", strength: "strong", sha256: hash("group") }],
    propertyIdentifierCommitments: [{ field: "block", sha256: hash("block") },
      { field: "county", sha256: hash("county") }, { field: "lot", sha256: hash("lot") },
      { field: "subdivision", sha256: hash("subdivision") }],
    propertyAliasReceiptSha256: hash("alias-receipt"),
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
    "persist-credentials: false", "contents: write", "encrypt-evidence", "encrypt-registry-evidence",
    "registry-evidence.bundle", "Upload ciphertext evidence only",
    "rm -rf \"$RUNNER_TEMP/deed-refusal-review\""]) assert.match(workflow, new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
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
