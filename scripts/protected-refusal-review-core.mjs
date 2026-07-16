import { createHash } from "node:crypto";

export const REVIEW_REPOSITORY = "HansenHomeAI/deed-corpus-transparency-log";
export const REVIEW_WORKFLOW = ".github/workflows/protected-refusal-reviewer.yml";
export const REVIEW_WORKFLOW_REF = `${REVIEW_REPOSITORY}/${REVIEW_WORKFLOW}@refs/heads/main`;
export const REVIEW_MODELS = Object.freeze([
  Object.freeze({ provider: "OpenAI", model: "openai/gpt-4.1", version: "2025-04-14" }),
  Object.freeze({ provider: "Meta", model: "meta/llama-4-maverick-17b-128e-instruct-fp8", version: "1" }),
]);
export const REFUSAL_CODES = Object.freeze([
  "SOURCE_HASH_MISMATCH", "TRANSCRIPTION_UNRESOLVED", "TRANSCRIPTION_DISAGREEMENT",
  "TRACT_AMBIGUOUS", "PARSE_CALL_OMITTED", "PARSE_UNRESOLVED", "TOPOLOGY_MISMATCH",
  "CURVE_UNRESOLVED", "CLOSURE_FAIL", "AREA_FAIL", "TRUTH_CONGRUENCE_FAIL",
  "SEGMENT_TRUTH_FAIL", "DOD_FAIL", "VISUAL_FAIL", "CRITIC_MAJOR", "REPEAT_NONDETERMINISM",
]);

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const CASE_ID = /^dp-[a-f0-9]{12}$/;
const CORPUS_ID = /^corpus-[a-f0-9]{16}$/;

export function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
export function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validateProtectedReviewerEnvironment(env = process.env) {
  const result = {
    repository: env.GITHUB_REPOSITORY || null,
    verifierPolicyTip: env.GITHUB_SHA || null,
    workflowRef: env.SPACEPORT_REFUSAL_REVIEW_WORKFLOW_REF || null,
    runnerOs: env.RUNNER_OS || null,
    runnerEnvironment: env.SPACEPORT_RUNNER_ENVIRONMENT || null,
    runId: env.GITHUB_RUN_ID || null,
    runAttempt: env.GITHUB_RUN_ATTEMPT || null,
  };
  if (env.GITHUB_ACTIONS !== "true" || result.repository !== REVIEW_REPOSITORY
    || result.workflowRef !== REVIEW_WORKFLOW_REF || result.runnerEnvironment !== "github-hosted"
    || !["macOS", "Linux"].includes(result.runnerOs) || !GIT_SHA.test(result.verifierPolicyTip || "")
    || !/^[1-9][0-9]*$/.test(result.runId || "") || !/^[1-9][0-9]*$/.test(result.runAttempt || "")) {
    throw new Error("Refusal review requires the exact protected public workflow on a GitHub-hosted runner.");
  }
  return { ok: true, ...result };
}

export function validateReviewDispatchRequest(request, { env = process.env } = {}) {
  const hosted = validateProtectedReviewerEnvironment(env);
  exactKeys(request, ["schemaVersion", "kind", "requestId", "verifierPolicyTip", "inputReleaseId",
    "sourceAssetId", "sourceBundleSha256", "reviewRequestSha256", "requesterPublicKeyPemBase64",
    "requesterPublicKeySha256"], "review dispatch request");
  const key = Buffer.from(request?.requesterPublicKeyPemBase64 || "", "base64");
  if (request.schemaVersion !== 1 || request.kind !== "spaceport-protected-refusal-review-request"
    || !SHA256.test(request.requestId || "") || request.verifierPolicyTip !== hosted.verifierPolicyTip
    || !/^[1-9][0-9]*$/.test(String(request.inputReleaseId || ""))
    || !/^[1-9][0-9]*$/.test(String(request.sourceAssetId || ""))
    || !SHA256.test(request.sourceBundleSha256 || "") || !SHA256.test(request.reviewRequestSha256 || "")
    || key.length < 256 || key.toString("base64") !== request.requesterPublicKeyPemBase64
    || sha256(key) !== request.requesterPublicKeySha256) {
    throw new Error("Protected refusal-review dispatch is invalid or stale.");
  }
  return { ...structuredClone(request), hosted, requesterPublicKeyPem: key.toString("utf8") };
}

export function validateReviewRequest(review, { requestId, root = null } = {}) {
  exactKeys(review, ["schemaVersion", "kind", "requestId", "campaign", "cases"], "review request");
  if (review.schemaVersion !== 1 || review.kind !== "spaceport-refusal-truth-review-candidates"
    || review.requestId !== requestId || review.campaign !== "deed-plotting-50-real"
    || !Array.isArray(review.cases) || review.cases.length < 1 || review.cases.length > 50) {
    throw new Error("Refusal candidate request schema is invalid.");
  }
  const ids = new Set();
  for (const item of review.cases) {
    exactKeys(item, ["caseId", "corpusId", "assignmentEventSha256", "sourceSha256", "sourceBytes",
      "sourcePath", "selector", "selectorSha256", "expectedFailureCandidate", "expectedFailureCandidateSha256"],
    `review case ${item?.caseId || "unknown"}`);
    exactKeys(item.selector, ["pages", "tractIds", "cropReceiptSha256"], "source selector");
    exactKeys(item.expectedFailureCandidate, ["code", "statement"], "expected-failure candidate");
    const pages = item.selector?.pages;
    if (!CASE_ID.test(item.caseId || "") || ids.has(item.caseId) || !CORPUS_ID.test(item.corpusId || "")
      || !SHA256.test(item.assignmentEventSha256 || "") || !SHA256.test(item.sourceSha256 || "")
      || !Number.isInteger(item.sourceBytes) || item.sourceBytes < 1 || item.sourcePath !== `sources/${item.caseId}.pdf`
      || !Array.isArray(pages) || pages.length < 1 || pages.some((page, i) => page !== i + 1)
      || !Array.isArray(item.selector.tractIds) || item.selector.tractIds.length < 1
      || new Set(item.selector.tractIds).size !== item.selector.tractIds.length
      || item.selector.tractIds.some((tract) => typeof tract !== "string" || !tract)
      || !SHA256.test(item.selector.cropReceiptSha256 || "")
      || item.selectorSha256 !== sha256(stableJson(item.selector))
      || !REFUSAL_CODES.includes(item.expectedFailureCandidate?.code)
      || typeof item.expectedFailureCandidate?.statement !== "string" || item.expectedFailureCandidate.statement.length < 1
      || item.expectedFailureCandidate.statement.length > 2000
      || item.expectedFailureCandidateSha256 !== sha256(stableJson(item.expectedFailureCandidate))) {
      throw new Error(`Refusal candidate ${item?.caseId || "unknown"} has invalid source, selector, or expected-code binding.`);
    }
    if (root) {
      const bytes = root(item.sourcePath);
      if (bytes.length !== item.sourceBytes || sha256(bytes) !== item.sourceSha256) throw new Error(`Source commitment failed for ${item.caseId}.`);
    }
    ids.add(item.caseId);
  }
  return structuredClone(review);
}

export function buildAssessmentSchema(pageCount) {
  return {
    type: "object", additionalProperties: false,
    required: ["decision", "expectedFailureCode", "pagesReviewed", "analysis", "missingInformation", "propertyIdentity"],
    properties: {
      decision: { type: "string", enum: ["approve-refusal", "reject-refusal", "uncertain"] },
      expectedFailureCode: { type: ["string", "null"], enum: [...REFUSAL_CODES, null] },
      pagesReviewed: { type: "array", minItems: pageCount, maxItems: pageCount, uniqueItems: true,
        items: { type: "integer", minimum: 1, maximum: pageCount } },
      analysis: { type: "string", minLength: 1, maxLength: 8000 },
      missingInformation: { type: "array", maxItems: 50, items: { type: "string", minLength: 1, maxLength: 500 } },
      propertyIdentity: {
        type: "object", additionalProperties: false,
        required: ["county", "recordingInstrument", "subdivision", "lot", "block", "parcel", "tract", "citations"],
        properties: {
          county: nullableString(), recordingInstrument: nullableString(), subdivision: nullableString(),
          lot: nullableString(), block: nullableString(), parcel: nullableString(), tract: nullableString(),
          citations: { type: "array", minItems: 1, maxItems: 30, items: {
            type: "object", additionalProperties: false, required: ["page", "field", "visibleText"], properties: {
              page: { type: "integer", minimum: 1, maximum: pageCount },
              field: { type: "string", enum: ["county", "recordingInstrument", "subdivision", "lot", "block", "parcel", "tract"] },
              visibleText: { type: "string", minLength: 1, maxLength: 500 },
            },
          } },
        },
      },
    },
  };
}

function nullableString() { return { type: ["string", "null"], minLength: 1, maxLength: 500 }; }

export function buildAssessmentPrompt({ requestId, challengeSha256, candidate, model }) {
  return [
    "You are an independent property-deed refusal-truth reviewer. Inspect every supplied page image yourself.",
    "No product implementation, product output, prior model answer, or geometry artifact is available.",
    "Approve only when the deed alone visibly supports the candidate typed refusal; never infer unreadable text.",
    `Protected request: ${requestId}`,
    `Protected challenge SHA-256: ${challengeSha256}`,
    `Case: ${candidate.caseId}`,
    `Source SHA-256: ${candidate.sourceSha256}`,
    `Selector SHA-256: ${candidate.selectorSha256}`,
    `Expected-failure candidate SHA-256: ${candidate.expectedFailureCandidateSha256}`,
    `Candidate code: ${candidate.expectedFailureCandidate.code}`,
    `Candidate statement: ${candidate.expectedFailureCandidate.statement}`,
    `Independent system: ${model.provider} / ${model.model} / catalog version ${model.version}`,
    `Return pagesReviewed exactly [${candidate.selector.pages.join(",")}].`,
    "For propertyIdentity, transcribe only source-visible stable recording/tract identifiers. Use null when absent.",
    "Citations must quote the visible source text that supports every non-null identity field.",
    "Return JSON only, conforming exactly to the supplied schema.",
  ].join("\n");
}

export function validateCatalogModels(catalog) {
  if (!Array.isArray(catalog)) throw new Error("Official GitHub Models catalog is invalid.");
  const commitments = [];
  for (const expected of REVIEW_MODELS) {
    const actual = catalog.find((entry) => entry?.id === expected.model);
    if (!actual || actual.version !== expected.version || actual.publisher !== expected.provider
      || !actual.supported_input_modalities?.includes("image") || !actual.supported_input_modalities?.includes("text")
      || !actual.supported_output_modalities?.includes("text")) {
      throw new Error(`Pinned distinct reviewer ${expected.model}@${expected.version} is absent or not multimodal.`);
    }
    commitments.push({ provider: expected.provider, model: expected.model, version: expected.version });
  }
  if (new Set(commitments.map((entry) => entry.provider)).size !== REVIEW_MODELS.length
    || new Set(commitments.map((entry) => entry.model)).size !== REVIEW_MODELS.length) {
    throw new Error("Reviewer systems must have distinct model and provider identities.");
  }
  return commitments;
}

export function normalizeAssessment(assessment, candidate) {
  const schema = buildAssessmentSchema(candidate.selector.pages.length);
  if (!assessment || typeof assessment !== "object" || Array.isArray(assessment)) throw new Error("Assessment is not an object.");
  exactKeys(assessment, schema.required, "assessment");
  if (!schema.properties.decision.enum.includes(assessment.decision)
    || !schema.properties.expectedFailureCode.enum.includes(assessment.expectedFailureCode)
    || stableJson(assessment.pagesReviewed) !== stableJson(candidate.selector.pages)
    || typeof assessment.analysis !== "string" || assessment.analysis.length < 1
    || !Array.isArray(assessment.missingInformation)
    || assessment.decision !== "approve-refusal" || assessment.expectedFailureCode !== candidate.expectedFailureCandidate.code) {
    throw new Error("Independent assessment did not approve the exact candidate refusal over all pages.");
  }
  const identity = normalizeIdentity(assessment.propertyIdentity, candidate.selector.pages.length);
  return { ...structuredClone(assessment), propertyIdentity: identity };
}

export function normalizeIdentity(identity, pageCount) {
  exactKeys(identity, ["county", "recordingInstrument", "subdivision", "lot", "block", "parcel", "tract", "citations"], "property identity");
  const fields = ["county", "recordingInstrument", "subdivision", "lot", "block", "parcel", "tract"];
  const normalized = {};
  for (const field of fields) {
    if (identity[field] !== null && (typeof identity[field] !== "string" || !identity[field].trim())) throw new Error("Property identity field is invalid.");
    normalized[field] = identity[field] === null ? null : normalizeVisible(identity[field]);
  }
  if (!Array.isArray(identity.citations) || identity.citations.length < 1) throw new Error("Property identity needs source-visible citations.");
  normalized.citations = identity.citations.map((citation) => {
    exactKeys(citation, ["page", "field", "visibleText"], "property identity citation");
    if (!Number.isInteger(citation.page) || citation.page < 1 || citation.page > pageCount
      || !fields.includes(citation.field) || typeof citation.visibleText !== "string" || !citation.visibleText.trim()) {
      throw new Error("Property identity citation is invalid.");
    }
    return { page: citation.page, field: citation.field, visibleText: normalizeVisible(citation.visibleText) };
  }).sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  for (const field of fields) if (normalized[field] !== null && !normalized.citations.some((citation) => citation.field === field)) {
    throw new Error(`Property identity field ${field} lacks a source-visible citation.`);
  }
  if (!fields.some((field) => normalized[field] !== null)) throw new Error("No stable source-visible property identity was extracted.");
  return normalized;
}

export function reconcilePropertyIdentity(left, right) {
  const identityFields = ["county", "recordingInstrument", "subdivision", "lot", "block", "parcel", "tract"];
  const leftKey = Object.fromEntries(identityFields.map((field) => [field, left[field]]));
  const rightKey = Object.fromEntries(identityFields.map((field) => [field, right[field]]));
  const agreedIdentity = Object.fromEntries(identityFields.map((field) => [field,
    leftKey[field] !== null && leftKey[field] === rightKey[field] ? leftKey[field] : null]));
  const propertySpecific = ["recordingInstrument", "subdivision", "lot", "block", "parcel", "tract"];
  if (!propertySpecific.some((field) => agreedIdentity[field] !== null)) {
    throw new Error("Independent reviewers share no stable source-visible property identifier.");
  }
  const evidence = { reviewerIdentities: [leftKey, rightKey], agreedIdentity,
    reviewerCitations: [left.citations, right.citations] };
  return {
    propertyIdentityEvidence: evidence,
    propertyIdentityEvidenceSha256: sha256(stableJson(evidence)),
    propertyGroupSha256: sha256(stableJson({ schemaVersion: 1, kind: "source-visible-property-group",
      identity: agreedIdentity })),
  };
}

export function sealCallReceipt(input) {
  exactKeys(input, ["requestId", "caseId", "challengeSha256", "modelRequested", "modelVersion", "provider",
    "modelReturned", "callId", "sessionIdSha256", "promptSha256", "schemaSha256", "imageManifestSha256",
    "outputSha256", "rawResponseSha256", "catalogSha256", "catalogVersion", "attempts", "completedAt"], "call receipt input");
  const receipt = { schemaVersion: 1, kind: "spaceport-protected-refusal-model-call", ...structuredClone(input) };
  validateCallReceipt(receipt);
  receipt.receiptSha256 = sha256(stableJson(receipt));
  return receipt;
}

export function validateCallReceipt(receipt) {
  exactKeys(receipt, ["schemaVersion", "kind", "requestId", "caseId", "challengeSha256", "modelRequested",
    "modelVersion", "provider", "modelReturned", "callId", "sessionIdSha256", "promptSha256", "schemaSha256",
    "imageManifestSha256", "outputSha256", "rawResponseSha256", "catalogSha256", "catalogVersion", "attempts",
    "completedAt", ...(receipt?.receiptSha256 ? ["receiptSha256"] : [])], "model call receipt");
  const expected = REVIEW_MODELS.find((item) => item.model === receipt.modelRequested);
  if (receipt.schemaVersion !== 1 || receipt.kind !== "spaceport-protected-refusal-model-call"
    || !SHA256.test(receipt.requestId || "") || !CASE_ID.test(receipt.caseId || "") || !SHA256.test(receipt.challengeSha256 || "")
    || !expected || receipt.provider !== expected.provider || receipt.modelVersion !== expected.version
    || typeof receipt.modelReturned !== "string" || !receipt.modelReturned
    || typeof receipt.callId !== "string" || !receipt.callId || !SHA256.test(receipt.sessionIdSha256 || "")
    || ["promptSha256", "schemaSha256", "imageManifestSha256", "outputSha256", "rawResponseSha256", "catalogSha256"].some((field) => !SHA256.test(receipt[field] || ""))
    || receipt.catalogVersion !== expected.version || !Number.isInteger(receipt.attempts) || receipt.attempts < 1
    || !validIso(receipt.completedAt)
    || (receipt.receiptSha256 && receipt.receiptSha256 !== sha256(stableJson(Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== "receiptSha256")))))) {
    throw new Error("Protected model-call receipt is invalid.");
  }
  return receipt;
}

export function buildReviewIndex({ request, challengeSha256, catalogSha256, cases, hosted }) {
  if (!SHA256.test(challengeSha256 || "") || !SHA256.test(catalogSha256 || "") || !Array.isArray(cases) || cases.length < 1) throw new Error("Review index inputs are invalid.");
  const callIds = new Set(); const sessions = new Set(); const propertyGroups = new Set();
  for (const item of cases) {
    exactKeys(item, ["caseId", "corpusId", "assignmentEventSha256", "sourceSha256", "selectorSha256",
      "expectedFailureCandidateSha256", "expectedFailureCode", "assessmentSha256s", "callReceiptSha256s", "calls",
      "propertyIdentityEvidenceSha256", "propertyGroupSha256", "status", "critical", "major"], "review-index case");
    if (!Array.isArray(item.calls) || item.calls.length !== 2) throw new Error("Every case requires exactly two independent semantic calls.");
    item.calls.forEach(validateCallReceipt);
    if (new Set(item.calls.map((call) => call.modelRequested)).size !== 2
      || new Set(item.calls.map((call) => call.provider)).size !== 2
      || new Set(item.calls.map((call) => call.modelReturned)).size !== 2
      || item.calls.some((call) => call.challengeSha256 !== challengeSha256 || call.requestId !== request.requestId || call.caseId !== item.caseId)
      || item.calls.some((call) => callIds.has(call.callId) || sessions.has(call.sessionIdSha256))
      || !CASE_ID.test(item.caseId || "") || !CORPUS_ID.test(item.corpusId || "")
      || !SHA256.test(item.assignmentEventSha256 || "") || !SHA256.test(item.sourceSha256 || "")
      || !SHA256.test(item.selectorSha256 || "") || !SHA256.test(item.expectedFailureCandidateSha256 || "")
      || !REFUSAL_CODES.includes(item.expectedFailureCode)
      || !Array.isArray(item.assessmentSha256s) || item.assessmentSha256s.length !== 2 || item.assessmentSha256s.some((value) => !SHA256.test(value))
      || stableJson(item.callReceiptSha256s) !== stableJson(item.calls.map((call) => call.receiptSha256))
      || !SHA256.test(item.propertyIdentityEvidenceSha256 || "") || !SHA256.test(item.propertyGroupSha256 || "")
      || propertyGroups.has(item.propertyGroupSha256) || item.status !== "approved" || item.critical !== 0 || item.major !== 0) {
      throw new Error("Call independence, protected challenge, or unique property-group binding failed.");
    }
    item.calls.forEach((call) => { callIds.add(call.callId); sessions.add(call.sessionIdSha256); });
    propertyGroups.add(item.propertyGroupSha256);
  }
  return {
    schemaVersion: 1, kind: "spaceport-protected-refusal-review-index", requestId: request.requestId,
    reviewRequestSha256: request.reviewRequestSha256, verifierPolicyTip: hosted.verifierPolicyTip,
    reviewerWorkflowRef: hosted.workflowRef, reviewerWorkflowRunId: hosted.runId,
    reviewerWorkflowRunAttempt: hosted.runAttempt, protectedChallengeSha256: challengeSha256,
    catalogSha256, models: REVIEW_MODELS.map((item) => ({ ...item })),
    productCodeMounted: false, productOutputAvailable: false, geometryArtifactsExpected: 0,
    cases: structuredClone(cases), status: "approved", critical: 0, major: 0,
    completedAt: new Date().toISOString(),
  };
}

export function validateReviewIndex(index, request) {
  exactKeys(index, ["schemaVersion", "kind", "requestId", "reviewRequestSha256", "verifierPolicyTip",
    "reviewerWorkflowRef", "reviewerWorkflowRunId", "reviewerWorkflowRunAttempt", "protectedChallengeSha256",
    "catalogSha256", "models", "productCodeMounted", "productOutputAvailable", "geometryArtifactsExpected",
    "cases", "status", "critical", "major", "completedAt"], "review index");
  if (index.schemaVersion !== 1 || index.kind !== "spaceport-protected-refusal-review-index"
    || index.requestId !== request.requestId || index.reviewRequestSha256 !== request.reviewRequestSha256
    || index.verifierPolicyTip !== request.verifierPolicyTip || index.reviewerWorkflowRef !== REVIEW_WORKFLOW_REF
    || !/^[1-9][0-9]*$/.test(index.reviewerWorkflowRunId || "") || !/^[1-9][0-9]*$/.test(index.reviewerWorkflowRunAttempt || "")
    || !SHA256.test(index.protectedChallengeSha256 || "") || !SHA256.test(index.catalogSha256 || "")
    || stableJson(index.models) !== stableJson(REVIEW_MODELS)
    || index.productCodeMounted !== false || index.productOutputAvailable !== false || index.geometryArtifactsExpected !== 0
    || index.status !== "approved" || index.critical !== 0 || index.major !== 0 || !validIso(index.completedAt)) {
    throw new Error("Protected refusal-review index header is invalid.");
  }
  buildReviewIndex({ request, challengeSha256: index.protectedChallengeSha256, catalogSha256: index.catalogSha256,
    cases: index.cases, hosted: { verifierPolicyTip: index.verifierPolicyTip, workflowRef: index.reviewerWorkflowRef,
      runId: index.reviewerWorkflowRunId, runAttempt: index.reviewerWorkflowRunAttempt } });
  return { reviewIndexSha256: sha256(`${JSON.stringify(index, null, 2)}\n`), cases: index.cases.length };
}

function normalizeVisible(value) { return value.normalize("NFKC").trim().replace(/\s+/g, " ").toUpperCase(); }
function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new Error(`${label} fields are not exact.`);
  }
}
function validIso(value) { return typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value; }
