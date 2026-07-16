import { createHash } from "node:crypto";

const SHA256 = /^[a-f0-9]{64}$/;
const CASE_ID = /^dp-[a-f0-9]{12}$/;
const CORPUS_ID = /^corpus-[a-f0-9]{16}$/;
const FAMILY_ID = /^family-[a-f0-9]{12}$/;
const ZERO = "0".repeat(64);
const SPLITS = new Set(["tuning", "final", "fail-safe", "legacy-quarantine"]);
const EXECUTABLE_SPLITS = new Set(["tuning", "final", "fail-safe"]);
export const CORPUS_EVENT_TYPES = new Set([
  "assign", "review-seal", "truth-seal", "source-release", "consume", "execution-seal",
  "judge-challenge", "judge-seal", "legacy-quarantine",
]);
const IDENTITY_FIELDS = ["sourceSha256", "selectorSha256", "propertyIdentitySha256", "titleChainGroupSha256"];
const TRUTH_IDENTITY_FIELDS = ["descriptionSha256", "geometrySha256"];
export const CORPUS_REPOSITORY = "HansenHomeAI/Autodesk-automation";
export const CORPUS_REF = "refs/heads/deed-corpus-registry";

export function corpusRegistryEventSha256(event) {
  const copy = structuredClone(event || {});
  delete copy.eventSha256;
  return sha256(stableJson(copy));
}

export function corpusRegistryRootSha256(registry) {
  return sha256(stableJson(registry));
}

export function appendCorpusRegistryEvent(registry, event) {
  const next = structuredClone(registry);
  const body = {
    ...structuredClone(event),
    schemaVersion: 1,
    sequence: next.events.length + 1,
    previousEventSha256: next.events.at(-1)?.eventSha256 || ZERO,
  };
  body.eventSha256 = corpusRegistryEventSha256(body);
  next.events.push(body);
  return next;
}

// This is the detailed validator used by the canonical deed-corpus registry.
// Keep its assignment, identity, cap, truth, release, execution, and judge
// invariants synchronized with scripts/deed-corpus-registry.mjs.
export function validateCorpusRegistry({ registry, previousRegistry = null } = {}) {
  const errors = [];
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    return verdict([failure("REGISTRY_SCHEMA", "registry must be an object")]);
  }
  if (registry.schemaVersion !== 1 || registry.campaign !== "deed-plotting-50-real"
    || registry.repository !== CORPUS_REPOSITORY || registry.ref !== CORPUS_REF
    || !Array.isArray(registry.events)) {
    errors.push(failure("REGISTRY_SCHEMA", "registry identity, version, or events are invalid"));
    return verdict(errors);
  }
  if (previousRegistry) validateAppendOnly(previousRegistry, registry, errors);
  const assignments = new Map();
  const reviewSeals = new Map();
  const truths = new Map();
  const sourceReleases = new Map();
  const consumedCorpora = new Set();
  const consumedCases = new Set();
  const executionKeys = new Set();
  const executionSeals = new Map();
  const judgeChallenges = new Map();
  const judgeSeals = new Set();
  const identities = new Map(IDENTITY_FIELDS.map((field) => [field, new Map()]));
  const truthIdentities = new Map(TRUTH_IDENTITY_FIELDS.map((field) => [field, new Map()]));
  const instrumentGroups = new Map();
  const familyGroups = new Map();
  const protectedProperties = [];
  let priorHash = ZERO;
  let priorTime = -Infinity;
  for (let index = 0; index < registry.events.length; index += 1) {
    const event = registry.events[index] || {};
    const at = `events[${index}]`;
    const time = Date.parse(event.issuedAt || "");
    if (event.schemaVersion !== 1 || event.sequence !== index + 1 || !CORPUS_EVENT_TYPES.has(event.eventType)
      || event.previousEventSha256 !== priorHash || event.eventSha256 !== corpusRegistryEventSha256(event)
      || !Number.isFinite(time) || time < priorTime) {
      errors.push(failure("REGISTRY_CHAIN_INVALID", `${at} breaks the canonical hash, sequence, type, or time chain`));
    }
    priorHash = event.eventSha256 || priorHash;
    priorTime = Number.isFinite(time) ? time : priorTime;
    if (event.eventType === "assign") {
      if (![...registry.events.slice(0, index)].some((prior) => prior.eventType === "legacy-quarantine")) {
        errors.push(failure("REGISTRY_QUARANTINE_MISSING", `${at} assigns a new case before the legacy touched-source quarantine was sealed`));
      }
      validateAssignment(event, at, { errors, assignments, identities, instrumentGroups, familyGroups });
    } else if (event.eventType === "review-seal") {
      validateReviewSeal(event, at, { errors, assignments, reviewSeals, protectedProperties });
    } else if (event.eventType === "truth-seal") {
      validateTruthSeal(event, at, { errors, assignments, reviewSeals, truths, truthIdentities });
    } else if (event.eventType === "source-release") {
      validateSourceRelease(event, at, { errors, assignments, sourceReleases });
    } else if (event.eventType === "consume") {
      validateConsume(event, at, { errors, assignments, truths, sourceReleases, consumedCorpora, consumedCases, executionKeys });
    } else if (event.eventType === "execution-seal") {
      validateExecutionSeal(event, at, { errors, registry, executionSeals });
    } else if (event.eventType === "judge-challenge") {
      validateJudgeChallenge(event, at, { errors, registry, executionSeals, judgeChallenges });
    } else if (event.eventType === "judge-seal") {
      validateJudgeSeal(event, at, { errors, registry, executionSeals, judgeChallenges, judgeSeals });
    } else {
      validateLegacyQuarantine(event, at, { errors, identities, truthIdentities });
    }
  }
  return {
    ...verdict(errors),
    rootSha256: corpusRegistryRootSha256(registry),
    eventCount: registry.events.length,
    assignments: assignments.size,
    reviewSeals: reviewSeals.size,
    truthSeals: truths.size,
    sourceReleases: sourceReleases.size,
    consumes: executionKeys.size,
    executionSeals: executionSeals.size,
    judgeChallenges: judgeChallenges.size,
    judgeSeals: judgeSeals.size,
  };
}

function validateReviewSeal(event, at, context) {
  const { errors, assignments, reviewSeals, protectedProperties } = context;
  const assignment = assignments.get(event.caseId);
  const payload = event.payload || {};
  const systems = payload.semanticSystems;
  const systemFields = new Set([
    "provider", "requestedModel", "catalogVersion", "returnedModel", "callId", "sessionIdSha256",
    "receiptSha256", "assessmentSha256",
  ]);
  const systemsValid = Array.isArray(systems) && systems.length === 2
    && systems.every((system) => system && typeof system === "object" && !Array.isArray(system)
      && Object.keys(system).length === systemFields.size && Object.keys(system).every((field) => systemFields.has(field))
      && typeof system.provider === "string" && system.provider.length > 0
      && typeof system.requestedModel === "string" && system.requestedModel.length > 0
      && typeof system.catalogVersion === "string" && system.catalogVersion.length > 0
      && typeof system.returnedModel === "string" && system.returnedModel.length > 0
      && typeof system.callId === "string" && system.callId.length > 0
      && ["sessionIdSha256", "receiptSha256", "assessmentSha256"].every((field) => SHA256.test(system[field] || "")))
    && new Set(systems.map((system) => system.provider)).size === 2
    && new Set(systems.map((system) => system.requestedModel)).size === 2
    && new Set(systems.map((system) => system.returnedModel)).size === 2
    && new Set(systems.map((system) => system.callId)).size === 2
    && new Set(systems.map((system) => system.sessionIdSha256)).size === 2;
  const aliases = payload.propertyAliases;
  const aliasesValid = validPropertyAliases(aliases);
  const commitmentsValid = validPropertyIdentifierCommitments(payload.propertyIdentifierCommitments);
  if (!assignment || reviewSeals.has(event.caseId) || event.corpusId !== assignment.corpusId
    || assignment.payload?.split !== "fail-safe" || payload.assignmentEventSha256 !== assignment.eventSha256
    || payload.sourceSha256 !== assignment.payload?.sourceSha256
    || payload.selectorSha256 !== assignment.payload?.selectorSha256
    || !SHA256.test(payload.expectedFailureCandidateSha256 || "")
    || !SHA256.test(payload.reviewRequestSha256 || "") || !SHA256.test(payload.reviewIndexSha256 || "")
    || !SHA256.test(payload.reviewEvidenceRootSha256 || "")
    || payload.reviewAttestationSubjectSha256 !== payload.reviewIndexSha256
    || !SHA256.test(payload.reviewAttestationBundleRootSha256 || "")
    || !/^[a-f0-9]{40}$/.test(payload.verifierPolicyTip || "")
    || payload.reviewerWorkflowRef
      !== "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/protected-refusal-reviewer.yml@refs/heads/main"
    || !/^[1-9][0-9]*$/.test(payload.reviewerWorkflowRunId || "")
    || !/^[1-9][0-9]*$/.test(payload.reviewerWorkflowRunAttempt || "")
    || !SHA256.test(payload.protectedChallengeSha256 || "") || !systemsValid
    || !SHA256.test(payload.propertyIdentityEvidenceSha256 || "") || !SHA256.test(payload.propertyAliasReceiptSha256 || "")
    || !aliasesValid || !commitmentsValid
    || payload.productCodeMounted !== false || payload.productOutputAvailable !== false
    || payload.geometryArtifactsExpected !== 0 || payload.status !== "approved"
    || payload.critical !== 0 || payload.major !== 0 || payload.sealedAt !== event.issuedAt
    || event.sequence <= assignment.sequence) {
    errors.push(failure("REGISTRY_REVIEW_SEAL_INVALID", `${at} is not a unique attested two-system refusal review over exact source and selector bindings`));
    return;
  }
  for (const prior of protectedProperties) {
    if (!propertyAliasOverlap(aliases, prior.payload.propertyAliases) || prior.caseId === event.caseId) continue;
    const conflicts = propertyCommitmentConflicts(payload.propertyIdentifierCommitments,
      prior.payload.propertyIdentifierCommitments);
    if (conflicts.length > 0) {
      errors.push(failure("REGISTRY_REVIEW_PROPERTY_CONFLICT",
        `${at} shares a property alias but conflicts on ${conflicts.join(",")}; protected adjudication is required`));
      return;
    }
    errors.push(failure("REGISTRY_REVIEW_SEAL_INVALID", `${at} replays an existing protected property alias`));
    return;
  }
  reviewSeals.set(event.caseId, event);
  protectedProperties.push(event);
}

function validPropertyAliases(value) {
  const kinds = new Set(["county-parcel", "county-subdivision-lot", "county-subdivision-block-lot",
    "county-subdivision-tract"]);
  return Array.isArray(value) && value.length > 0
    && value.every((alias) => alias && typeof alias === "object" && !Array.isArray(alias)
      && Object.keys(alias).length === 3 && kinds.has(alias.kind)
      && alias.strength === (alias.kind === "county-subdivision-lot" ? "weak" : "strong")
      && SHA256.test(alias.sha256 || ""))
    && new Set(value.map((alias) => alias.kind)).size === value.length
    && new Set(value.map((alias) => alias.sha256)).size === value.length
    && stableJson(value) === stableJson([...value].sort((a, b) => stableJson(a).localeCompare(stableJson(b))));
}

function validPropertyIdentifierCommitments(value) {
  const fields = new Set(["county", "subdivision", "lot", "block", "parcel", "tract"]);
  return Array.isArray(value) && value.length > 0
    && value.every((item) => item && typeof item === "object" && !Array.isArray(item)
      && Object.keys(item).length === 2 && fields.has(item.field) && SHA256.test(item.sha256 || ""))
    && new Set(value.map((item) => item.field)).size === value.length
    && stableJson(value) === stableJson([...value].sort((a, b) => a.field.localeCompare(b.field)));
}
function propertyAliasOverlap(left, right) { const hashes = new Set(left.map((alias) => alias.sha256));
  return right.some((alias) => hashes.has(alias.sha256)); }
function propertyCommitmentConflicts(left, right) { const prior = new Map(right.map((item) => [item.field, item.sha256]));
  return left.filter((item) => prior.has(item.field) && prior.get(item.field) !== item.sha256).map((item) => item.field).sort(); }

function validateAppendOnly(previous, current, errors) {
  const prior = validateCorpusRegistry({ registry: previous });
  if (!prior.ok || current.events.length < previous.events.length
    || stableJson(current.events.slice(0, previous.events.length)) !== stableJson(previous.events)) {
    errors.push(failure("REGISTRY_NOT_APPEND_ONLY", "registry history was deleted, reordered, rewritten, or truncated"));
  }
}

function validateAssignment(event, at, context) {
  const { errors, assignments, identities, instrumentGroups, familyGroups } = context;
  const payload = event.payload || {};
  if (!CASE_ID.test(event.caseId || "") || !CORPUS_ID.test(event.corpusId || "") || assignments.has(event.caseId)
    || !SPLITS.has(payload.split) || payload.split === "legacy-quarantine" || !FAMILY_ID.test(payload.sourceFamilyId || "")
    || !Number.isInteger(payload.sourceBytes) || payload.sourceBytes < 1
    || payload.assignmentStatus !== "sealed-untouched" || !["exclusive-custodian", "operator-attested"].includes(payload.custodyMode)
    || !SHA256.test(payload.encryptedSourceBundleRootSha256 || "") || !SHA256.test(payload.custodianIdentitySha256 || "")
    || (payload.split === "final" && payload.custodyMode !== "exclusive-custodian")
    || !SHA256.test(payload.instrumentIdHash || "")) {
    errors.push(failure("REGISTRY_ASSIGN_INVALID", `${at} is not a unique untouched split assignment`));
    return;
  }
  for (const field of IDENTITY_FIELDS) {
    if (!SHA256.test(payload[field] || "")) errors.push(failure("REGISTRY_ASSIGN_INVALID", `${at}.${field} is invalid`));
    bindIdentity(identities.get(field), payload[field], event, field, errors);
  }
  const instrument = instrumentGroups.get(payload.instrumentIdHash) || [];
  instrument.push(event);
  instrumentGroups.set(payload.instrumentIdHash, instrument);
  if (instrument.length > 2 || instrument.some((other) => other.corpusId !== event.corpusId || other.payload?.split !== payload.split)) {
    errors.push(failure("REGISTRY_INSTRUMENT_REUSE", `${at} splits an instrument across cohorts or exceeds two parcels`));
  }
  const family = familyGroups.get(payload.sourceFamilyId) || [];
  family.push(event);
  familyGroups.set(payload.sourceFamilyId, family);
  if (family.length > 5 || family.some((other) => other.corpusId !== event.corpusId || other.payload?.split !== payload.split)) {
    errors.push(failure("REGISTRY_FAMILY_REUSE", `${at} splits a source family across cohorts or exceeds five properties`));
  }
  assignments.set(event.caseId, event);
}

function validateSourceRelease(event, at, context) {
  const { errors, assignments, sourceReleases } = context;
  const assignment = assignments.get(event.caseId);
  const payload = event.payload || {};
  const cohortRelease = [...sourceReleases.values()].find((candidate) => candidate.corpusId === event.corpusId);
  if (!assignment || sourceReleases.has(event.caseId) || event.corpusId !== assignment.corpusId
    || assignment.payload?.split !== "final" || assignment.payload?.custodyMode !== "exclusive-custodian"
    || payload.assignmentEventSha256 !== assignment.eventSha256
    || payload.sourceSha256 !== assignment.payload?.sourceSha256
    || payload.encryptedSourceBundleRootSha256 !== assignment.payload?.encryptedSourceBundleRootSha256
    || payload.custodianIdentitySha256 !== assignment.payload?.custodianIdentitySha256
    || !/^[a-f0-9]{40}$/.test(payload.productCodeTip || "") || !validIso(payload.frozenAt)
    || payload.priorReleaseCount !== 0 || payload.releaseTarget !== "official-challenged-runner"
    || payload.releaseAuthority !== "protected-custodian-workflow" || !validIso(payload.releasedAt)
    || payload.releasedAt !== event.issuedAt || Date.parse(payload.releasedAt) < Date.parse(payload.frozenAt)
    || (cohortRelease && (payload.frozenAt !== cohortRelease.payload?.frozenAt
      || payload.productCodeTip !== cohortRelease.payload?.productCodeTip))
    || (!cohortRelease && payload.frozenAt !== event.issuedAt)
    || event.sequence <= assignment.sequence) {
    errors.push(failure("REGISTRY_SOURCE_RELEASE_INVALID", `${at} is not a zero-prior-release exclusive-custody handoff after product freeze`));
    return;
  }
  sourceReleases.set(event.caseId, event);
}

function validateTruthSeal(event, at, context) {
  const { errors, assignments, reviewSeals, truths, truthIdentities } = context;
  const assignment = assignments.get(event.caseId);
  const reviewSeal = reviewSeals.get(event.caseId);
  const payload = event.payload || {};
  if (!assignment || truths.has(event.caseId) || event.corpusId !== assignment.corpusId
    || payload.assignmentEventSha256 !== assignment.eventSha256 || !SHA256.test(payload.truthSha256 || "")
    || !SHA256.test(payload.evidenceSha256 || "") || !SHA256.test(payload.evidenceSelectorSha256 || "")
    || !SHA256.test(payload.truthReceiptRootSha256 || "") || !SHA256.test(payload.measurementReceiptSha256 || "")
    || payload.productOutputAvailable !== false || !validIso(payload.reviewSealedAt)
    || Date.parse(payload.reviewSealedAt) < Date.parse(assignment.issuedAt)
    || Date.parse(event.issuedAt) < Date.parse(payload.reviewSealedAt)
    || (assignment?.payload?.split === "fail-safe" && (!reviewSeal
      || payload.reviewSealEventSha256 !== reviewSeal.eventSha256
      || payload.expectedFailureCandidateSha256 !== reviewSeal.payload?.expectedFailureCandidateSha256
      || payload.reviewSealedAt !== reviewSeal.issuedAt || reviewSeal.sequence >= event.sequence))) {
    errors.push(failure("REGISTRY_TRUTH_SEAL_INVALID", `${at} is not a unique pre-product truth seal for its assignment`));
    return;
  }
  for (const field of TRUTH_IDENTITY_FIELDS) {
    if (!SHA256.test(payload[field] || "")) errors.push(failure("REGISTRY_TRUTH_SEAL_INVALID", `${at}.${field} is invalid`));
    bindIdentity(truthIdentities.get(field), payload[field], assignment, field, errors);
  }
  truths.set(event.caseId, event);
}

function validateConsume(event, at, context) {
  const { errors, assignments, truths, sourceReleases, consumedCorpora, consumedCases, executionKeys } = context;
  const payload = event.payload || {};
  const roots = payload.caseEventSha256s;
  const executionKey = `${event.corpusId}|${payload.campaign}`;
  if (!CORPUS_ID.test(event.corpusId || "") || executionKeys.has(executionKey)
    || typeof payload.campaign !== "string" || !payload.campaign || !SHA256.test(payload.manifestSha256 || "")
    || !SHA256.test(payload.intakeSealSha256 || "") || !/^[a-f0-9]{40}$/.test(payload.codeTip || "")
    || !EXECUTABLE_SPLITS.has(payload.split)
    || !Array.isArray(roots) || roots.length < 1 || new Set(roots).size !== roots.length
    || !SHA256.test(payload.oneUseNonce || "") || !validIso(payload.consumedAt)
    || payload.consumedAt !== event.issuedAt) {
    errors.push(failure("REGISTRY_CONSUME_INVALID", `${at} is not an exact unique registered campaign execution event`));
    return;
  }
  const assigned = [...assignments.values()].filter((item) => item.corpusId === event.corpusId && item.payload?.split === payload.split);
  const expected = assigned.map((item) => item.eventSha256).sort();
  const wrongCardinality = payload.split === "final" ? assigned.length !== 50 : assigned.length < 20;
  const previouslyConsumed = payload.split === "final"
    && (consumedCorpora.has(event.corpusId) || assigned.some((item) => consumedCases.has(item.caseId)));
  if (wrongCardinality || stableJson([...roots].sort()) !== stableJson(expected)
    || assigned.some((item) => !truths.has(item.caseId))
    || (payload.split === "final" && assigned.some((item) => {
      const release = sourceReleases.get(item.caseId);
      return !release || release.payload?.productCodeTip !== payload.codeTip || release.sequence >= event.sequence;
    })) || previouslyConsumed) {
    errors.push(failure("REGISTRY_CONSUME_INVALID", `${at} does not execute one complete truth-sealed ${payload.split} cohort`));
  }
  executionKeys.add(executionKey);
  if (payload.split === "final") {
    consumedCorpora.add(event.corpusId);
    for (const item of assigned) consumedCases.add(item.caseId);
  }
}

function validateExecutionSeal(event, at, context) {
  const { errors, registry, executionSeals } = context;
  const payload = event.payload || {};
  const consume = (registry?.events || []).find((candidate) => candidate.eventType === "consume"
    && candidate.eventSha256 === payload.consumeEventSha256);
  const key = `${event.corpusId}|${payload.campaign}`;
  const attestedCertification = ["final", "fail-safe"].includes(consume?.payload?.split);
  if (!consume || executionSeals.has(key) || event.caseId !== null
    || event.corpusId !== consume.corpusId || payload.campaign !== consume.payload?.campaign
    || payload.manifestSha256 !== consume.payload?.manifestSha256 || payload.codeTip !== consume.payload?.codeTip
    || !SHA256.test(payload.executionRootSha256 || "") || !SHA256.test(payload.executionIndexSha256 || "")
    || !Number.isInteger(payload.executionCount) || payload.executionCount < 1
    || (consume.payload?.split === "final" && payload.executionCount !== 150)
    || (attestedCertification && (payload.productCodeTip !== payload.codeTip
      || !/^[a-f0-9]{40}$/.test(payload.verifierPolicyTip || "")
      || !SHA256.test(payload.executionAttestationSubjectSha256 || "")
      || payload.executionAttestationSubjectSha256 !== payload.executionIndexSha256
      || !SHA256.test(payload.executionAttestationBundleRootSha256 || "")))
    || !validIso(payload.sealedAt) || payload.sealedAt !== event.issuedAt
    || event.sequence <= consume.sequence) {
    errors.push(failure("REGISTRY_EXECUTION_SEAL_INVALID", `${at} does not uniquely seal the challenged product executions before truth access`));
    return;
  }
  executionSeals.set(key, event);
}

function validateJudgeChallenge(event, at, context) {
  const { errors, registry, executionSeals, judgeChallenges } = context;
  const payload = event.payload || {};
  const execution = (registry?.events || []).find((candidate) => candidate.eventType === "execution-seal"
    && candidate.eventSha256 === payload.executionSealEventSha256);
  const key = `${event.corpusId}|${payload.campaign}|${payload.role}`;
  if (!execution || judgeChallenges.has(key) || event.caseId !== null || event.corpusId !== execution.corpusId
    || payload.campaign !== execution.payload?.campaign || !["numerical", "provenance", "visual"].includes(payload.role)
    || !SHA256.test(payload.evidenceRootSha256 || "") || !SHA256.test(payload.challengeNonce || "")
    || !validIso(payload.challengedAt) || payload.challengedAt !== event.issuedAt || event.sequence <= execution.sequence
    || !executionSeals.has(`${event.corpusId}|${payload.campaign}`)) {
    errors.push(failure("REGISTRY_JUDGE_CHALLENGE_INVALID", `${at} is not a fresh custodian-issued judge challenge over sealed evidence`));
    return;
  }
  judgeChallenges.set(key, event);
}

function validateJudgeSeal(event, at, context) {
  const { errors, registry, executionSeals, judgeChallenges, judgeSeals } = context;
  const payload = event.payload || {};
  const challenge = (registry?.events || []).find((candidate) => candidate.eventType === "judge-challenge"
    && candidate.eventSha256 === payload.judgeChallengeEventSha256);
  const execution = challenge && (registry?.events || []).find((candidate) => candidate.eventType === "execution-seal"
    && candidate.eventSha256 === challenge.payload?.executionSealEventSha256);
  const key = `${event.corpusId}|${payload.campaign}|${payload.role}`;
  if (!execution || judgeSeals.has(key) || event.caseId !== null || event.corpusId !== execution.corpusId
    || payload.campaign !== execution.payload?.campaign || !["numerical", "provenance", "visual"].includes(payload.role)
    || payload.role !== challenge?.payload?.role || payload.evidenceRootSha256 !== challenge?.payload?.evidenceRootSha256
    || payload.judgeChallengeSha256 !== judgeChallengeDigest(challenge)
    || !SHA256.test(payload.transcriptSha256 || "") || !SHA256.test(payload.responseSha256 || "")
    || !SHA256.test(payload.attachmentsRootSha256 || "") || !SHA256.test(payload.sessionIdSha256 || "")
    || !validIso(payload.sealedAt) || payload.sealedAt !== event.issuedAt || event.sequence <= execution.sequence
    || event.sequence <= challenge.sequence || !executionSeals.has(`${event.corpusId}|${payload.campaign}`)
    || !judgeChallenges.has(key)) {
    errors.push(failure("REGISTRY_JUDGE_SEAL_INVALID", `${at} does not bind one fresh judge to the sealed campaign evidence`));
    return;
  }
  judgeSeals.add(key);
}

function judgeChallengeDigest(event) {
  return sha256(stableJson({
    schemaVersion: 1,
    role: event?.payload?.role,
    evidenceRootSha256: event?.payload?.evidenceRootSha256,
    executionSealEventSha256: event?.payload?.executionSealEventSha256,
    judgeChallengeEventSha256: event?.eventSha256,
    challengeNonce: event?.payload?.challengeNonce,
    issuedAt: event?.issuedAt,
  }));
}

function validateLegacyQuarantine(event, at, context) {
  const { errors, identities, truthIdentities } = context;
  if (event.caseId !== null || event.corpusId !== null || !Array.isArray(event.payload?.records) || event.payload.records.length < 1) {
    errors.push(failure("REGISTRY_QUARANTINE_INVALID", `${at} must contain the legacy touched identity import`));
    return;
  }
  for (const record of event.payload.records) {
    const pseudo = { caseId: record.caseId || `legacy-${String(record.sourceSha256 || "").slice(0, 12)}`, corpusId: "legacy", payload: { split: "legacy-quarantine" } };
    for (const field of IDENTITY_FIELDS) if (record[field]) bindIdentity(identities.get(field), record[field], pseudo, field, errors);
    for (const field of TRUTH_IDENTITY_FIELDS) if (record[field]) bindIdentity(truthIdentities.get(field), record[field], pseudo, field, errors);
  }
}

function bindIdentity(map, value, event, field, errors) {
  if (!SHA256.test(value || "")) return;
  const prior = map.get(value);
  if (prior && prior.caseId !== event.caseId) {
    errors.push(failure("REGISTRY_CROSS_CORPUS_REUSE", `${field} is reused by ${prior.caseId} and ${event.caseId}`));
  } else map.set(value, event);
}

function validIso(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
}
function failure(code, message) { return { code, message }; }
function verdict(errors) { return { schemaVersion: 1, ok: errors.length === 0, errorCount: errors.length, errors }; }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
