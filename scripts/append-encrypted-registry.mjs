#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  appendPlaintextEvent,
  buildProtectedAppendRejectionReceipt,
  buildProtectedAppendReceipt,
  CorpusRegistrySemanticError,
  ciphertextPath,
  decodeAesKey,
  decryptRequest,
  decryptState,
  encryptState,
  envelopeSha256,
  indexSha256,
  sha256,
  STATE_ALGORITHM,
  validateAppendIntent,
  validateCanonicalIndexBytes,
  validatePublicIndex,
} from "./registry-core.mjs";

const indexPath = argument("--index");
const ciphertextDirectory = argument("--ciphertext-dir");
const requestPrivateKeyPath = argument("--request-private-key");
const requestBase64url = argument("--request-base64url");
const requestKeyId = argument("--request-key-id");
const stateKeyId = argument("--state-key-id");
const workflowRunId = argument("--workflow-run-id");
const workflowRunAttempt = argument("--workflow-run-attempt");
const workflowRef = argument("--workflow-ref");
const workflowTip = argument("--workflow-tip");
const receiptDirectory = argument("--receipt-dir");
const derivedReviewEventPath = optionalArgument("--derived-review-event");
const key = decodeAesKey(process.env.REGISTRY_AES_KEY_BASE64);

const indexBytes = readFileSync(indexPath);
const index = JSON.parse(indexBytes.toString("utf8"));
validateCanonicalIndexBytes(indexBytes, index);
validatePublicIndex(index, { ciphertextDirectory });
const beforeIndexSha256 = indexSha256(index);
const intent = decryptRequest(requestBase64url, readFileSync(requestPrivateKeyPath, "utf8"), requestKeyId);

if (index.envelopes.length === 0) {
  throw new Error("Encrypted genesis is missing; run the one-time protected migration before any append.");
}
const state = decryptState(readFileSync(ciphertextPath(ciphertextDirectory, index.envelopes.length)), key);
validateAppendIntent(intent, beforeIndexSha256, state);

const authority = {
  schemaVersion: 1,
  provider: "github-actions",
  repository: "HansenHomeAI/deed-corpus-transparency-log",
  workflow: ".github/workflows/append-encrypted-registry.yml",
  workflowRunId,
  workflowRunAttempt,
  workflowRef,
  workflowTip,
};
const derivedReviewEvent = derivedReviewEventPath ? JSON.parse(readFileSync(derivedReviewEventPath, "utf8")) : null;
let event;
try {
  event = appendPlaintextEvent(state, intent, authority, new Date(), undefined, { derivedReviewEvent });
} catch (error) {
  if (!(error instanceof CorpusRegistrySemanticError)) throw error;
  const currentEnvelope = index.envelopes.at(-1);
  const protectedReceipt = buildProtectedAppendRejectionReceipt({
    intent,
    state,
    authority,
    errors: error.errors,
    rejectedAt: new Date().toISOString(),
    publicCommitment: {
      sequence: currentEnvelope.sequence,
      publicIndexSha256: beforeIndexSha256,
      envelopeSha256: currentEnvelope.envelopeSha256,
      ciphertextSha256: currentEnvelope.ciphertextSha256,
    },
  });
  const artifactName = `deed-registry-receipt-${protectedReceipt.requestSha256}`;
  const metadata = {
    schemaVersion: 1,
    outcome: "rejected",
    artifactName,
    requestSha256: protectedReceipt.requestSha256,
    encryptedReceiptSha256: protectedReceipt.encryptedReceiptSha256,
    publicIndexSha256: beforeIndexSha256,
    ciphertextSha256: currentEnvelope.ciphertextSha256,
    workflowRunId,
    workflowRunAttempt,
  };
  mkdirSync(receiptDirectory, { recursive: true, mode: 0o700 });
  writeFileSync(`${receiptDirectory}/receipt.encrypted.json`, protectedReceipt.bytes, { flag: "wx", mode: 0o600 });
  writeFileSync(`${receiptDirectory}/receipt-metadata.json`, `${JSON.stringify(metadata, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  await writeStdout(`${JSON.stringify({
    ok: false,
    appended: false,
    sequence: currentEnvelope.sequence,
    indexSha256: beforeIndexSha256,
    ciphertextSha256: currentEnvelope.ciphertextSha256,
    envelopeSha256: currentEnvelope.envelopeSha256,
    requestSha256: protectedReceipt.requestSha256,
    encryptedReceiptSha256: protectedReceipt.encryptedReceiptSha256,
    artifactName,
  }, null, 2)}\n`);
  process.exit(0);
}
const ciphertext = encryptState(state, key);
const sequence = index.envelopes.length + 1;
const issuedAt = event.issuedAt;
const envelope = {
  sequence,
  previousEnvelopeSha256: index.envelopes.at(-1)?.envelopeSha256 || "0".repeat(64),
  ciphertextSha256: sha256(ciphertext),
  ciphertextBytes: ciphertext.length,
  algorithm: STATE_ALGORITHM,
  keyId: stateKeyId,
  issuedAt,
  workflowRunId,
};
envelope.envelopeSha256 = envelopeSha256(envelope);
index.envelopes.push(envelope);

const protectedReceipt = buildProtectedAppendReceipt({
  intent,
  event,
  state,
  authority,
  publicCommitment: {
    sequence,
    publicIndexSha256: indexSha256(index),
    envelopeSha256: envelope.envelopeSha256,
    ciphertextSha256: envelope.ciphertextSha256,
  },
});
const artifactName = `deed-registry-receipt-${protectedReceipt.requestSha256}`;
const metadata = {
  schemaVersion: 1,
  outcome: "appended",
  artifactName,
  requestSha256: protectedReceipt.requestSha256,
  encryptedReceiptSha256: protectedReceipt.encryptedReceiptSha256,
  publicIndexSha256: indexSha256(index),
  ciphertextSha256: envelope.ciphertextSha256,
  workflowRunId,
  workflowRunAttempt,
};

mkdirSync(ciphertextDirectory, { recursive: true });
mkdirSync(receiptDirectory, { recursive: true, mode: 0o700 });
const outputPath = ciphertextPath(ciphertextDirectory, sequence);
writeFileSync(outputPath, ciphertext, { flag: "wx", mode: 0o600 });
writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
writeFileSync(`${receiptDirectory}/receipt.encrypted.json`, protectedReceipt.bytes, { flag: "wx", mode: 0o600 });
writeFileSync(`${receiptDirectory}/receipt-metadata.json`, `${JSON.stringify(metadata, null, 2)}\n`, { flag: "wx", mode: 0o600 });
validatePublicIndex(index, { ciphertextDirectory });

process.stdout.write(`${JSON.stringify({
  ok: true,
  appended: true,
  sequence,
  indexSha256: indexSha256(index),
  ciphertextPath: outputPath,
  ciphertextSha256: envelope.ciphertextSha256,
  envelopeSha256: envelope.envelopeSha256,
  requestSha256: protectedReceipt.requestSha256,
  encryptedReceiptSha256: protectedReceipt.encryptedReceiptSha256,
  artifactName,
}, null, 2)}\n`);

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: append-encrypted-registry ${name} <value>`);
  return process.argv[index + 1];
}
function optionalArgument(name) { const index = process.argv.indexOf(name); return index < 0 ? null : process.argv[index + 1]; }
function writeStdout(value) {
  return new Promise((resolve, reject) => process.stdout.write(value, (error) => error ? reject(error) : resolve()));
}
