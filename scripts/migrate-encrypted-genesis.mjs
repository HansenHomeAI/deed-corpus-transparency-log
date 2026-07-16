#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  ciphertextPath,
  createGenesisState,
  decodeAesKey,
  encryptState,
  envelopeSha256,
  indexSha256,
  sha256,
  STATE_ALGORITHM,
  validateCanonicalIndexBytes,
  validatePublicIndex,
} from "./registry-core.mjs";

const indexPath = argument("--index");
const ciphertextDirectory = argument("--ciphertext-dir");
const privateRegistryPath = argument("--private-registry");
const legacyPath = argument("--legacy-file");
const stateKeyId = argument("--state-key-id");
const workflowRunId = argument("--workflow-run-id");
const workflowRunAttempt = argument("--workflow-run-attempt");

const indexBytes = readFileSync(indexPath);
const index = JSON.parse(indexBytes.toString("utf8"));
validateCanonicalIndexBytes(indexBytes, index);
validatePublicIndex(index, { ciphertextDirectory });
if (index.envelopes.length !== 0) throw new Error("Encrypted genesis already exists and cannot be replaced.");

const migrationAuthority = {
  schemaVersion: 1,
  provider: "github-actions",
  repository: "HansenHomeAI/deed-corpus-transparency-log",
  workflow: ".github/workflows/migrate-encrypted-genesis.yml",
  workflowRunId,
  workflowRunAttempt,
};
const privateRegistry = JSON.parse(readFileSync(privateRegistryPath, "utf8"));
const legacyLog = JSON.parse(readFileSync(legacyPath, "utf8"));
const state = createGenesisState(privateRegistry, legacyLog, migrationAuthority);
const ciphertext = encryptState(state, decodeAesKey(process.env.REGISTRY_AES_KEY_BASE64));
const envelope = {
  sequence: 1,
  previousEnvelopeSha256: "0".repeat(64),
  ciphertextSha256: sha256(ciphertext),
  ciphertextBytes: ciphertext.length,
  algorithm: STATE_ALGORITHM,
  keyId: stateKeyId,
  issuedAt: state.genesis.migratedAt,
  workflowRunId,
};
envelope.envelopeSha256 = envelopeSha256(envelope);
index.envelopes.push(envelope);
mkdirSync(ciphertextDirectory, { recursive: true });
const outputPath = ciphertextPath(ciphertextDirectory, 1);
writeFileSync(outputPath, ciphertext, { flag: "wx", mode: 0o600 });
writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
validatePublicIndex(index, { ciphertextDirectory });
process.stdout.write(`${JSON.stringify({
  ok: true,
  sequence: 1,
  indexSha256: indexSha256(index),
  ciphertextPath: outputPath,
  ciphertextSha256: envelope.ciphertextSha256,
  envelopeSha256: envelope.envelopeSha256,
}, null, 2)}\n`);

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: migrate-encrypted-genesis ${name} <value>`);
  return process.argv[index + 1];
}
