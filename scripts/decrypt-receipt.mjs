#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { decryptProtectedAppendReceipt, sha256, stableJson } from "./registry-core.mjs";

const input = argument("--input");
const bundlePath = argument("--attestation-bundle");
const privateKeyPath = argument("--private-key");
const keyId = argument("--key-id");
const expectedRequestSha256 = argument("--expected-request-sha256");
const expectedCiphertextSha256 = argument("--expected-ciphertext-sha256");
const expectedSignerDigest = argument("--expected-signer-digest");
const output = argument("--output");
if (!/^[a-f0-9]{40}$/.test(expectedSignerDigest)) throw new Error("Expected append-workflow signer digest must be 40 lowercase hex characters.");

const bytes = readFileSync(input);
verifyAttestation(bytes, input, bundlePath, expectedSignerDigest);
const receipt = decryptProtectedAppendReceipt(bytes, readFileSync(privateKeyPath, "utf8"), keyId,
  { expectedRequestSha256, expectedCiphertextSha256, expectedSignerDigest });
writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });
process.stdout.write(`${JSON.stringify({ ok: true, output, requestSha256: receipt.requestSha256 })}\n`);

function verifyAttestation(bytes, artifactPath, retainedBundlePath, signerDigest) {
  const result = spawnSync("gh", ["attestation", "verify", artifactPath,
    "--repo", "HansenHomeAI/deed-corpus-transparency-log",
    "--signer-workflow", "HansenHomeAI/deed-corpus-transparency-log/.github/workflows/append-encrypted-registry.yml",
    "--signer-digest", signerDigest,
    "--source-ref", "refs/heads/main",
    "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
    "--deny-self-hosted-runners", "--bundle", retainedBundlePath, "--format", "json"],
  { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) throw new Error("Encrypted receipt Sigstore verification failed.");
  const response = JSON.parse(result.stdout);
  const verified = response?.[0];
  const certificate = verified?.verificationResult?.signature?.certificate || {};
  const statement = verified?.verificationResult?.statement || {};
  const retainedBundle = JSON.parse(readFileSync(retainedBundlePath, "utf8"));
  const verifiedBundle = verified?.attestation?.bundle || {};
  const retainedCanonicalBytes = Buffer.from(stableJson(retainedBundle), "utf8");
  const verifiedCanonicalBytes = Buffer.from(stableJson(verifiedBundle), "utf8");
  const retainedBundleRootSha256 = sha256(retainedCanonicalBytes);
  const verifiedBundleRootSha256 = sha256(verifiedCanonicalBytes);
  const subjects = statement.subject || [];
  const tlogEntries = verifiedBundle?.verificationMaterial?.tlogEntries || [];
  const tlog = tlogEntries[0] || {};
  if (!Array.isArray(response) || response.length !== 1
    || certificate.issuer !== "https://token.actions.githubusercontent.com"
    || certificate.githubWorkflowRepository !== "HansenHomeAI/deed-corpus-transparency-log"
    || certificate.githubWorkflowRef !== "refs/heads/main" || certificate.runnerEnvironment !== "github-hosted"
    || certificate.buildSignerDigest !== signerDigest
    || !retainedCanonicalBytes.equals(verifiedCanonicalBytes)
    || retainedBundleRootSha256 !== verifiedBundleRootSha256
    || !Array.isArray(subjects) || subjects.length !== 1 || subjects[0]?.digest?.sha256 !== sha256(bytes)
    || !Array.isArray(tlogEntries) || tlogEntries.length !== 1
    || !Number.isSafeInteger(Number(tlog.logIndex)) || !Number.isSafeInteger(Number(tlog.integratedTime))
    || !Array.isArray(verified?.verificationResult?.verifiedTimestamps)
    || verified.verificationResult.verifiedTimestamps.length < 1) {
    throw new Error("Encrypted receipt attestation violates signer, subject, hosted-runner, Fulcio, or Rekor policy.");
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: decrypt-receipt ${name} <value>`);
  return process.argv[index + 1];
}
