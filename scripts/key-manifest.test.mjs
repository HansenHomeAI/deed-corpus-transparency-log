import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

import { sha256 } from "./registry-core.mjs";

const repository = resolve(import.meta.dirname, "..");

test("committed key manifest binds only reviewed 3072-bit public keys", () => {
  const manifest = JSON.parse(readFileSync(join(repository, "keys/manifest.json"), "utf8"));
  assert.equal(manifest.schemaVersion, 1);
  assert.deepEqual(readdirSync(join(repository, "keys")).sort(), [
    "deed-evaluator-bundle-public.pem",
    "deed-registry-request-public.pem",
    "manifest.json",
  ]);
  for (const record of [manifest.registryRequest, manifest.evaluatorBundle]) {
    const bytes = readFileSync(join(repository, record.publicKeyPath));
    const key = createPublicKey(bytes);
    assert.equal(key.asymmetricKeyType, "rsa");
    assert.equal(key.asymmetricKeyDetails.modulusLength, 3072);
    assert.equal(sha256(bytes), record.publicKeySha256);
    assert.match(record.keyId, new RegExp(record.publicKeySha256.slice(0, 8) + "$"));
    assert.doesNotMatch(bytes.toString("utf8"), /PRIVATE KEY/);
  }
  assert.equal(manifest.registryRequest.algorithm, "RSA-OAEP-256+A256GCM");
  assert.equal(manifest.evaluatorBundle.algorithm, "RSA-OAEP-256+A256GCM");
  assert.equal(manifest.registryState.algorithm, "AES-256-GCM");
  assert.match(manifest.registryState.keyId, /^deed-registry-state-[0-9]{8}-v[1-9][0-9]*$/);
});
