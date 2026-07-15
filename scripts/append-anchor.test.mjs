import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = new URL("./append-anchor.mjs", import.meta.url).pathname;
const initial = JSON.parse(readFileSync(new URL("../anchors.json", import.meta.url), "utf8"));
const ZERO = "0".repeat(64);
const KINDS = [
  "legacy-quarantine",
  "assign",
  "truth-seal",
  "source-release",
  "consume",
  "execution-seal",
  "judge-challenge",
  "judge-seal",
];

test("every protected campaign event kind appends to one connected monotonic chain", () => {
  const directory = mkdtempSync(join(tmpdir(), "deed-anchor-"));
  const file = join(directory, "anchors.json");
  writeFileSync(file, `${JSON.stringify(initial, null, 2)}\n`);

  for (const [index, kind] of KINDS.entries()) {
    const before = JSON.parse(readFileSync(file, "utf8"));
    const last = before.events.at(-1);
    const request = {
      schemaVersion: 1,
      kind,
      expectedAnchorRootSha256: sha256(stableJson(before)),
      previousPrivateRegistryRootSha256: last?.privateRegistryRootSha256 || ZERO,
      privateRegistryRootSha256: sha256(`private-root-${index}`),
      privateRegistryEventCount: (last?.privateRegistryEventCount || 0) + 1,
      requestNonce: sha256(`nonce-${index}`),
    };
    const result = spawnSync(process.execPath, [script, "--file", file, "--request-base64url", Buffer.from(JSON.stringify(request)).toString("base64url")], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).event.kind, kind);
  }
});

test("unknown event kinds and stale public roots are refused without mutation", () => {
  const directory = mkdtempSync(join(tmpdir(), "deed-anchor-"));
  const file = join(directory, "anchors.json");
  const original = `${JSON.stringify(initial, null, 2)}\n`;
  writeFileSync(file, original);
  const last = initial.events.at(-1);
  const request = {
    schemaVersion: 1,
    kind: "invented-event",
    expectedAnchorRootSha256: ZERO,
    previousPrivateRegistryRootSha256: last?.privateRegistryRootSha256 || ZERO,
    privateRegistryRootSha256: sha256("different"),
    privateRegistryEventCount: (last?.privateRegistryEventCount || 0) + 1,
    requestNonce: sha256("nonce"),
  };
  const result = spawnSync(process.execPath, [script, "--file", file, "--request-base64url", Buffer.from(JSON.stringify(request)).toString("base64url")], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.equal(readFileSync(file, "utf8"), original);
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
