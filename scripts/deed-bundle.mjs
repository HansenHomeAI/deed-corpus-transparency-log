#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  createFileSet,
  decryptBundle,
  encryptBundle,
  materializeFileSet,
  sha256,
} from "./official-evaluator-core.mjs";

const command = process.argv[2];
if (command === "pack") {
  const role = argument("--role");
  const requestId = argument("--request-id");
  const root = resolve(argument("--root"));
  const paths = JSON.parse(readFileSync(argument("--paths-json"), "utf8")).map((path) => resolve(root, path));
  const fileSet = createFileSet({ role, requestId, root, paths });
  const bytes = encryptBundle(fileSet, readFileSync(argument("--public-key"), "utf8"), argument("--key-id"));
  const output = argument("--out");
  writeFileSync(output, bytes, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, role, requestId, files: fileSet.files.length,
    fileRootSha256: fileSet.fileRootSha256, bundleSha256: sha256(bytes), output })}\n`);
} else if (command === "unpack") {
  const bytes = readFileSync(argument("--bundle"));
  const requestId = argument("--request-id");
  const role = argument("--role");
  const fileSet = decryptBundle(bytes, readFileSync(argument("--private-key"), "utf8"), argument("--key-id"), {
    expectedRole: role, expectedRequestId: requestId,
  });
  const result = materializeFileSet(fileSet, argument("--out"), { expectedRole: role, expectedRequestId: requestId });
  const receipt = { schemaVersion: 1, kind: "spaceport-deed-evaluator-materialized-file-set", role, requestId,
    fileRootSha256: fileSet.fileRootSha256,
    files: fileSet.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })) };
  writeFileSync(join(resolve(argument("--out")), `.${role}-fileset-receipt.json`), `${JSON.stringify(receipt, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, role, requestId, bundleSha256: sha256(bytes), ...result })}\n`);
} else {
  throw new Error("usage: deed-bundle pack|unpack ...");
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}
