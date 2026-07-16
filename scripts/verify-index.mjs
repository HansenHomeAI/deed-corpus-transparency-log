#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { indexSha256, validateCanonicalIndexBytes, validatePublicIndex } from "./registry-core.mjs";

const indexPath = argument("--index");
const ciphertextDirectory = argument("--ciphertext-dir");
const indexBytes = readFileSync(indexPath);
const index = JSON.parse(indexBytes.toString("utf8"));
validateCanonicalIndexBytes(indexBytes, index);
validatePublicIndex(index, { ciphertextDirectory });
process.stdout.write(`${JSON.stringify({ ok: true, envelopeCount: index.envelopes.length, indexSha256: indexSha256(index) }, null, 2)}\n`);

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: verify-index ${name} <value>`);
  return process.argv[index + 1];
}
