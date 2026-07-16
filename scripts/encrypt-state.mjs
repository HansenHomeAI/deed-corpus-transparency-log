#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { decodeAesKey, encryptState, validatePlaintextRegistry } from "./registry-core.mjs";

const input = argument("--input");
const output = argument("--output");
const key = decodeAesKey(process.env.REGISTRY_AES_KEY_BASE64);
const state = validatePlaintextRegistry(JSON.parse(readFileSync(input, "utf8")));
writeFileSync(output, encryptState(state, key), { mode: 0o600 });
process.stdout.write(`${JSON.stringify({ ok: true, output })}\n`);

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: encrypt-state ${name} <value>`);
  return process.argv[index + 1];
}
