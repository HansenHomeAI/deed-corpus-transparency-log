#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { decodeAesKey, decryptState } from "./registry-core.mjs";

const input = argument("--input");
const output = optionalArgument("--output");
const state = decryptState(readFileSync(input), decodeAesKey(process.env.REGISTRY_AES_KEY_BASE64));
const json = `${JSON.stringify(state, null, 2)}\n`;
if (output) writeFileSync(output, json, { mode: 0o600 });
else process.stdout.write(json);

function argument(name) {
  const value = optionalArgument(name);
  if (!value) throw new Error(`usage: decrypt-state ${name} <value>`);
  return value;
}
function optionalArgument(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}
