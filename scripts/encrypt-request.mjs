#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { encryptRequest } from "./registry-core.mjs";

const input = argument("--input");
const publicKey = argument("--public-key");
const keyId = argument("--key-id");
const intent = JSON.parse(readFileSync(input, "utf8"));
process.stdout.write(`${encryptRequest(intent, readFileSync(publicKey, "utf8"), keyId)}\n`);

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: encrypt-request ${name} <value>`);
  return process.argv[index + 1];
}
