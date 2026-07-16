#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { decryptRequest } from "./registry-core.mjs";

const request = argument("--request-base64url");
const privateKey = argument("--private-key");
const keyId = argument("--key-id");
const intent = decryptRequest(request, readFileSync(privateKey, "utf8"), keyId);
process.stdout.write(`${JSON.stringify(intent, null, 2)}\n`);

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`usage: decrypt-request ${name} <value>`);
  return process.argv[index + 1];
}
