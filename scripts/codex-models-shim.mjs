#!/usr/bin/env node

import { basename, dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { sha256, validateModelReceipt } from "./model-receipt.mjs";

const ownDirectory = dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(readFileSync(resolve(ownDirectory, ".spaceport-model-broker.json"), "utf8"));
const parsed = parseCodexArgs(process.argv.slice(2));
const cwd = resolve(process.cwd());
const schemaPath = confined(parsed.schemaPath, cwd);
const responsePath = confined(parsed.responsePath, cwd);
const images = parsed.images.map((path) => {
  const absolute = confined(path, cwd);
  const content = readFileSync(absolute);
  return { name: basename(absolute), mediaType: "image/png", bytes: content.length, sha256: sha256(content), contentBase64: content.toString("base64") };
});
const prompt = readFileSync(0, "utf8");
writeFileSync(`${responsePath}.prompt.txt`, prompt, { flag: "wx", mode: 0o600 });
const response = await fetch(config.endpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${config.bearer}`, "Content-Type": "application/json" },
  body: JSON.stringify({ schemaVersion: 1, prompt, schema: JSON.parse(readFileSync(schemaPath, "utf8")), images }),
  signal: AbortSignal.timeout(11 * 60 * 1000),
});
const body = await response.json();
if (!response.ok || typeof body.output !== "string") throw new Error(`Trusted model broker failed: ${body.error || response.status}`);
JSON.parse(body.output);
validateModelReceipt(body.receipt, { output: body.output, prompt, schema: JSON.parse(readFileSync(schemaPath, "utf8")), images,
  model: config.model, modelVersion: config.modelVersion });
writeFileSync(responsePath, body.output, { flag: "wx", mode: 0o600 });
writeFileSync(`${responsePath}.model-receipt.json`, `${JSON.stringify(body.receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });

function parseCodexArgs(args) {
  if (args[0] !== "exec") throw new Error("The evaluator codex shim supports only noninteractive exec.");
  let schemaPath; let responsePath; const images = [];
  for (let index = 1; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--output-schema") schemaPath = args[++index];
    else if (token === "--output-last-message") responsePath = args[++index];
    else if (token === "--image") images.push(args[++index]);
    else if (["--sandbox"].includes(token)) index += 1;
    else if (!["--ephemeral", "--ignore-rules", "--skip-git-repo-check"].includes(token)) throw new Error(`Unsupported codex shim argument: ${token}`);
  }
  if (!schemaPath || !responsePath || images.length < 1 || images.length > 6) throw new Error("Codex shim invocation is incomplete.");
  return { schemaPath, responsePath, images };
}

function confined(path, root) {
  const absolute = resolve(path);
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) throw new Error("Codex shim path escaped the product output directory.");
  return absolute;
}
