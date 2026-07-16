import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

const repository = resolve(import.meta.dirname, "..");
const workflow = readFileSync(join(repository, ".github/workflows/hosted-model-smoke.yml"), "utf8");

test("hosted model smoke is protected, credential-isolated, maximum-cardinality, attested, and synthetic-only", () => {
  assert.match(workflow, /runs-on: macos-15/);
  assert.match(workflow, /environment: deed-corpus-evaluator/);
  assert.match(workflow, /test "\$GITHUB_REF" = refs\/heads\/main/);
  assert.match(workflow, /models: read/);
  assert.doesNotMatch(workflow, /contents: write|DEED_PRODUCT|DEED_REGISTRY/);
  assert.match(workflow, /unset MODEL_TOKEN GITHUB_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL/);
  assert.match(workflow, /for index in range\(80\)/);
  assert.match(workflow, /--model openai\/gpt-4\.1 --model-version 2025-04-14/);
  assert.match(workflow, /actions\/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4\.1\.1/);
  assert.match(workflow, /--deny-self-hosted-runners --bundle/);
  assert.match(workflow, /retention-days: 30/);
  assert.match(workflow, /rm -rf "\$root"/);
});
