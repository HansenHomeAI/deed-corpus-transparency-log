#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { decryptRequest } from "./registry-core.mjs";

const intent = decryptRequest(argument("--request-base64url"),
  readFileSync(argument("--request-private-key"), "utf8"), argument("--request-key-id"));
const event = intent?.eventData;
let result = { required: false };
if (event?.eventType === "review-seal") {
  const fields = ["reviewRequestId", "reviewerWorkflowRunId", "reviewerWorkflowRunAttempt", "verifierPolicyTip"];
  if (!event.payload || Object.keys(event.payload).length !== fields.length
    || fields.some((field) => !Object.hasOwn(event.payload, field))
    || !/^dp-[a-f0-9]{12}$/.test(event.caseId || "") || !/^corpus-[a-f0-9]{16}$/.test(event.corpusId || "")
    || !/^[a-f0-9]{64}$/.test(event.payload.reviewRequestId || "")
    || !/^[1-9][0-9]*$/.test(event.payload.reviewerWorkflowRunId || "")
    || !/^[1-9][0-9]*$/.test(event.payload.reviewerWorkflowRunAttempt || "")
    || !/^[a-f0-9]{40}$/.test(event.payload.verifierPolicyTip || "")) {
    throw new Error("Review-seal callers may supply only one exact protected workflow reference.");
  }
  result = { required: true, eventType: "review-seal", caseId: event.caseId, corpusId: event.corpusId,
    ...event.payload };
}
writeFileSync(argument("--out"), `${JSON.stringify(result, null, 2)}\n`, { flag: "wx", mode: 0o600 });

function argument(name) { const index = process.argv.indexOf(name); if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`); return process.argv[index + 1]; }
