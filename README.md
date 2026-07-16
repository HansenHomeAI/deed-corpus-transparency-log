# Encrypted deed-corpus custody registry

This protected public repository provides an append-only chronology for the
private Spaceport deed-plotting corpus without publishing event kinds, case or
parcel identifiers, source hashes, truth roots, private registry roots, or
caller-chosen chronology values.

`registry/index.json` is the only active public index. Each entry reveals only:

- sequence and previous-envelope hash;
- ciphertext SHA-256 and byte length;
- `AES-256-GCM` plus a non-secret key id;
- workflow-issued time and GitHub workflow run id; and
- the envelope hash.

The corresponding immutable bytes live at the sequence-derived path
`registry/ciphertexts/NNNNNN.bin`. They are authenticated encrypted snapshots
of the complete plaintext registry. The plaintext retains the original event
kinds and the canonical detailed corpus registry: assignment uniqueness,
source/property/title/description/geometry identity exclusion, instrument and
family caps, truth seals, exclusive zero-prior-release custody, one-time
consumption, execution seals, and judge challenge/seal chronology. Every new
event is bound to a workflow-generated timestamp and GitHub Actions authority;
consume and judge-challenge nonces are also workflow-generated. Plaintext is
never written to the repository or workflow logs.

`anchors.json` is the frozen v1 public log. It remains for historical
verification and is imported into the first encrypted snapshot, but no
workflow can append to it. Historical Git data cannot be made secret; v2
prevents all future event semantics and roots from entering the public index.
The encrypted genesis also contains the complete preexisting private registry,
and migration succeeds only when its canonical root and event count exactly
match the last frozen public anchor.

## Security and failure model

The append workflow serializes all runs, checks every retained ciphertext and
public chain link before and after mutation, decrypts the latest state, runs
the full detailed corpus state machine before and after append, rejects stale
or semantically invalid intents, and then creates protected nonce, time, and
authority values itself. A request is a hybrid envelope: a
random AES-256-GCM request key is wrapped with RSA-OAEP-SHA256. The workflow
decrypts requests using a repository secret and re-encrypts state using a
separate repository secret.

The protected `main` branch must reject force pushes and deletion, require this
workflow/check policy, and permit only the workflow identity to append. GitHub
Actions attests the exact `registry/index.json` and every retained ciphertext.
The chain detects stale requests, reordering, missing bytes, ciphertext edits,
wrong keys, and authenticated-decryption failures. As with every append-only
log, tail truncation requires comparison with a previously trusted attestation
or protected Git history; an internally self-contained prefix cannot prove a
newer suffix once existed.

## One-time custodian setup

Generate real keys only in an approved secret-management environment. These
commands are examples; never commit either private key or the AES key.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out deed-request-private.pem
openssl pkey -in deed-request-private.pem -pubout -out deed-request-public.pem
openssl pkey -pubin -in deed-request-public.pem -outform DER | openssl dgst -sha256
umask 077
openssl rand -base64 32 | tr -d '\n' > deed-state-aes.b64

gh api --method PUT \
  repos/HansenHomeAI/deed-corpus-transparency-log/environments/deed-corpus-registry
gh secret set DEED_REGISTRY_REQUEST_PRIVATE_KEY_PEM --env deed-corpus-registry \
  --repo HansenHomeAI/deed-corpus-transparency-log < deed-request-private.pem
gh secret set DEED_REGISTRY_AES_KEY_BASE64 --env deed-corpus-registry \
  --repo HansenHomeAI/deed-corpus-transparency-log < deed-state-aes.b64
gh secret set DEED_REGISTRY_SOURCE_TOKEN --env deed-corpus-registry \
  --repo HansenHomeAI/deed-corpus-transparency-log
gh variable set DEED_REGISTRY_REQUEST_KEY_ID --env deed-corpus-registry \
  --repo HansenHomeAI/deed-corpus-transparency-log --body request-key-2026-07
gh variable set DEED_REGISTRY_STATE_KEY_ID --env deed-corpus-registry \
  --repo HansenHomeAI/deed-corpus-transparency-log --body custody-state-2026-07

gh api repos/HansenHomeAI/deed-corpus-transparency-log/branches/main/protection
```

Configure repository settings:

- secret `DEED_REGISTRY_REQUEST_PRIVATE_KEY_PEM`: contents of the RSA private
  key;
- secret `DEED_REGISTRY_AES_KEY_BASE64`: canonical base64 of exactly 32 random
  bytes;
- secret `DEED_REGISTRY_SOURCE_TOKEN`: a fine-grained token with read-only
  Contents access to `HansenHomeAI/Autodesk-automation`, used only by the
  one-time migration to fetch `deed-corpus-registry` into ephemeral storage;
- variable `DEED_REGISTRY_REQUEST_KEY_ID`: the non-sensitive RSA request-key
  rotation id supplied to authorized requesters;
- variable `DEED_REGISTRY_STATE_KEY_ID`: the non-sensitive AES state-key
  rotation id such as `custody-state-2026-07`; and
- branch protection/rulesets as described above, including GitHub Actions
  attestation permissions; and
- a protected `deed-corpus-registry` environment with required reviewers,
  restricted deployment branches, and only the custody secrets above.

Distribute `deed-request-public.pem` and its independently verified fingerprint
to the authorized requester. The public-key location is deliberately a CLI
argument, so custody policy controls distribution rather than this repository.

Run the one-time protected genesis migration before accepting requests:

```bash
gh workflow run migrate-encrypted-genesis.yml \
  --repo HansenHomeAI/deed-corpus-transparency-log
```

The migration refuses a nonempty encrypted index, validates the complete
private registry against the frozen public root/count, encrypts it in memory,
attests only the ciphertext and opaque index, and deletes its ephemeral source
file. After migration and escrow verification, securely delete local copies of
`deed-state-aes.b64` and `deed-request-private.pem`; the protected workflow
secrets remain the operational custody keys. Delete the one-time source token
after the successful attested migration:

```bash
gh secret delete DEED_REGISTRY_SOURCE_TOKEN --env deed-corpus-registry \
  --repo HansenHomeAI/deed-corpus-transparency-log
```

## Prepare and dispatch an encrypted intent

The requester needs only the request public key and current opaque index.
Neither the previous/new private registry root nor event count is supplied.
The plaintext intent contains one canonical semantic event body and must not
contain nonce, issued/released/consumed/sealed/challenged timestamps, release
authority, sequence, event hashes, workflow ids, or any private root. Obtain
the current public index SHA-256 from the trusted verifier and put it in
`expectedPublicIndexSha256`.

```json
{
  "schemaVersion": 4,
  "expectedPublicIndexSha256": "<current canonical index SHA-256>",
  "eventData": {
    "eventType": "assign",
    "caseId": "dp-<12 lowercase hex>",
    "corpusId": "corpus-<16 lowercase hex>",
    "payload": {
      "split": "tuning",
      "sourceSha256": "<64 lowercase hex>",
      "sourceBytes": 12345,
      "selectorSha256": "<64 lowercase hex>",
      "sourceFamilyId": "family-<12 lowercase hex>",
      "instrumentIdHash": "<64 lowercase hex>",
      "propertyIdentitySha256": "<64 lowercase hex>",
      "titleChainGroupSha256": "<64 lowercase hex>",
      "assignmentStatus": "sealed-untouched",
      "custodyMode": "operator-attested",
      "encryptedSourceBundleRootSha256": "<64 lowercase hex>",
      "custodianIdentitySha256": "<64 lowercase hex>"
    }
  },
  "response": {
    "algorithm": "RSA-OAEP-256+A256GCM",
    "keyId": "ephemeral-response-key-<request id>",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n<ephemeral per-request RSA public key>\n-----END PUBLIC KEY-----\n"
  }
}
```

Allowed kinds remain `legacy-quarantine`, `assign`, `truth-seal`,
`source-release`, `consume`, `execution-seal`, `judge-challenge`, and
`judge-seal`. `eventData` is required and encrypted. Its top-level fields are
exactly `eventType`, `caseId`, `corpusId`, and `payload`; the detailed validator
then enforces the exact type-specific semantics. Reserved chronology and
authority field names are rejected even when nested.
The complete plaintext request is capped at 32 KiB and its final canonical
base64url envelope at 60 KiB so it remains below GitHub's workflow-dispatch
payload ceiling; both encryption and protected decryption reject oversize
requests.

`response` is required and contains only an ephemeral per-request RSA public
key and its non-secret id. The protected append workflow uses it to return a
one-day artifact named `deed-registry-receipt-<full request SHA-256>`. The
artifact's `receipt.encrypted.json` is attested before upload and contains the
complete resulting detailed registry snapshot only inside its hybrid-encrypted
payload. Its public wrapper and optional metadata expose only request,
ciphertext, index, envelope, workflow-run, and encrypted-artifact commitments.
The decrypted receipt is limited to 32 MiB, binds the exact request, appended
tip event, registry root/count, public ciphertext/index/envelope, workflow
signer tip, run, timestamps, nonces, and execution certification fields, and
must pass the full detailed registry validator before use.

If the detailed state machine rejects an otherwise well-formed request, the
workflow does not change or recommit the public index or encrypted state. It
still attests and uploads a request-addressed, caller-encrypted rejection
receipt. Only the holder of that request's ephemeral response key can read the
exact validator errors and current registry prefix; public logs and receipt
metadata disclose only opaque commitments and the `rejected` outcome. This
lets a custodian repair a conflicting cohort without weakening the protected
validator or exposing private corpus identities.

For `source-release`, the caller payload contains only `productCodeTip`.
The protected workflow looks up the canonical assignment and derives
`assignmentEventSha256`, `sourceSha256`, encrypted bundle and custodian roots,
the actual prior matching release count, workflow issuance/freeze/release time,
release target, and release authority. Attempts to assert any derived custody
field are rejected before append.

`final` and `fail-safe` `execution-seal` events additionally bind separate
40-hex product and verifier-policy tips, require the product tip to equal the
consumed code tip, bind the attestation subject exactly to
`executionIndexSha256`, and require an attestation bundle-root SHA-256.

```bash
node scripts/encrypt-request.mjs \
  --input /secure/path/append-intent.json \
  --public-key /secure/path/deed-request-public.pem \
  --key-id request-key-2026-07 > /secure/path/request.base64url

gh workflow run append-encrypted-registry.yml \
  --repo HansenHomeAI/deed-corpus-transparency-log \
  -f encrypted_request_base64url="$(< /secure/path/request.base64url)"
```

After downloading the exact replay-addressed artifact, verify its retained
Sigstore bundle and decrypt it with the matching ephemeral private key. The CLI
requires the independently expected request hash, new state-ciphertext hash,
and exact protected append-workflow commit before it writes the validated
detailed receipt with mode `0600`:

```bash
node scripts/decrypt-receipt.mjs \
  --input /secure/path/receipt.encrypted.json \
  --attestation-bundle /secure/path/receipt.sigstore.json \
  --private-key /secure/path/ephemeral-response-private.pem \
  --key-id ephemeral-response-key-<request-id> \
  --expected-request-sha256 <64 lowercase hex> \
  --expected-ciphertext-sha256 <64 lowercase hex> \
  --expected-signer-digest <40 lowercase hex protected main commit> \
  --output /secure/path/validated-registry-receipt.json
```

Use the exact `main` tip at the start of that individual append run as
`--expected-signer-digest`. Each successful append advances `main`, so a later
execution-seal append normally has a newer signer tip than its preceding
consume append. The execution event's `verifierPolicyTip` remains the frozen
official-evaluator policy commit and is intentionally validated separately.

Request and state keys have distinct ids. State-key rotation requires a
controlled re-encryption ceremony that retains the prior AES key until the
latest authenticated snapshot has been decrypted and validated; changing only
the variable or secret will correctly fail closed.

## Official hosted deed evaluator

`.github/workflows/official-deed-evaluator.yml` is the only certification
runner. It refuses any verifier-policy tip other than its exact protected
`main` commit, checks out the private product at an exact SHA with a read-only
deploy key, and runs on GitHub-hosted macOS. Its positive final contract is 50
frozen cases times three cold trials; fail-safe campaigns use the same
source-only, attested, post-seal truth barrier.

Input PDFs and truth never enter workflow inputs, Git, logs, or plaintext
artifacts. Create separate `source` and `truth` file sets with
`scripts/deed-bundle.mjs`, encrypt both to the evaluator bundle public key, and
embed the same random 32-byte request id in each. Stage the two ciphertexts as
`source.bundle` and `truth.bundle` on a transient draft release in this
protected public repository. Draft assets remain inaccessible to anonymous
users and contain authenticated ciphertext only. The exact tag and release
name must both be
`deed-evaluator-input-<request-id>` and its target commit must be the frozen
protected verifier-policy SHA. Pass the release id, two distinct asset ids,
and ciphertext hashes to the official evaluator. It reads the same-repository
draft release with its scoped `contents: read` Actions token, validates the
tag/target/name/id/content type and hash of each asset, and never extracts an
archive. The local dispatcher owns a `finally` cleanup that deletes the
transient release after the hosted run, including on evaluation failure; the
evaluator itself has no contents-write permission.

Inside the encrypted source file set, the manifest is always named
`private-manifest.json` at the file-set root; a final cohort also carries its
root `intake-seal.json`, and every other member must be an exact source path
declared by that manifest. The truth file set contains only declared truth
packets and the receipt/evidence files those packets reference. Both unpackers
write role/request/root receipts, and the evaluator rejects any missing or
extra path before source execution or post-seal grading. This prevents an
undeclared truth file from being smuggled into the source phase.

The evaluator decrypts source only, verifies every manifest source commitment
and the absence of every truth path, then executes and seals all product
trials. A narrow local `codex` shim can submit only the product's attached PNG
crops, prompt, and JSON schema to a loopback GitHub Models broker. The broker
alone receives the workflow model token; the sandboxed product child receives
no GitHub token, OIDC variables, registry response key, evaluator bundle key,
truth, or preexisting Codex home.

`execution-index.json` is rebuilt and attested with SHA-pinned
`actions/attest` v4.1.1. The retained bundle is independently verified against
the exact workflow signer digest, protected source ref, Fulcio issuer,
GitHub-hosted runner claim, and Rekor record before the encrypted registry may
append its execution seal. Only after the seal receipt verifies does the
workflow decrypt truth and grade. Returned evidence excludes the original
source/truth payloads and is hybrid-encrypted to the requester's per-run public
key before the sole upload step.

The required evaluator environment contains no generated secrets until an
operator performs the reviewed setup ceremony. It needs the read-only private
product deploy key, the evaluator bundle-decryption private key, and the
corresponding non-secret bundle key id. The workflow generates registry receipt
keys ephemerally per run and deletes all private plaintext and key material in
an `always()` cleanup step.

## Protected refusal-truth reviewer

`.github/workflows/protected-refusal-reviewer.yml` is the separate fail-safe
truth-review boundary. It accepts only an encrypted raw-source bundle, never
checks out the product repository, renders and retains every PDF page, and
requires approving semantic reviews from pinned OpenAI and Meta multimodal
models after a workflow-generated challenge. The encrypted return contains
each prompt, schema, all-page image manifest and image, raw model response,
parsed assessment, model/call/session receipt, source-visible property identity
evidence, review index, and OIDC Sigstore attestation.

The encrypted registry accepts a fail-safe `truth-seal` only after a unique
`review-seal` binds the exact assignment, source, selector, expected-code
candidate, two distinct provider/model and returned-model identities, unique
call and session ids, evidence and attestation roots, and the protected
property-group hash. Reusing that protected property group for another case or
title chain is rejected.

## Offline custodian recovery and verification

The AES CLI reads its key only from `REGISTRY_AES_KEY_BASE64`; it does not accept
the key on the command line.

```bash
node scripts/verify-index.mjs \
  --index registry/index.json \
  --ciphertext-dir registry/ciphertexts

REGISTRY_AES_KEY_BASE64="$DEED_REGISTRY_AES_KEY_BASE64" \
  node scripts/decrypt-state.mjs \
  --input registry/ciphertexts/000001.bin \
  --output /secure/path/registry-state.json

REGISTRY_AES_KEY_BASE64="$DEED_REGISTRY_AES_KEY_BASE64" \
  node scripts/encrypt-state.mjs \
  --input /secure/path/registry-state.json \
  --output /secure/path/registry-state.bin
```

Run all adversarial and round-trip tests with:

```bash
node --test scripts/encrypted-registry.test.mjs
```
