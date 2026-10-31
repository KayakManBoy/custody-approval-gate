# Independent signing-key custody gate (public-source candidate)

This is a minimal, **generic public-source** one-time execution repository. There are no private dataset files, private source references, provider account identifiers, store IDs, signing secrets, management tokens, credentials, or private bearer values in this source tree. Public RSA verification-key material may appear in the receipt after an approved create; **a public-key receipt is not a completed production release**.

## Purpose, cost and boundary

- Intended GitHub repository: `KayakManBoy/custody-approval-gate` (PUBLIC). **Do not import or fork any private project repository.** Publish only the reviewed files in this directory.
- Existing GitHub Free/Pro accounts support required environment reviews for public repositories; standard GitHub-hosted Linux Actions on public repositories cost no runner minutes. Do not purchase an upgrade or use paid larger runners.
- Workflow dispatch is **manual only**. `CHECK_ONLY` uses two GitHub metadata GETs, no privileged environment or Cloudflare token. `CREATE_ONCE` needs an independent reviewer and short-lived Cloudflare authority, and never runs in the initial feasibility stage.
- No new production datasets, deployment, Worker route, Cron, database writes, storage deletion, user grants or AI data transfer are authorized by the presence of this code.
- The one-time Cloudflare Edit permission can modify/delete other account secrets. Application code pins its intended destination but **cannot narrow provider-enforced IAM**. This blast radius requires separate explicit approval, temporary custody, independent readback and revocation.

## Hard preconditions (do not load credentials before all pass)

1. Owner creates the **new, otherwise empty public repository** with the exact name above, not by changing any private repository's visibility. Confirm there are no repo-level Actions secrets or untrusted reusable workflows.
2. Independent human reviewer agrees to participate and has an actual GitHub login. Before any source is trusted, configure a public `main` branch ruleset/protection requiring PR reviews (including changes to workflow/scripts), disallow force pushes/deletions, and disallow administrative bypass where available. Do not allow direct owner pushes bypassing review. The reviewer must review exact code/commit before it is the executable `main`.
3. Configure GitHub environment `signer-custody-review` manually, with exactly **one named separate User reviewer**, `prevent_self_review=true`, exact custom deployment branch policy **main only**. **Uncheck “Allow administrators to bypass configured protection rules.”** Have the independent reviewer inspect these settings because the metadata-only checker cannot prove the bypass checkbox state.
4. Create repository variable `INDEPENDENT_REVIEWER_LOGIN` containing that reviewer's exact login. This is a public identifier, not a token.
5. Dispatch **CHECK_ONLY** on `main`. The job must finish `PASS_PUBLIC_GITHUB_REVIEW_GATE_ONLY`. A failed, missing, inconclusive or changing gate => HOLD. Success is GitHub reviewer eligibility only.
6. Separately approve the precise **account-wide** temporary Cloudflare Secrets Store Edit authority and custody. The holder provisions the short-lived token directly as the environment-only secret `CF_TEMP_EDIT_TOKEN`, never in a public repo issue, action input, log, file, chat or general repository secret. Use no long-lived Cloudflare write credential.
7. Set the protected environment secrets `CF_TARGET_ACCOUNT`, `CF_TARGET_STORE` and `CF_TARGET_SECRET_NAME` **through an authorized private channel**, not public job input/repository variables. Set protected environment-only secret `CF_APPROVED_COMMIT_SHA` to the independently reviewed exact 40-character `main` commit. Do not create a repository-wide substitute. Confirm it does not change before the one-shot dispatch.
8. Only following a **new, exact CREATE authorization**, owner dispatches `CREATE_ONCE`; independent reviewer approves that pending environment job after verifying the pinned commit and full workflow diff. Any missing approval, settings drift, changed commit or failed preflight => HOLD. Never retry an ambiguous POST.
9. Collect the **public-key-only** receipt; independently read Cloudflare secret metadata and signer/public-key match through approved access. Revoke the temporary Cloudflare token immediately. Confirm unchanged existing secrets and dataset collector. Mark signer custody PASS only after independent readback and matching-key proof.

The approval gate is conditional on real provider enforcement. A GitHub administrator can alter settings or trusted code if repository protection is not effective. An isolated public source repository is therefore **not** itself proof of independent enforcement. Never label the gate LIVE merely because workflow YAML is published.

## Execute tests without network or credentials

```bash
node --check scripts/verify-gate.mjs
node --check scripts/create-once.mjs
node --test tests/*.test.mjs
```

The public-repository CI runs only those offline tests. It has no Cloudflare secret binding and is separate from the manual signer workflow. The manual workflow uses a pinned checkout, `contents: read` only in the privileged job, no repository write, no direct private project checkout and no third-party installer.

## Public receipts and recovery

The service creates an RSA-2048 RS256 key in ephemeral runner memory, posts its Base64URL PKCS8 only to the configured Cloudflare Secrets Store API, and prints **public** JWK, key ID and fingerprint for downstream verification. These public values may be visible in public Actions logs. Do not use this route if even disclosing the public key would be unacceptable. It is not designed to hide runner source code from the GitHub runner infrastructure or remove Cloudflare's account-wide token power.

On failure or uncertain response, do **not** dispatch CREATE again. Inspect actual Cloudflare metadata independently, verify whether the named secret exists or is pending, preserve a sanitized audit receipt, then obtain a specific recovery decision. Manual GitHub job re-runs (run attempt greater than 1) are rejected both by the workflow job conditions and by the credential-bearing script before any provider request. A new manual dispatch still requires all the independent gates and its own approval. No automatic deletion, replacement or rotation is implemented. No private key is exported to the user or to any AI connector.

## Acceptance boundary

This infrastructure package cannot independently guarantee supported native ChatGPT and Claude phone retrieval. Signer custody is an upstream blocker only. Subsequent individually revocable identities, signed grants, protected reader/issuer deployment, two distinct real historical source SHA checks and tested native mobile tool behavior remain separate HOLD gates.
## Current live state (October 31, 2026)

The source may be merged as an **inert, fail-closed implementation milestone** without provisioning a protected environment, independent reviewer or any secrets. The actual public repository has no verified branch protection, no reviewer configuration and no successful live `CHECK_ONLY` receipt; `CREATE_ONCE` must remain **HOLD**. The owner does not consider additional human reviews necessary for code quality; this preference does **not** authorize weakening the separate privileged execution gate. Changing that security model requires a distinct, explicit documented risk decision and safer alternative; it is never inferred from a source-only merge.

## PA-456 — Owner-only *alternative* (SOURCE ONLY; no independent approver)

Edward explicitly selected one-person operation on October 31, 2026. This model **replaces the second-person execution approval only for a separately authorized future operation**; it does NOT establish independent human review or permission to run CREATE. Keep the original independently reviewed `one-time.yml` as a dormant alternative. The new `.github/workflows/owner-one-time.yml` uses the same isolated, already offline-tested `create-once.mjs` key generator and read-before-write/no-retry safeguards.

**Owner-only risk acceptance:** If Edward's GitHub account or its protected environment configuration is compromised, the same authority can potentially modify code and approve execution. An owner-authenticated approval is a deliberate second action, *not* a second principal. GitHub branch rules, SHA-pinned environment secret, temporary Cloudflare token and audit logs mitigate accidents and some compromise paths but cannot create independent human separation. The user has approved exploring this risk model, **not creating credentials or broadly granting account permissions**.

### Hard pre-credential conditions

1. Maintain the repository public but generic. Never publish private account identifiers, Cloudflare target IDs, dataset metadata, key, token or private Project Alpha files. Do not make Project Alpha itself public.
2. Owner must separately authorize and configure one active **no-bypass** repository branch ruleset targeting only default `main`: require PR before merging (**0 approving reviews**; owner may merge their own PR), require existing named CI status `test` with strict up-to-date checks, block deletions and force pushes. Enforce on administrators; no bypass roles/apps. No credential-bearing job until effective protection independently passes readback.
3. Owner must separately authorize and configure the public GitHub environment `signer-custody-owner`, with exactly one required **User** reviewer `KayakManBoy`, **Prevent self-review OFF**, custom deployment branches **main only** and **Allow administrators to bypass configured protection rules OFF**. Last bypass flag is not established by the GET verifier; owner must examine GitHub's actual setting before any privileged operation. There must be **no environment secrets yet** during the read-only source/CI stage.
4. Following separately authorized settings changes and a reviewed/merged main SHA, the owner may separately dispatch `CHECK_ONLY` on `main`. The `inspect` job reads **only GitHub** environment/ruleset/branch metadata, has no environment binding or Cloudflare token and must print `PASS_PA456_OWNER_GATE_ONLY_NO_CLOUD_AUTHORITY`. A malformed/missing API response, wrong rules, wrong SHA or changed main returns HOLD. Public source CI exercises fixtures only and does not establish these conditions.
5. Before any actual key creation, obtain a **new exact** owner approval to create the single RSA signer and for the temporary **account-wide** Cloudflare Secrets Store Edit permission, its short expiry, securely provisioned environment-only token, prompt independent metadata readback and immediate revocation. Edit remains able to change/delete unrelated secrets; neither runner code nor GitHub rules narrow Cloudflare IAM.
6. Only if the preceding checks pass, put `CF_APPROVED_COMMIT_SHA` (exact committed `main` SHA) and `CF_TEMP_EDIT_TOKEN`, `CF_TARGET_ACCOUNT`, `CF_TARGET_STORE`, `CF_TARGET_SECRET_NAME` in **environment-only** secrets via approved custody. Never put secret values into workflow inputs, GitHub repo-level secrets, logs, chats, files or artifacts.
7. Owner separately dispatches `CREATE_ONCE`, then personally reviews the exact pending environment job/commit and clicks **Approve and deploy**. This is owner re-authorization, not independent approval. A new action run must have `run_attempt=1`; GitHub re-runs and ambiguous Cloudflare POST responses are not automatically retried. The source script requires the exact SHA and checks destination inventory before generating a fresh ephemeral RSA-2048 key.
8. Verify the public-key-only receipt, real Cloudflare secret metadata and (using a separately approved authenticated signing challenge) public/private key match, unchanged unrelated secrets and immediate token revocation. **Metadata alone cannot prove matching key bytes.** A create acceptance is not full signer custody PASS and does not authorize private grant/issuer/reader deploy.

**Not yet done:** Current public `main` unprotected and zero rulesets; this new owner workflow, gate and environment have not been activated or run; no live `CHECK_ONLY`, key, temporary token, credential, grant or deploy. No fee/subscription is proposed. The original private PA-452 failed, so do not use it as a substitute. Permanent Schedules full-46-field producer and complete source R2/D1 history are out of scope; private serving and phone acceptance remain HOLD.
