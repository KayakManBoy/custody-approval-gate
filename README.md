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

This infrastructure package cannot independently guarantee supported native ChatGPT and Claude phone retrieval. Signer custody is an upstream blocker only. Subsequent individually revocable identities, signed grants, protected reader/issuer deployment, two distinct real historical source SHA checks and tested native mobile tool behavior remain separate HOLD gates.\n## Current live state (October 31, 2026)\n\nThe source may be merged as an **inert, fail-closed implementation milestone** without provisioning a protected environment, independent reviewer or any secrets. The actual public repository has no verified branch protection, no reviewer configuration and no successful live `CHECK_ONLY` receipt; `CREATE_ONCE` must remain **HOLD**. The owner does not consider additional human reviews necessary for code quality; this preference does **not** authorize weakening the separate privileged execution gate. Changing that security model requires a distinct, explicit documented risk decision and safer alternative; it is never inferred from a source-only merge.\n