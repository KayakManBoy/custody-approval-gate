# Public one-time signing-key custody gate

This is a **public, generic source repository** for a manually authorized, one-time RSA signer bootstrap in Cloudflare Secrets Store. This repository is **not** a private application, a production deployment, or authority to create a secret. It contains no intended target account IDs, store IDs, private signer bytes, token values, application-specific grants or protected source records.

The GitHub repository is [KayakManBoy/custody-approval-gate](https://github.com/KayakManBoy/custody-approval-gate). The protected owner is the public GitHub login `KayakManBoy`. Only generic custody procedures belong in this public README. Do not paste private-project names, account metadata, user identities, datasets, source history or internal operational handoffs into this repository or public pull requests. Those belong in the appropriate **private** repository.

## What is implemented

Two **manual-only** GitHub Actions alternatives are retained; neither runs on a push, pull request, schedule, or CI:

| Workflow | Human review model | Environment |
| --- | --- | --- |
| `.github/workflows/owner-one-time.yml` | **Owner-only** approval, not independent | `signer-custody-owner` |
| `.github/workflows/one-time.yml` | Separate named reviewer, only if independently configured | `signer-custody-review` |

The owner selected the owner-only model, knowing it creates a **single principal** for authorization. The separate-person workflow remains a dormant alternative and does not imply another reviewer has been recruited or that a protected environment exists.

Both workflows support `CHECK_ONLY` (default) and `CREATE_ONCE` (distinct effect authorization necessary). Each has an unprivileged GitHub metadata-check job, and a separate environment-bound credential job that is conditional on `CREATE_ONCE`, a successful first check and the exact owner, repository, `main` ref and first run attempt. Both share the same repository-wide `one-time-signing-key-custody` concurrency group with cancellation disabled. The privileged job repeats its applicable GitHub gate **after deployment approval and before its only secret-bearing step**. No automatic retries of Cloudflare POST or reruns of an execution attempt.

The public `test` GitHub Actions job uses pinned checkout and offline Node tests, without repository write permission, environment secrets, Cloudflare credentials or a third-party installer.

## Hard restrictions before any credential is provisioned

1. **Protect public main first.** The owner must separately authorize and configure one active, non-bypassable repository branch ruleset for default `main` only: a PR is required, **zero** approving human reviews for owner-only operation, strict up-to-date `test` status, no force pushes and no branch deletion. The `test` required check must be produced by **GitHub Actions App ID `15368`**, not "any source". The owner must inspect and attest the actual bypass configuration in GitHub Settings; the read-only API can omit it.
2. **Protect the environment separately.** For owner-only operation, create `signer-custody-owner` with exactly one required user reviewer, `KayakManBoy`, `Prevent self-review` **OFF**, administrator bypass **OFF**, custom deployment branch policy **only exact `main`**, and no unrelated reviewers. This is a separate GitHub administrative change requiring owner approval. Do **not** add credentials to repository-level secrets or unprotected variables.
3. **Check without Cloudflare.** Only after the settings are authorized and independently inspected, run `CHECK_ONLY` on public `main`; the read-only owner gate should emit `PA456_VISIBLE_RULES_PASS_OWNER_ADMIN_CHECK_REQUIRED_NO_CLOUD_AUTHORITY`. That string proves observable GitHub settings only; it **cannot** prove the hidden bypass switches or confer Cloudflare permission. Any failing, incomplete, ambiguous or inaccessible API response remains **HOLD**.
4. **Get a new exact effect authorization.** Real `CREATE_ONCE`, the intended target, one RSA signer, temporary Cloudflare token privileges, its expiry and custody, and an independent readback/revocation protocol must all be separately authorized. A code merge or successful `CHECK_ONLY` is not approval. A temporary Secrets Store Write/Edit token can create, replace or delete **other** account secrets; this code's destination pinning does not narrow provider IAM.
5. **Use environment-only secrets, after approval.** The credential-bearing job accepts `CF_APPROVED_COMMIT_SHA` (exact protected `main` commit), `CF_TEMP_EDIT_TOKEN` (short-lived), `CF_TARGET_ACCOUNT`, `CF_TARGET_STORE`, and `CF_TARGET_SECRET_NAME` exclusively via the protected environment. Do not put these values in public source, workflow inputs, general repository secrets, chat, logs, shell history or artifacts. The private key never leaves the ephemeral process except for its intended authenticated provider write.
6. **Re-approve the exact dispatch.** Only after separately approved preconditions may the owner dispatch `CREATE_ONCE`, inspect the pinned source commit in the pending environment job, and explicitly approve deployment. Owner approval is a second action, **not** independent-person separation. A changed SHA, protection drift, missing metadata or unexpected condition must fail closed.
7. **Prove the result and revoke.** Even an accepted create response is **not** proof of an active signer or matching-key custody. Independently confirm provider secret metadata and a real protected signing challenge that verifies against the receipt's public JWK, confirm unrelated secrets are unchanged, and immediately revoke the temporary token. A failed or uncertain write must **not** be retried without independent readback and new explicit authorization.

The read-only owner gate verifies visible repository rules, named owner/environment/reviewer, custom main-only branch policy, exact current main SHA and GitHub Actions-produced required `test` status. The independent-review gate checks a different human and self-review prevention, and is not a substitute for the owner-only branch rules. Administrative bypass controls are deliberately **not claimed proven by read-only tokens**.

## Actual prewrite protections

The shared `scripts/create-once.mjs` checks the exact owner, repository, commit SHA, action, one-run attempt, target format and token format before provider access. It verifies an account-scoped Cloudflare token through a read-only token-verify GET and requires **active status with an explicit expiration 2–60 minutes away**. This is a remaining-lifetime check; it does **not** prove the token's original age, narrow permissions, issuance restrictions or eventual revocation. A denial is **HOLD**, never a fallback to a broader credential.

It reads exactly one complete page of Secrets Store inventory, checks page metadata and record provenance, and **rejects any existing same-name secret**, including a deleted or pending entry. It generates a fresh RSA-2048 RS256 key in ephemeral runner memory, then demands a byte-for-byte canonical PKCS8 DER round-trip (rejecting trailing bytes or noncanonical representations), and cryptographically rechecks the *exact* Base64URL PKCS8 DER against the advertised public JWK, SHA-256 fingerprint and `rs256-` key ID **before the first and only POST**. It never prints the private key, bearer or provider account/store identifiers. It returns a **public-key-only** receipt that is safe to share publicly; this receipt does not establish active private signer custody.

Because Cloudflare's GET-before-POST inventory is **not atomic**, another client outside this repository can still race. A GitHub concurrency group locks only runs in this repository. Provider-side permissions remain broader than one named secret; independent inventory/readback/revocation and explicit human approval remain mandatory.

## Offline tests, scope, and safety

```bash
node --check scripts/verify-gate.mjs
node --check scripts/verify-owner-gate.mjs
node --check scripts/create-once.mjs
node --test tests/*.test.mjs
```

All automated tests use synthetic identities, keys and mocked APIs. Passing CI proves **source behavior only**. It is not a live environment, credential, secret-store inventory, cloud deployment or protected reader acceptance. This source does not grant rights to deploy any service, access a private dataset, modify credentials, connect AI providers, delete backups, acquire paid subscriptions or change another repository.

The public owner gate's real operation cannot be certified until the protected ruleset and environment are **configured and verified**. At the last checked public `main` state, branch protection was absent, the repository had **zero rulesets**, and no custody `workflow_dispatch` runs had occurred. This source-only merge changes none of those controls.

### Public-history limitation

Public commits and pull-request descriptions are durable records. Cleaning the current README prevents *new readers* from encountering private-context references on the default branch; it **does not erase references already present in prior public Git history, discussions, logs, or forks**. There is no destructive history rewrite in this work. Future public-source changes must use generic terms only, with a disclosure regression test; any sensitive history remediation would require a separate deliberate decision.

## External API references

- [GitHub deployment environments](https://docs.github.com/en/rest/deployments/environments)
- [GitHub repository rulesets](https://docs.github.com/en/rest/repos/rules)
- [GitHub deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies)
- [Cloudflare token verification](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/verify/)
- [Cloudflare Secrets Store](https://developers.cloudflare.com/api/resources/secrets_store/)
