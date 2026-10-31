/** No provider credential, mutation, or environment binding. Public-repo approval verification. */
import {pathToFileURL} from 'node:url';
import {isHeaderSafeGitHubToken} from './github-token.mjs';

export const REPO = 'KayakManBoy/custody-approval-gate';
export const OWNER = 'KayakManBoy';
export const ENVIRONMENT = 'signer-custody-review';
const root = 'https://api.github.com/repos/' + REPO;
const envURL = root + '/environments/' + ENVIRONMENT;
const branchesURL = envURL + '/deployment-branch-policies?per_page=100&page=1';
const hold = () => { throw Error('HOLD_CUSTODY_REVIEW_UNVERIFIED'); };
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const login = x => typeof x === 'string' && /^[A-Za-z0-9-]{1,39}$/.test(x);

async function getJSON(get, url, token) {
  let r;
  try {
    r = await get(url, {method: 'GET', redirect: 'manual',
      headers: {authorization: 'Bearer ' + token, accept: 'application/vnd.github+json',
        'x-github-api-version': '2026-03-10'}, signal: AbortSignal.timeout(8000)});
  } catch { hold(); }
  if (!r || r.status !== 200 || !r.ok || r.url !== url) hold();
  let body;
  try { body = await r.text(); } catch { hold(); }
  if (typeof body !== 'string' || body.length > 16000) hold();
  try { return JSON.parse(body); } catch { hold(); }
}

export async function verifyGate({repository, actor, ref, expectedReviewer, githubToken,
  get = fetch} = {}) {
  if (repository !== REPO || actor !== OWNER || ref !== 'refs/heads/main' ||
    !login(expectedReviewer) || expectedReviewer === OWNER ||
    !isHeaderSafeGitHubToken(githubToken) ||
    typeof get !== 'function') hold();
  const e = await getJSON(get, envURL, githubToken);
  if (!plain(e) || e.name !== ENVIRONMENT || !plain(e.deployment_branch_policy) ||
    e.deployment_branch_policy.custom_branch_policies !== true ||
    e.deployment_branch_policy.protected_branches !== false ||
    !Array.isArray(e.protection_rules)) hold();
  const br = e.protection_rules.filter(x => x?.type === 'branch_policy');
  const rev = e.protection_rules.filter(x => x?.type === 'required_reviewers');
  if (br.length !== 1 || rev.length !== 1 || rev[0].prevent_self_review !== true ||
    !Array.isArray(rev[0].reviewers) || rev[0].reviewers.length !== 1 ||
    rev[0].reviewers[0]?.type !== 'User' ||
    rev[0].reviewers[0]?.reviewer?.login !== expectedReviewer) hold();
  const b = await getJSON(get, branchesURL, githubToken);
  if (!plain(b) || b.total_count !== 1 || !Array.isArray(b.branch_policies) ||
    b.branch_policies.length !== 1 || b.branch_policies[0]?.name !== 'main' ||
    (Object.hasOwn(b.branch_policies[0], 'type') && b.branch_policies[0].type !== 'branch')) hold();
  return Object.freeze({verified: true});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await verifyGate({repository: process.env.GITHUB_REPOSITORY,
      actor: process.env.GITHUB_ACTOR, ref: process.env.GITHUB_REF,
      expectedReviewer: process.env.EXPECTED_REVIEWER,
      githubToken: process.env.GITHUB_TOKEN});
    process.stdout.write('PASS_PUBLIC_GITHUB_REVIEW_GATE_ONLY\n');
  } catch {
    process.stderr.write('HOLD_CUSTODY_REVIEW_UNVERIFIED\n');
    process.exitCode = 1;
  }
}
