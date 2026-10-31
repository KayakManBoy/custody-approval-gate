/**
 * PA-456: metadata-only owner-authorized GitHub custody preflight.
 * This intentionally DOES NOT claim independent-human approval.
 * GET only; never touches Cloudflare or an environment secret.
 */
import {pathToFileURL} from 'node:url';

export const REPO = 'KayakManBoy/custody-approval-gate';
export const OWNER = 'KayakManBoy';
export const ENVIRONMENT = 'signer-custody-owner';
const ROOT = 'https://api.github.com/repos/' + REPO;
const ENV_URL = ROOT + '/environments/' + ENVIRONMENT;
const BRANCHES_URL = ENV_URL + '/deployment-branch-policies?per_page=100&page=1';
const RULESETS_URL = ROOT + '/rulesets?per_page=100&page=1';
const MAIN_URL = ROOT + '/branches/main';
const HOLD = 'HOLD_PA456_OWNER_CUSTODY_UNVERIFIED';
const deny = () => { throw Error(HOLD); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactArray = (v, item) => Array.isArray(v) && v.length === 1 && v[0] === item;

async function getJSON(get, url, token) {
  let response;
  try {
    response = await get(url, {method: 'GET', redirect: 'manual',
      headers: {authorization: 'Bearer ' + token,
        accept: 'application/vnd.github+json', 'x-github-api-version': '2026-03-10'},
      signal: AbortSignal.timeout(8000)});
  } catch { deny(); }
  if (!response || response.status !== 200 || response.ok !== true ||
    response.url !== url || typeof response.text !== 'function') deny();
  let body;
  try { body = await response.text(); } catch { deny(); }
  if (typeof body !== 'string' || body.length > 32768) deny();
  try { return JSON.parse(body); } catch { deny(); }
}

export async function verifyOwnerGate({repository, actor, ref, sha, githubToken,
  get = fetch} = {}) {
  if (repository !== REPO || actor !== OWNER || ref !== 'refs/heads/main' ||
    typeof sha !== 'string' || !/^[a-f0-9]{40}$/.test(sha) ||
    typeof githubToken !== 'string' || !/^[A-Za-z0-9_+-]{20,512}$/.test(githubToken) ||
    typeof get !== 'function') deny();

  const environment = await getJSON(get, ENV_URL, githubToken);
  if (!plain(environment) || environment.name !== ENVIRONMENT ||
    !plain(environment.deployment_branch_policy) ||
    environment.deployment_branch_policy.custom_branch_policies !== true ||
    environment.deployment_branch_policy.protected_branches !== false ||
    !Array.isArray(environment.protection_rules)) deny();
  const branches = environment.protection_rules.filter(p => p?.type === 'branch_policy');
  const reviews = environment.protection_rules.filter(p => p?.type === 'required_reviewers');
  if (branches.length !== 1 || reviews.length !== 1 ||
    reviews[0].prevent_self_review !== false ||
    !Array.isArray(reviews[0].reviewers) || reviews[0].reviewers.length !== 1 ||
    reviews[0].reviewers[0]?.type !== 'User' ||
    reviews[0].reviewers[0]?.reviewer?.login !== OWNER) deny();
  const policies = await getJSON(get, BRANCHES_URL, githubToken);
  if (!plain(policies) || policies.total_count !== 1 ||
    !Array.isArray(policies.branch_policies) ||
    policies.branch_policies.length !== 1 ||
    policies.branch_policies[0]?.name !== 'main' ||
    (Object.hasOwn(policies.branch_policies[0], 'type') &&
      policies.branch_policies[0].type !== 'branch')) deny();

  // Do not rely on workflow source predicates or an unprotected main.
  const list = await getJSON(get, RULESETS_URL, githubToken);
  if (!Array.isArray(list) || list.length !== 1 || !Number.isSafeInteger(list[0]?.id) ||
    list[0].id <= 0 || list[0].enforcement !== 'active' ||
    list[0].source_type !== 'Repository') deny();
  const ruleset = await getJSON(get, ROOT + '/rulesets/' + list[0].id, githubToken);
  if (!plain(ruleset) || ruleset.id !== list[0].id ||
    ruleset.target !== 'branch' || ruleset.enforcement !== 'active' ||
    ruleset.source_type !== 'Repository' || ruleset.source !== REPO ||
    !Array.isArray(ruleset.bypass_actors) || ruleset.bypass_actors.length !== 0 ||
    !plain(ruleset.conditions) || !plain(ruleset.conditions.ref_name) ||
    !exactArray(ruleset.conditions.ref_name.include, '~DEFAULT_BRANCH') ||
    !Array.isArray(ruleset.conditions.ref_name.exclude) ||
    ruleset.conditions.ref_name.exclude.length !== 0 ||
    !Array.isArray(ruleset.rules)) deny();
  const rules = new Map();
  for (const rule of ruleset.rules) {
    if (!plain(rule) || typeof rule.type !== 'string' || rules.has(rule.type)) deny();
    rules.set(rule.type, rule);
  }
  if (!rules.has('deletion') || !rules.has('non_fast_forward') ||
    !rules.has('pull_request') || !rules.has('required_status_checks')) deny();
  const pr = rules.get('pull_request').parameters;
  if (!plain(pr) || pr.required_approving_review_count !== 0 ||
    pr.require_code_owner_review !== false || pr.require_last_push_approval !== false) deny();
  const checks = rules.get('required_status_checks').parameters;
  if (!plain(checks) || checks.strict_required_status_checks_policy !== true ||
    !Array.isArray(checks.required_status_checks) ||
    !checks.required_status_checks.some(x => x?.context === 'test')) deny();

  const main = await getJSON(get, MAIN_URL, githubToken);
  if (!plain(main) || main.name !== 'main' || main.protected !== true ||
    main.commit?.sha !== sha) deny();
  return Object.freeze({verified: true, model: 'OWNER_ONLY_NOT_INDEPENDENT', sha});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await verifyOwnerGate({repository: process.env.GITHUB_REPOSITORY,
      actor: process.env.GITHUB_ACTOR, ref: process.env.GITHUB_REF,
      sha: process.env.GITHUB_SHA, githubToken: process.env.GITHUB_TOKEN});
    process.stdout.write('PASS_PA456_OWNER_GATE_ONLY_NO_CLOUD_AUTHORITY\n');
  } catch {
    process.stderr.write(HOLD + '\n');
    process.exitCode = 1;
  }
}
