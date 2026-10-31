/**
 * PA-456: metadata-only owner-authorized GitHub custody preflight.
 * This intentionally DOES NOT claim independent-human approval.
 * GET only; never touches Cloudflare or an environment secret.
 */
import {pathToFileURL} from 'node:url';
import {isHeaderSafeGitHubToken} from './github-token.mjs';

export const REPO = 'KayakManBoy/custody-approval-gate';
export const OWNER = 'KayakManBoy';
export const ENVIRONMENT = 'signer-custody-owner';
const ROOT = 'https://api.github.com/repos/' + REPO;
const ENV_URL = ROOT + '/environments/' + ENVIRONMENT;
const BRANCHES_URL = ENV_URL + '/deployment-branch-policies?per_page=100&page=1';
const RULESETS_URL = ROOT + '/rulesets?per_page=100&page=1';
const MAIN_URL = ROOT + '/branches/main';
// GitHub Actions public App ID: status checks from other apps must never
// satisfy the protected branch gate by reusing the "test" context name.
export const GITHUB_ACTIONS_APP_ID = 15368;
const HOLD = 'HOLD_PA456_OWNER_CUSTODY_UNVERIFIED';
// Pure source-only diagnostics: never log endpoint paths, response bodies,
// bearer tokens, headers, account identifiers or administrator metadata.
// Each gate still rejects exactly as before; only the stable failure stage
// becomes visible in the inspect job's existing sanitized HOLD message.
const PHASES = ['ENV', 'POLICY', 'RULESET_LIST', 'RULESET', 'MAIN'];
const SAFE_STAGES = new Set(['INPUT', 'INPUT_CONTEXT', 'INPUT_TOKEN', 'ENV_SHAPE', 'ENV_REVIEWER',
  'POLICY_SHAPE', 'RULESET_LIST_SHAPE', 'RULESET_SHAPE', 'RULESET_RULES',
  'RULESET_CI', 'MAIN_SHAPE']);
for (const phase of PHASES) {
  for (const reason of ['NETWORK', 'HTTP_401', 'HTTP_403', 'HTTP_404',
    'HTTP_OTHER', 'RESPONSE', 'BODY', 'JSON']) {
    SAFE_STAGES.add(phase + '_' + reason);
  }
}
const deny = (stage = 'UNCLASSIFIED') => {
  const error = Error(HOLD);
  error.stage = SAFE_STAGES.has(stage) ? stage : 'UNCLASSIFIED';
  throw error;
};
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactArray = (v, item) => Array.isArray(v) && v.length === 1 && v[0] === item;

async function getJSON(get, url, token, phase) {
  let response;
  try {
    response = await get(url, {method: 'GET', redirect: 'manual',
      headers: {authorization: 'Bearer ' + token,
        accept: 'application/vnd.github+json', 'x-github-api-version': '2026-03-10'},
      signal: AbortSignal.timeout(8000)});
  } catch { deny(phase + '_NETWORK'); }
  if (!response || response.status !== 200 || response.ok !== true) {
    const status = response?.status;
    deny(phase + (status === 401 ? '_HTTP_401' : status === 403 ?
      '_HTTP_403' : status === 404 ? '_HTTP_404' : '_HTTP_OTHER'));
  }
  if (response.url !== url || typeof response.text !== 'function')
    deny(phase + '_RESPONSE');
  let body;
  try { body = await response.text(); } catch { deny(phase + '_BODY'); }
  if (typeof body !== 'string' || body.length > 32768)
    deny(phase + '_BODY');
  try { return JSON.parse(body); } catch { deny(phase + '_JSON'); }
}

export async function verifyOwnerGate({repository, actor, ref, sha, githubToken,
  get = fetch} = {}) {
  if (repository !== REPO || actor !== OWNER || ref !== 'refs/heads/main' ||
    typeof sha !== 'string' || !/^[a-f0-9]{40}$/.test(sha) ||
    typeof get !== 'function') deny('INPUT_CONTEXT');
  if (!isHeaderSafeGitHubToken(githubToken)) deny('INPUT_TOKEN');

  const environment = await getJSON(get, ENV_URL, githubToken, 'ENV');
  if (!plain(environment) || environment.name !== ENVIRONMENT ||
    !plain(environment.deployment_branch_policy) ||
    environment.deployment_branch_policy.custom_branch_policies !== true ||
    environment.deployment_branch_policy.protected_branches !== false ||
    !Array.isArray(environment.protection_rules)) deny('ENV_SHAPE');
  const branches = environment.protection_rules.filter(p => p?.type === 'branch_policy');
  const reviews = environment.protection_rules.filter(p => p?.type === 'required_reviewers');
  if (branches.length !== 1 || reviews.length !== 1 ||
    reviews[0].prevent_self_review !== false ||
    !Array.isArray(reviews[0].reviewers) || reviews[0].reviewers.length !== 1 ||
    reviews[0].reviewers[0]?.type !== 'User' ||
    reviews[0].reviewers[0]?.reviewer?.login !== OWNER) deny('ENV_REVIEWER');
  const policies = await getJSON(get, BRANCHES_URL, githubToken, 'POLICY');
  if (!plain(policies) || policies.total_count !== 1 ||
    !Array.isArray(policies.branch_policies) ||
    policies.branch_policies.length !== 1 ||
    policies.branch_policies[0]?.name !== 'main' ||
    (Object.hasOwn(policies.branch_policies[0], 'type') &&
      policies.branch_policies[0].type !== 'branch')) deny('POLICY_SHAPE');

  // Do not rely on workflow source predicates or an unprotected main.
  const list = await getJSON(get, RULESETS_URL, githubToken, 'RULESET_LIST');
  if (!Array.isArray(list) || list.length !== 1 || !Number.isSafeInteger(list[0]?.id) ||
    list[0].id <= 0 || list[0].enforcement !== 'active' ||
    list[0].source_type !== 'Repository') deny('RULESET_LIST_SHAPE');
  const ruleset = await getJSON(get, ROOT + '/rulesets/' + list[0].id, githubToken, 'RULESET');
  if (!plain(ruleset) || ruleset.id !== list[0].id ||
    ruleset.target !== 'branch' || ruleset.enforcement !== 'active' ||
    ruleset.source_type !== 'Repository' || ruleset.source !== REPO ||
    (Object.hasOwn(ruleset, 'bypass_actors') &&
      (!Array.isArray(ruleset.bypass_actors) || ruleset.bypass_actors.length !== 0)) ||
    !plain(ruleset.conditions) || !plain(ruleset.conditions.ref_name) ||
    !exactArray(ruleset.conditions.ref_name.include, '~DEFAULT_BRANCH') ||
    !Array.isArray(ruleset.conditions.ref_name.exclude) ||
    ruleset.conditions.ref_name.exclude.length !== 0 ||
    !Array.isArray(ruleset.rules)) deny('RULESET_SHAPE');
  const rules = new Map();
  for (const rule of ruleset.rules) {
    if (!plain(rule) || typeof rule.type !== 'string' || rules.has(rule.type))
      deny('RULESET_RULES');
    rules.set(rule.type, rule);
  }
  if (!rules.has('deletion') || !rules.has('non_fast_forward') ||
    !rules.has('pull_request') || !rules.has('required_status_checks'))
    deny('RULESET_RULES');
  const pr = rules.get('pull_request').parameters;
  if (!plain(pr) || pr.required_approving_review_count !== 0 ||
    pr.require_code_owner_review !== false || pr.require_last_push_approval !== false)
    deny('RULESET_RULES');
  const checks = rules.get('required_status_checks').parameters;
  // GitHub can accept a context-only "test" status from an untrusted source.
  // Require precisely the GitHub Actions CI job identity, not "any source".
  if (!plain(checks) || checks.strict_required_status_checks_policy !== true ||
    checks.do_not_enforce_on_create === true ||
    !Array.isArray(checks.required_status_checks) ||
    checks.required_status_checks.length !== 1 ||
    !plain(checks.required_status_checks[0]) ||
    checks.required_status_checks[0].context !== 'test' ||
    checks.required_status_checks[0].integration_id !== GITHUB_ACTIONS_APP_ID)
    deny('RULESET_CI');

  const main = await getJSON(get, MAIN_URL, githubToken, 'MAIN');
  if (!plain(main) || main.name !== 'main' || main.protected !== true ||
    main.commit?.sha !== sha) deny('MAIN_SHAPE');
  // GitHub omits bypass_actors for read-only tokens. A human owner MUST inspect
  // the no-bypass ruleset and admin environment bypass switches out of band.
  return Object.freeze({visibleRulesVerified: true,
    ownerAdminCheckRequired: true, model: 'OWNER_ONLY_NOT_INDEPENDENT', sha});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await verifyOwnerGate({repository: process.env.GITHUB_REPOSITORY,
      actor: process.env.GITHUB_ACTOR, ref: process.env.GITHUB_REF,
      sha: process.env.GITHUB_SHA, githubToken: process.env.GITHUB_TOKEN});
    process.stdout.write('PA456_VISIBLE_RULES_PASS_OWNER_ADMIN_CHECK_REQUIRED_NO_CLOUD_AUTHORITY\n');
  } catch (error) {
    // Never print the original exception, its message or any response data.
    const stage = SAFE_STAGES.has(error?.stage) ? error.stage : 'UNCLASSIFIED';
    process.stderr.write(HOLD + ' stage=' + stage + '\n');
    process.exitCode = 1;
  }
}
