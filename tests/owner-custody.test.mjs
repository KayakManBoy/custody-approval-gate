import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyOwnerGate, REPO, OWNER, ENVIRONMENT, GITHUB_ACTIONS_APP_ID} from '../scripts/verify-owner-gate.mjs';

const sha = 'a'.repeat(40), token = 'ghs_' + 't'.repeat(32);
const root = 'https://api.github.com/repos/' + REPO;
const environment = {name: ENVIRONMENT,
  deployment_branch_policy: {protected_branches: false, custom_branch_policies: true},
  protection_rules: [{type: 'branch_policy'}, {type: 'required_reviewers',
    prevent_self_review: false, reviewers: [{type: 'User', reviewer: {login: OWNER}}]}]};
const branches = {total_count: 1, branch_policies: [{name: 'main', type: 'branch'}]};
const listed = [{id: 456, source_type: 'Repository', enforcement: 'active'}];
const ruleset = {id: 456, source_type: 'Repository', source: REPO, target: 'branch',
  enforcement: 'active', bypass_actors: [],
  conditions: {ref_name: {include: ['~DEFAULT_BRANCH'], exclude: []}},
  rules: [{type: 'deletion'}, {type: 'non_fast_forward'},
    {type: 'pull_request', parameters: {required_approving_review_count: 0,
      require_code_owner_review: false, require_last_push_approval: false}},
    {type: 'required_status_checks', parameters: {
      strict_required_status_checks_policy: true,
      required_status_checks: [{context: 'test', integration_id:GITHUB_ACTIONS_APP_ID}]}}]};
const main = {name: 'main', protected: true, commit: {sha}};
const ok = (url, data, status = 200) => ({
  url, status, ok: status === 200, text: async () => JSON.stringify(data)});
const fixtureGet = (data = {}) => async (url, options) => {
  assert.equal(options.method, 'GET');
  assert.equal(options.redirect, 'manual');
  const source = url.endsWith('/branches/main') ? (data.main ?? main) :
    url.endsWith('/deployment-branch-policies?per_page=100&page=1') ?
      (data.branches ?? branches) :
    url.endsWith('/environments/' + ENVIRONMENT) ? (data.environment ?? environment) :
    url.endsWith('/rulesets?per_page=100&page=1') ? (data.listed ?? listed) :
    url.endsWith('/rulesets/456') ? (data.ruleset ?? ruleset) : null;
  assert.notEqual(source, null, 'unknown network endpoint');
  return ok(data.redirect ? url + '/redirect' : url, source, data.status ?? 200);
};
const args = overrides => ({repository: REPO, actor: OWNER, ref: 'refs/heads/main',
  sha, githubToken: token, get: fixtureGet(), ...overrides});
const denied = async overrides =>
  assert.rejects(() => verifyOwnerGate(args(overrides)), /HOLD_PA456_OWNER_CUSTODY_UNVERIFIED/);
const deniedStage = async (overrides, stage) =>
  assert.rejects(() => verifyOwnerGate(args(overrides)), error => {
    assert.equal(error.message, 'HOLD_PA456_OWNER_CUSTODY_UNVERIFIED');
    assert.equal(error.stage, stage);
    assert.doesNotMatch(String(error), /ghs_|Authorization:|Bearer /);
    return true;
  });
const variation = patch => ({...ruleset, ...patch});

test('owner-only is a labeled, exact-main protected check, not independent review', async () => {
  assert.deepEqual(await verifyOwnerGate(args()), {visibleRulesVerified: true,
    ownerAdminCheckRequired: true, model: 'OWNER_ONLY_NOT_INDEPENDENT', sha});
});

test('wrong initiating identity, SHA and GitHub HTTP errors deny before cloud', async () => {
  for (const change of [
    {repository: 'another/repo'}, {actor: 'other'}, {ref: 'refs/heads/topic'},
    {sha: 'invalid'}, {githubToken: ''}, {get: fixtureGet({status: 403})},
    {get: fixtureGet({redirect: true})}, {get: async () => {throw Error('offline');}}
  ]) await denied(change);
});

test('owner review environment must exist with exact required owner and main only', async () => {
  for (const invalid of [
    {...environment, protection_rules: []},
    {...environment, protection_rules: [environment.protection_rules[0],
      {...environment.protection_rules[1], prevent_self_review: true}]},
    {...environment, protection_rules: [environment.protection_rules[0],
      {...environment.protection_rules[1], reviewers: [{type:'User', reviewer:{login:'Other'}}]}]},
    {...environment, deployment_branch_policy: {protected_branches: true,
      custom_branch_policies: false}}
  ]) await denied({get: fixtureGet({environment: invalid})});
  for (const invalid of [
    {total_count: 2, branch_policies: [{name:'main'},{name:'dev'}]},
    {total_count: 1, branch_policies: [{name:'*'}]}
  ]) await denied({get: fixtureGet({branches: invalid})});
});

test('public main must have active visible CI/PR rules; bypass still requires owner admin check', async () => {
  // GitHub omits bypass_actors without ruleset write permission. Do not invent
  // independent no-bypass verification from a read-only workflow token.
  const {bypass_actors: ignored, ...publicDetails} = ruleset;
  assert.deepEqual(await verifyOwnerGate(args({get: fixtureGet({
    ruleset: publicDetails})})), {visibleRulesVerified: true,
    ownerAdminCheckRequired: true, model:'OWNER_ONLY_NOT_INDEPENDENT', sha});
  for (const invalid of [
    {listed: []}, {listed: [{...listed[0], enforcement:'disabled'}]},
    {ruleset: variation({bypass_actors: [{actor_type:'RepositoryRole', actor_id:5}]})},
    {ruleset: variation({conditions: {ref_name:{include:['~ALL'],exclude:[]}}})},
    {ruleset: variation({rules: ruleset.rules.filter(r => r.type !== 'pull_request')})},
    {ruleset: variation({rules: ruleset.rules.filter(r => r.type !== 'non_fast_forward')})},
    {ruleset: variation({rules: ruleset.rules.map(r => r.type === 'pull_request' ?
      {...r,parameters:{...r.parameters,required_approving_review_count: 1}} : r)})},
    {ruleset: variation({rules: ruleset.rules.map(r => r.type === 'required_status_checks' ?
      {...r,parameters:{...r.parameters,required_status_checks:[{context:'untrusted',integration_id:GITHUB_ACTIONS_APP_ID}]}} : r)})},
    ...[
      [{context:'test'}],
      [{context:'test',integration_id:null}],
      [{context:'test',integration_id:42}],
      [{context:'test',integration_id:GITHUB_ACTIONS_APP_ID},{context:'test',integration_id:GITHUB_ACTIONS_APP_ID}]
    ].map(required_status_checks => ({ruleset:variation({rules:ruleset.rules.map(r=>
      r.type==='required_status_checks' ? {...r,parameters:{...r.parameters,required_status_checks}}:r)})})),
    {ruleset: variation({rules: ruleset.rules.map(r => r.type === 'required_status_checks' ?
      {...r,parameters:{...r.parameters,do_not_enforce_on_create:true}} : r)})},
    {main: {...main, protected: false}},
    {main: {...main, commit:{sha:'b'.repeat(40)}}}
  ]) await denied({get: fixtureGet(invalid)});
});

test('owner workflow never runs on push or accesses environment secrets in inspect', () => {
  const src = readFileSync(new URL('../.github/workflows/owner-one-time.yml', import.meta.url), 'utf8');
  assert.match(src, /workflow_dispatch:/);
  assert.doesNotMatch(src, /^\s+(push|pull_request|schedule|workflow_run):/m);
  assert.match(src, /inputs.action == 'CREATE_ONCE'/);
  assert.match(src, /needs: inspect/);
  assert.match(src.split('  create:\n')[0], /actions: read/);
  assert.match(src, /github.run_attempt == 1/g);
  assert.equal((src.match(/github.run_attempt == 1/g) || []).length, 2);
  const inspect = src.split('  create:\n')[0];
  assert.doesNotMatch(inspect, /secrets\./);
  assert.doesNotMatch(inspect, /environment:/);
  assert.match(src, /environment: signer-custody-owner/);
  assert.match(src, /secrets.CF_APPROVED_COMMIT_SHA/);
  assert.match(src, /secrets.CF_TEMP_EDIT_TOKEN/);
  assert.match(src, /node scripts\/create-once.mjs/);
  assert.doesNotMatch(src, /permissions:\s*\n\s*contents: write/);
});


test('required CI workflow is pinned to an offline GitHub Actions test job',()=>{
  assert.equal(GITHUB_ACTIONS_APP_ID,15368);
  const source=readFileSync(new URL('../.github/workflows/offline-tests.yml',import.meta.url),'utf8');
  assert.match(source,/^  pull_request:$/m);
  assert.match(source,/^  push:$/m);
  assert.match(source,/^    branches: \[main\]$/m);
  assert.match(source,/^  test:$/m);
  assert.match(source,/node --test tests\/\*\.test\.mjs/);
  assert.match(source,/actions\/checkout@[a-f0-9]{40}/);
  assert.match(source,/persist-credentials: false/);
  assert.doesNotMatch(source,/secrets\.|environment:|contents: write|id-token: write|workflow_dispatch:/);
});

test('sanitized diagnostic codes identify fail-closed stage without exposing responses',async()=>{
  await deniedStage({actor:'not-owner'},'INPUT_CONTEXT');
  await deniedStage({githubToken:''},'INPUT_TOKEN');
  await deniedStage({get:fixtureGet({status:403})},'ENV_HTTP_403');
  await deniedStage({get:fixtureGet({status:404})},'ENV_HTTP_404');
  await deniedStage({get:async()=>{throw Error('private credential raw error');}},'ENV_NETWORK');
  await deniedStage({get:fixtureGet({redirect:true})},'ENV_RESPONSE');
  await deniedStage({get:fixtureGet({environment:{...environment,name:'unexpected'}})},'ENV_SHAPE');
  await deniedStage({get:fixtureGet({environment:{...environment,
    protection_rules:[environment.protection_rules[0]]}})},'ENV_REVIEWER');
  await deniedStage({get:fixtureGet({branches:{...branches,total_count:2}})},'POLICY_SHAPE');
  await deniedStage({get:fixtureGet({listed:[]})},'RULESET_LIST_SHAPE');
  await deniedStage({get:fixtureGet({ruleset:{...ruleset,conditions:null}})},'RULESET_SHAPE');
  await deniedStage({get:fixtureGet({ruleset:{...ruleset,rules:[]}})},'RULESET_RULES');
  await deniedStage({get:fixtureGet({ruleset:{...ruleset,rules:ruleset.rules.map(rule=>
    rule.type==='required_status_checks' ? {...rule,parameters:{
      ...rule.parameters, required_status_checks:[{context:'test',integration_id:42}]}} : rule)}})},'RULESET_CI');
  await deniedStage({get:fixtureGet({main:{...main,protected:false}})},'MAIN_SHAPE');
});

test('inspect path uses only GitHub read access and never prints raw exceptions',()=>{
  const src=readFileSync(new URL('../scripts/verify-owner-gate.mjs', import.meta.url),'utf8');
  const pre=readFileSync(new URL('../.github/workflows/owner-one-time.yml', import.meta.url),'utf8');
  assert.match(src,/process\.stderr\.write\(HOLD \+ ' stage=' \+ stage/);
  assert.match(src,/SAFE_STAGES\.has\(error\?\.stage\)/);
  assert.doesNotMatch(src,/console\.log|console\.error|JSON\.stringify\(environment\)|response\.statusText/);
  assert.doesNotMatch(pre.split(/^  create:\s*$/m)[0],/secrets\.|environment:|contents: write/);
});

test('2026 opaque GitHub Actions JWT token reaches GitHub metadata gate unchanged', async()=>{
  const jwtLike = 'ghs_15368_' + 'a'.repeat(224) + '.' +
    'b'.repeat(224) + '.' + 'c'.repeat(224);
  assert.ok(jwtLike.length > 512);
  let requests = 0;
  const get = async (url,opts) => {
    requests++;
    assert.equal(opts.headers.authorization,'Bearer '+jwtLike);
    return fixtureGet()(url,opts);
  };
  assert.deepEqual(await verifyOwnerGate(args({githubToken:jwtLike,get})),{
    visibleRulesVerified:true,ownerAdminCheckRequired:true,
    model:'OWNER_ONLY_NOT_INDEPENDENT',sha});
  assert.equal(requests,5,'all original metadata GETs, no additional requests');
});
