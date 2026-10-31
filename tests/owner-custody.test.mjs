import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyOwnerGate, REPO, OWNER, ENVIRONMENT} from '../scripts/verify-owner-gate.mjs';

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
      required_status_checks: [{context: 'test'}]}}]};
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
const variation = patch => ({...ruleset, ...patch});

test('owner-only is a labeled, exact-main protected check, not independent review', async () => {
  assert.deepEqual(await verifyOwnerGate(args()), {verified: true,
    model: 'OWNER_ONLY_NOT_INDEPENDENT', sha});
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

test('public main must have an actual active zero-bypass CI/PR ruleset', async () => {
  for (const invalid of [
    {listed: []}, {listed: [{...listed[0], enforcement:'disabled'}]},
    {ruleset: variation({bypass_actors: [{actor_type:'RepositoryRole', actor_id:5}]})},
    {ruleset: variation({conditions: {ref_name:{include:['~ALL'],exclude:[]}}})},
    {ruleset: variation({rules: ruleset.rules.filter(r => r.type !== 'pull_request')})},
    {ruleset: variation({rules: ruleset.rules.filter(r => r.type !== 'non_fast_forward')})},
    {ruleset: variation({rules: ruleset.rules.map(r => r.type === 'pull_request' ?
      {...r,parameters:{...r.parameters,required_approving_review_count: 1}} : r)})},
    {ruleset: variation({rules: ruleset.rules.map(r => r.type === 'required_status_checks' ?
      {...r,parameters:{...r.parameters,required_status_checks:[{context:'untrusted'}]}} : r)})},
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
