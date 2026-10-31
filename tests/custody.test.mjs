import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {verifyGate, REPO, OWNER, ENVIRONMENT} from '../scripts/verify-gate.mjs';
import {createOnce} from '../scripts/create-once.mjs';
import {readFileSync} from 'node:fs';

const githubToken = 'ghs_' + 't'.repeat(32);
const reviewer = 'IndependentReviewer';
const approvedSha = 'a'.repeat(40);
const account = 'b'.repeat(32), store = 'c'.repeat(32), name = 'ISSUER_SIGNING_KEY';
const goodEnvironment = {name: ENVIRONMENT,
  deployment_branch_policy: {protected_branches: false, custom_branch_policies: true},
  protection_rules: [
    {type: 'branch_policy'},
    {type: 'required_reviewers', prevent_self_review: true,
      reviewers: [{type: 'User', reviewer: {login: reviewer}}]}
  ]};
const policies = {total_count: 1, branch_policies: [{name: 'main', type: 'branch'}]};
const response = (url, body, status = 200) => ({url, status, ok: status === 200,
  text: async () => JSON.stringify(body)});
const githubAPI = (e = goodEnvironment, b = policies, status = 200) => async (url, opts) => {
  assert.equal(opts.method, 'GET');
  assert.equal(opts.redirect, 'manual');
  return response(url, url.includes('deployment-branch-policies') ? b : e, status);
};
const verification = overrides => ({repository: REPO, actor: OWNER, ref: 'refs/heads/main',
  expectedReviewer: reviewer, githubToken, get: githubAPI(), ...overrides});

test('review gate accepts only independent reviewer/main-only rule', async () => {
  assert.deepEqual(await verifyGate(verification()), {verified: true});
});
test('review gate rejects false authority, self-review and deployment policy drift', async () => {
  for (const overrides of [
    {repository: 'not/trusted'}, {actor: 'stranger'}, {ref: 'refs/heads/test'},
    {expectedReviewer: OWNER}, {expectedReviewer: ''}, {githubToken: ''},
    {get: githubAPI({...goodEnvironment, protection_rules: [{type:'branch_policy'}]})},
    {get: githubAPI({...goodEnvironment, protection_rules: [goodEnvironment.protection_rules[0],
      {...goodEnvironment.protection_rules[1], prevent_self_review: false}]})},
    {get: githubAPI({...goodEnvironment, protection_rules: [goodEnvironment.protection_rules[0],
      {...goodEnvironment.protection_rules[1], reviewers: [{type: 'User', reviewer: {login: OWNER}}]}]})},
    {get: githubAPI(goodEnvironment, {total_count: 1, branch_policies: [{name: '*'}]})},
    {get: githubAPI(goodEnvironment, {total_count: 2, branch_policies: [{name: 'main'}, {name: 'dev'}]})},
    {get: githubAPI(goodEnvironment, policies, 403)},
    {get: async url => response(url + '/redirect', goodEnvironment)}
  ]) {
    await assert.rejects(() => verifyGate(verification(overrides)), /HOLD_CUSTODY_REVIEW_UNVERIFIED/);
  }
});

const inventory = {success: true, errors: [], result: [{name: 'UNRELATED_SAFE_ENTRY'}], result_info: {total_pages: 1}};
const created = {success: true, errors: [], result: [{name, store_id: store,
  id: 'd'.repeat(32), status: 'active', scopes: ['workers']}]};
const base = extra => ({repo: REPO, actor: OWNER, ref: 'refs/heads/main', sha: approvedSha,
  approvedSha, action: 'CREATE_ONCE', token: 't'.repeat(40), account, store,
  secretName: name, ...extra});

test('one-shot creates only the designated secret and generated private key never enters receipt', async () => {
  let calls = 0;
  let posted = null;
  const fetchFn = async (url, init) => {
    calls++;
    assert.equal(init.redirect, 'manual');
    assert.ok(url.includes(account));
    assert.ok(url.includes(store));
    if (calls === 1) {
      assert.equal(init.method, 'GET');
      return response(url, inventory);
    }
    assert.equal(calls, 2);
    assert.equal(init.method, 'POST');
    posted = JSON.parse(init.body);
    return response(url, created);
  };
  const result = await createOnce(base({fetchFn}));
  assert.equal(calls, 2);
  assert.equal(result.created, true);
  assert.equal(posted.length, 1);
  assert.deepEqual([posted[0].name, posted[0].scopes], [name, ['workers']]);
  const pkcs8 = Buffer.from(posted[0].value, 'base64url');
  const priv = createPrivateKey({key: pkcs8, format: 'der', type: 'pkcs8'});
  const pub = createPublicKey({key: result.publicJwk, format: 'jwk'});
  const challenge = Buffer.from('LOCAL-FIXTURE');
  assert.ok(verify('RSA-SHA256', challenge, pub, sign('RSA-SHA256', challenge, priv)));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(posted[0].value.slice(0,64)));
  assert.equal(result.publicJwk.alg, 'RS256');
  assert.match(result.fingerprint, /^[a-f0-9]{64}$/);
});

test('before a write, mismatched SHA, owner, mode, target and inventory fail closed', async () => {
  for (const modification of [
    {sha: 'e'.repeat(40)}, {approvedSha: 'f'.repeat(40)}, {actor: 'intruder'},
    {repo: 'other/repo'}, {ref: 'refs/tags/v1'}, {runAttempt: 2},
    {runAttempt: 0}, {action: 'CHECK_ONLY'},
    {token: ''}, {account: 'wrong'}, {store: ''}, {secretName: 'BAD-path'},
  ]) {
    let calls = 0;
    await assert.rejects(() => createOnce(base({...modification,
      fetchFn: async () => {calls++; throw Error('NEVER');}})), /HOLD_PREWRITE/);
    assert.equal(calls, 0);
  }
  for (const bad of [
    {...inventory, result: [{name}]}, {...inventory, result_info: {total_pages: 2}},
    {...inventory, errors: ['bad']}, {...inventory, result: []},
  ]) {
    if (bad.result.length === 0 && bad.result_info.total_pages === 1 && !bad.errors.length) continue;
    let count = 0;
    await assert.rejects(() => createOnce(base({fetchFn: async url => {
      count++; return response(url, bad);
    }})), /HOLD_PREWRITE/);
    assert.equal(count, 1);
  }
});

test('uncertain POST never retries, including non-200 or unexpected response', async () => {
  for (const failure of ['throw', '500', 'bad']) {
    let calls = 0;
    await assert.rejects(() => createOnce(base({fetchFn: async url => {
      calls++;
      if (calls === 1) return response(url, inventory);
      if (failure === 'throw') throw Error('ambiguous network');
      return response(url, failure === 'bad' ? {...created, result: [{...created.result[0], name: 'WRONG'}]} : created,
        failure === '500' ? 500 : 200);
    }})), /HOLD_UNKNOWN_WRITE_NO_RETRY/);
    assert.equal(calls, 2);
  }
});

test('public workflow is manual-only and keeps Cloudflare secrets out of unprivileged preflight', () => {
  const source = readFileSync(new URL('../.github/workflows/one-time.yml', import.meta.url), 'utf8');
  assert.match(source, /workflow_dispatch:/);
  assert.doesNotMatch(source, /^\s+(push|pull_request|schedule|workflow_run):/m);
  assert.match(source, /environment: signer-custody-review/);
  assert.match(source, /needs: inspect/);
  assert.match(source, /action == 'CREATE_ONCE'/);
  assert.match(source, /secrets\.CF_TEMP_EDIT_TOKEN/);
  const preflight = source.split('  create:\n')[0];
  assert.doesNotMatch(preflight, /secrets\./);
  assert.doesNotMatch(preflight, /environment:/);
  assert.match(preflight, /actions: read/);
  assert.doesNotMatch(source, /permissions:\s*\n\s*contents: write/);
});
