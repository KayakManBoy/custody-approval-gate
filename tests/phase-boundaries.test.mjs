/**
 * PA-457: zero-credential workflow safety tests for both signer execution paths.
 * Every check is on source text. No GitHub environment or Cloudflare API call.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const read = file => readFileSync(new URL('../.github/workflows/' + file, import.meta.url), 'utf8');
const independent = read('one-time.yml');
const owner = read('owner-one-time.yml');
const flows = [
  {name: 'independent', source: independent, environment: 'signer-custody-review',
    checker: 'verify-gate.mjs', marker: 'Recheck independent reviewer protections after approval'},
  {name: 'owner', source: owner, environment: 'signer-custody-owner',
    checker: 'verify-owner-gate.mjs', marker: 'Recheck owner-only GitHub rules after approval'},
];

test('both manual signer variants hold one shared, non-cancelling workflow lock', () => {
  for (const {name, source} of flows) {
    assert.match(source, /^  group: one-time-signing-key-custody$/m, name);
    assert.match(source, /^  cancel-in-progress: false$/m, name);
    assert.equal((source.match(/^  group: /gm) || []).length, 1, name);
    assert.match(source, /^  workflow_dispatch:$/m, name);
    assert.doesNotMatch(source, /^  (push|pull_request|schedule|workflow_run):$/m, name);
  }
  assert.notEqual(flows[0].environment, flows[1].environment,
    'environment approval models must remain distinct');
});

test('inspect stage remains credential-free; create stage has exact environment and minimum read API permissions', () => {
  for (const {name,source,environment} of flows) {
    const [inspect,create] = source.split(/^  create:\s*$/m);
    assert.ok(inspect && create, name);
    assert.doesNotMatch(inspect, /\$\{\{\s*secrets\./, name);
    assert.doesNotMatch(inspect, /^\s+environment:/m, name);
    assert.match(inspect, /actions: read/, name);
    assert.match(create, /needs: inspect/, name);
    assert.match(create, /contents: read/, name);
    assert.match(create, /actions: read/, name);
    assert.match(create, new RegExp('environment: ' + environment), name);
    assert.doesNotMatch(create, /contents: write|actions: write|id-token: write/, name);
    assert.match(source, /github\.run_attempt == 1/g, name);
    assert.equal((source.match(/github\.run_attempt == 1/g) || []).length, 2, name);
  }
});

test('after approval, recheck is before the *only* secret-bearing step', () => {
  for (const {name,source,checker,marker} of flows) {
    const create = source.split(/^  create:\s*$/m)[1];
    assert.ok(create, name);
    const recheckPos = create.indexOf('      - name: ' + marker);
    const provisionPos = create.indexOf('      - name: Create exactly one');
    assert.ok(recheckPos >= 0 && provisionPos > recheckPos, name);
    const recheck = create.slice(recheckPos,provisionPos);
    const provision = create.slice(provisionPos);
    assert.match(recheck, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/, name);
    assert.match(recheck, new RegExp('node --check scripts/' + checker.replaceAll('.', '\\.')), name);
    assert.match(recheck, new RegExp('node scripts/' + checker.replaceAll('.', '\\.')), name);
    assert.doesNotMatch(recheck, /CF_TEMP_EDIT_TOKEN|CF_TARGET_|CF_APPROVED_COMMIT_SHA|secrets\./, name);
    assert.doesNotMatch(recheck, /continue-on-error:\s*true|curl|wrangler|cloudflare\.com|node scripts\/create-once/, name);
    assert.match(provision, /APPROVED_COMMIT_SHA: \$\{\{ secrets\.CF_APPROVED_COMMIT_SHA \}\}/, name);
    assert.match(provision, /CF_TEMP_EDIT_TOKEN: \$\{\{ secrets\.CF_TEMP_EDIT_TOKEN \}\}/, name);
    assert.match(provision, /CF_TARGET_ACCOUNT: \$\{\{ secrets\.CF_TARGET_ACCOUNT \}\}/, name);
    assert.match(provision, /CF_TARGET_STORE: \$\{\{ secrets\.CF_TARGET_STORE \}\}/, name);
    assert.match(provision, /CF_TARGET_SECRET_NAME: \$\{\{ secrets\.CF_TARGET_SECRET_NAME \}\}/, name);
    assert.match(provision, /node --check scripts\/create-once\.mjs/, name);
    assert.match(provision, /node scripts\/create-once\.mjs/, name);
    assert.doesNotMatch(provision, /continue-on-error:\s*true/, name);
    assert.equal((create.match(/node scripts\/create-once\.mjs/g) || []).length, 1, name);
  }
});

test('only the original independent variant requires a separate human', () => {
  assert.match(independent,/environment: signer-custody-review/);
  assert.match(independent,/EXPECTED_REVIEWER: \$\{\{ vars\.INDEPENDENT_REVIEWER_LOGIN \}\}/);
  assert.equal((independent.match(/EXPECTED_REVIEWER:/g)||[]).length,2);
  assert.doesNotMatch(owner, /EXPECTED_REVIEWER:|INDEPENDENT_REVIEWER_LOGIN/);
  assert.match(owner, /environment: signer-custody-owner/);
});

test('workflow triggers cannot silently obtain other provider identities or auto-run', () => {
  for (const {name,source} of flows) {
    assert.match(source, /github\.repository == 'KayakManBoy\/custody-approval-gate'/g,name);
    assert.match(source, /github\.actor == 'KayakManBoy'/g,name);
    assert.match(source, /github\.ref == 'refs\/heads\/main'/g,name);
    assert.match(source, /inputs\.action == 'CREATE_ONCE'/,name);
    assert.match(source, /persist-credentials: false/g,name);
    assert.doesNotMatch(source, /schedule:|workflow_call:|pull_request_target:|repository_dispatch:|oidc|id-token:/,name);
  }
});
