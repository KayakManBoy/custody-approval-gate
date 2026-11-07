/** PA-690 non-writing owner-only configuration stage regression. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyCustodyConfiguration,createOnce} from '../scripts/create-once.mjs';

const sha='a'.repeat(40),account='b'.repeat(32),store='c'.repeat(32);
const args={repo:'KayakManBoy/custody-approval-gate',actor:'KayakManBoy',
  ref:'refs/heads/main',sha,approvedSha:sha,runAttempt:1,
  action:'CHECK_CONFIG_ONLY',account,store,secretName:'TEST_SIGNER_KEY'};

test('non-writing config check validates exact owner/ref/SHA and structural shapes',()=>{
  assert.deepEqual(verifyCustodyConfiguration(args),{
    shapeVerified:true,manualTargetVerificationRequired:true});
  for(const [key,value,stage] of [
    ['repo','not/owner','CONFIG_CONTEXT'],['actor','other','CONFIG_CONTEXT'],
    ['ref','refs/tags/v2','CONFIG_CONTEXT'],['runAttempt',2,'CONFIG_CONTEXT'],
    ['action','CREATE_ONCE','CONFIG_CONTEXT'],
    ['approvedSha','f'.repeat(40),'CONFIG_COMMIT'],
    ['account','wrong','CONFIG_ACCOUNT'],['store','','CONFIG_STORE'],
    ['secretName','NOT-A-NAME','CONFIG_SECRET_NAME']
  ]){
    assert.throws(()=>verifyCustodyConfiguration({...args,[key]:value}),e=>{
      assert.equal(e.message,'HOLD_PREWRITE');assert.equal(e.stage,stage);return true;
    });
  }
});

test('create requires temporary token and fails before any network',async()=>{
  let calls=0;
  await assert.rejects(()=>createOnce({...args,action:'CREATE_ONCE',
    token:undefined,fetchFn:async()=>{calls++;throw Error('unreachable');}}),
    e=>e.message==='HOLD_PREWRITE'&&e.stage==='CONFIG_TOKEN');
  assert.equal(calls,0);
});

test('owner config-only job has no token, provider calls, write permissions or triggers',()=>{
  const flow=readFileSync(new URL('../.github/workflows/owner-one-time.yml',import.meta.url),'utf8');
  const lane=flow.split(/^  config_check:\s*$/m)[1];
  assert.ok(lane);assert.match(lane,/needs: inspect/);
  assert.match(lane,/environment: signer-custody-owner/);
  assert.match(lane,/inputs.action == 'CHECK_CONFIG_ONLY'/);
  assert.match(lane,/github.run_attempt == 1/);
  assert.match(lane,/node scripts\/config-only.mjs/);
  assert.doesNotMatch(lane,/CF_TEMP_EDIT_TOKEN|create-once.mjs|contents: write|curl|wrangler|cloudflare.com/);
  assert.doesNotMatch(flow,/^  (push|schedule|pull_request|workflow_run):/m);
  const source=readFileSync(new URL('../scripts/config-only.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source,/fetch\(|https:|POST|CF_TEMP_EDIT_TOKEN|process\.env\.CF_TEMP_EDIT_TOKEN/);
});

test('create error stages are fixed, no raw token or upstream error text',()=>{
  const s=readFileSync(new URL('../scripts/create-once.mjs',import.meta.url),'utf8');
  assert.match(s,/HOLD_CUSTODY_NO_RETRY_INDEPENDENT_READBACK_REQUIRED stage=/);
  assert.match(s,/POST_UNKNOWN/);
  assert.doesNotMatch(s,/process\.stderr\.write\(error\.message\)/);
  assert.doesNotMatch(s,/process\.stderr\.write\(JSON\.stringify\(error\)/);
});
