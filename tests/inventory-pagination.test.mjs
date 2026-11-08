/** PA-696: synthetic, credential-free Cloudflare inventory completeness tests. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyCompleteInventory, createOnce} from '../scripts/create-once.mjs';

const store='b'.repeat(32), account='c'.repeat(32), name='NEW_SIGNER_KEY';
const entry={id:'d'.repeat(32), store_id:store, name:'UNRELATED_SAFE_KEY',
  status:'active', scopes:['workers']};
const base=info=>({success:true, errors:[], result:[entry], result_info:info});
const full={page:1,per_page:100,count:1,total_count:1,total_pages:1};
const verify=info=>verifyCompleteInventory(base(info),{store,secretName:name});
const fails=(listing,stage)=>assert.throws(
  ()=>verifyCompleteInventory(listing,{store,secretName:name}),
  error=>error.message==='HOLD_PREWRITE' && error.stage===stage &&
    !String(error).includes(store) && !String(error).includes(name));

test('full page and documented optional metadata omissions are safe only with completeness proof',()=>{
  for(const info of [
    full,
    {page:1,total_count:1},
    {page:1,total_pages:1},
    {page:1,count:1,total_pages:1},
    {page:1,per_page:100,total_count:1},
    {page:1,total_pages:1,total_count:1}
  ]) assert.deepEqual(verify(info),{complete:true});
});

test('optional does not mean unproven completeness; fail closed on missing or contradicted proof',()=>{
  for(const info of [
    undefined,null,{}, {page:1},{page:1,count:1},{page:1,per_page:100},
    {page:1,total_count:1,total_pages:2},
    {page:1,total_pages:1,total_count:2},
    {page:1,total_count:1,count:2},
    {page:1,total_pages:1,per_page:0},
    {page:1,total_pages:1,per_page:101},
    {page:1,total_pages:1,per_page:0.5},
    {page:2,total_count:1},
    {page:0,total_pages:1}
  ]) assert.throws(()=>verify(info),/HOLD_PREWRITE/);
  fails(base({page:1}),'INVENTORY_COMPLETENESS');
  fails(base({page:1,total_count:2}),'INVENTORY_COUNT');
  fails(base({page:1,total_pages:2}),'INVENTORY_PAGE');
  fails(base(null),'INVENTORY_PAGE');
});

test('complete page cannot hide an existing, tombstoned or malformed target',()=>{
  for(const status of ['active','pending','deleted']){
    fails({...base(full),result:[{...entry,name,status}]},'INVENTORY_TARGET_PRESENT');
  }
  for(const bad of [
    {...entry,id:'not-hex'},
    {...entry,store_id:'e'.repeat(32)},
    {...entry,status:'unknown'},
    {...entry,name:'bad name'},
    {...entry,value:'private'},
    null
  ]) fails({...base(full),result:[bad]},'INVENTORY_RECORD');
  fails({...base(full),result:[entry,entry]},'INVENTORY_COUNT');
});

test('unproven pagination prevents key generation and POST, without any automatic retry',async()=>{
  let calls=0,generated=0;
  const fetchFn=async (url, init)=>{
    calls++;
    assert.equal(init.method,'GET');
    assert.equal(init.redirect,'manual');
    return {url,ok:true,status:200,text:async()=>JSON.stringify(base({page:1,count:1}))};
  };
  await assert.rejects(()=>createOnce({
    repo:'KayakManBoy/custody-approval-gate',actor:'KayakManBoy',ref:'refs/heads/main',
    sha:'a'.repeat(40),approvedSha:'a'.repeat(40),runAttempt:1,
    action:'CREATE_ONCE',token:'t'.repeat(40),account,store,secretName:name,
    tokenVerifier:async()=>({active:true,boundedExpiration:true}),
    generator:()=>{generated++;throw Error('must not generate');}, fetchFn
  }),e=>e.message==='HOLD_PREWRITE'&&e.stage==='INVENTORY_COMPLETENESS');
  assert.equal(calls,1);
  assert.equal(generated,0);
});
