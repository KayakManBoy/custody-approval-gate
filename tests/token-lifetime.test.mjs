import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyTokenLifetime, createOnce} from '../scripts/create-once.mjs';

const nowMs = Date.parse('2026-10-31T15:00:00Z');
const account = 'a'.repeat(32), store = 'b'.repeat(32);
const token = 't'.repeat(40);
const verifyURL = 'https://api.cloudflare.com/client/v4/accounts/' + account + '/tokens/verify';
const expires = minutes => new Date(nowMs + minutes * 60000).toISOString().replace('.000Z','Z');
const valid = {success:true, errors:[],result:{
  id:'f'.repeat(32), status:'active',expires_on:expires(20),
  not_before:expires(-20)}};
const response=(url,body,status=200)=>({url,status,ok:status===200,
  text:async()=>JSON.stringify(body)});
const get = (body=valid,status=200) => async(url,init)=>{
  assert.equal(url,verifyURL);
  assert.equal(init.method,'GET');
  assert.equal(init.redirect,'manual');
  assert.equal(init.headers.authorization,'Bearer '+token);
  return response(url,body,status);
};
const args=(other={})=>({account,token,nowMs,fetchFn:get(),...other});

test('fixed account-only verification returns sanitized fact and no token identifier',async()=>{
  assert.deepEqual(await verifyTokenLifetime(args()),{
    active:true,boundedExpiration:true});
});

test('bounded UTC RFC3339 fractional precision is accepted',async()=>{
  for(const fraction of ['.123','.123456','.123456789']){
    const body={...valid,result:{...valid.result,
      expires_on:expires(20).replace('Z',fraction+'Z'),
      not_before:expires(-20).replace('Z',fraction+'Z')}};
    assert.deepEqual(await verifyTokenLifetime(args({fetchFn:get(body)})),
      {active:true,boundedExpiration:true});
  }
});

test('bounded active expiry is mandatory; no long-lived or missing validity',async()=>{
  for(const record of [
    {status:'disabled'}, {status:'expired'},
    {expires_on:undefined}, {expires_on:expires(1)},
    {expires_on:expires(61)}, {expires_on:expires(-2)},
    {expires_on:'2026-02-30T00:00:00Z'}, {expires_on:'tomorrow'},
    {expires_on:expires(20).replace('Z','.1234567890Z')},
    {not_before:expires(21)},{not_before:'bad'},
    {id:'not-a-token-id'}
  ]) {
    await assert.rejects(()=>verifyTokenLifetime(args({
      fetchFn:get({...valid,result:{...valid.result,...record}})
    })),/HOLD_PREWRITE/);
  }
});

test('token verification denies 401/429, redirects, missing success and invalid JSON',async()=>{
  for(const other of [
    {fetchFn:get(valid,401)}, {fetchFn:get(valid,429)},
    {fetchFn:async url=>response(url+'/redirect',valid)},
    {fetchFn:async url=>({url,status:200,ok:true,text:async()=>'{bad'})},
    {fetchFn:get({...valid,success:false})},
    {fetchFn:get({...valid,errors:[{code:1000}]})},
    {fetchFn:async()=>{throw Error('offline')}},
    {account:'wrong'}, {token:''},
    {nowMs:NaN}
  ]) await assert.rejects(()=>verifyTokenLifetime(args(other)),/HOLD_PREWRITE/);
});

test('production createOnce checks real token verifier before inventory, key generation or POST',async()=>{
  let calls=0,generations=0;
  const fetchFn=async(url,init)=>{
    calls++;
    assert.equal(calls,1,'no inventory or POST on failed verification');
    assert.equal(url,verifyURL);
    assert.equal(init.method,'GET');
    return response(url,{...valid,result:{...valid.result,expires_on:expires(90)}});
  };
  await assert.rejects(()=>createOnce({
    repo:'KayakManBoy/custody-approval-gate',actor:'KayakManBoy',ref:'refs/heads/main',
    sha:'c'.repeat(40),approvedSha:'c'.repeat(40),runAttempt:1,action:'CREATE_ONCE',
    token,account,store,secretName:'ISSUER_SIGNING_KEY',nowMs,
    fetchFn,generator:()=>{generations++;throw Error('must not generate');}
  }),/HOLD_PREWRITE/);
  assert.equal(calls,1);
  assert.equal(generations,0);
});
