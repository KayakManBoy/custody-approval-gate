import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createOnce,verifyPrewriteKeyMaterial} from '../scripts/create-once.mjs';

const pair=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
const jwk=pair.publicKey.export({format:'jwk'});
const jwkPublic={kty:'RSA',n:jwk.n,e:'AQAB',alg:'RS256',key_ops:['verify'],ext:true};
const fingerprint=createHash('sha256').update(
  JSON.stringify({kty:'RSA',n:jwk.n,e:'AQAB'})).digest('hex');
const key={secret:pair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64url'),
  publicJwk:jwkPublic,fingerprint,kid:'rs256-'+fingerprint.slice(0,20)};
const store='b'.repeat(32),account='a'.repeat(32),name='ISSUER_SIGNING_KEY';
const inventory={success:true,errors:[],result:[{id:'d'.repeat(32),
  name:'UNRELATED_SAFE_ENTRY',store_id:store,status:'active',scopes:['workers']}],
  result_info:{page:1,total_pages:1,count:1,total_count:1}};
const created={success:true,errors:[],result:[{id:'c'.repeat(32),store_id:store,
  name,status:'active',scopes:['workers']}]};
const response=(url,value)=>({url,status:200,ok:true,text:async()=>JSON.stringify(value)});
const args=(other={})=>({
  repo:'KayakManBoy/custody-approval-gate',actor:'KayakManBoy',ref:'refs/heads/main',
  sha:'f'.repeat(40),approvedSha:'f'.repeat(40),runAttempt:1,action:'CREATE_ONCE',
  account,store,secretName:name,token:'t'.repeat(40),
  tokenVerifier:async()=>({active:true,boundedExpiration:true}),nowMs:1793450000000,
  ...other});

test('independent prewrite verification proves exact DER/JWK/fingerprint/kid pairing',()=>{
  assert.equal(verifyPrewriteKeyMaterial(key),true);
  assert.deepEqual(Object.keys(key.publicJwk).sort(),['alg','e','ext','key_ops','kty','n']);
});

test('unexpected generator outputs never reach Cloudflare POST',async()=>{
  const other=generateKeyPairSync('rsa',{modulusLength:2048}).publicKey.export({format:'jwk'});
  const modifications=[
    {...key,secret:'A'+key.secret.slice(1)}, // DER SEQUENCE tag is corrupted
    {...key,secret:Buffer.concat([Buffer.from(key.secret,'base64url'),
      Buffer.from([0x00,0x00])]).toString('base64url')}, // trailing DER bytes
    {...key,secret:'-----BEGIN PRIVATE KEY-----'},
    {...key,publicJwk:{...jwkPublic,n:other.n}},
    {...key,publicJwk:{...jwkPublic,alg:'RS512'}},
    {...key,publicJwk:{...jwkPublic,key_ops:['sign']}},
    {...key,publicJwk:{...jwkPublic,ext:false}},
    {...key,publicJwk:{...jwkPublic,unexpected:true}},
    {...key,fingerprint:'0'.repeat(64)},
    {...key,kid:'rs256-'+'0'.repeat(20)},
    {...key,secret:key.secret+'='},
    {...key,publicJwk:{...jwkPublic,e:'Aw'}},
  ];
  for(const invalid of modifications) {
    assert.throws(()=>verifyPrewriteKeyMaterial(invalid),/HOLD_PREWRITE/);
    let requests=0;
    await assert.rejects(()=>createOnce(args({
      generator:()=>invalid,
      fetchFn:async url=>{requests++;return response(url,inventory);}
    })),/HOLD_PREWRITE/);
    assert.equal(requests,1,'only the prewrite inventory GET, never POST');
  }
});

test('verified synthetic DER/JWK receipt reaches exactly one modeled POST, no private receipt leak',async()=>{
  let requests=0,payload;
  const fetchFn=async(url,init)=>{
    requests++;
    if(init.method==='GET'){
      assert.equal(requests,1);
      return response(url,inventory);
    }
    assert.equal(init.method,'POST');
    assert.equal(requests,2);
    payload=JSON.parse(init.body);
    return response(url,created);
  };
  const result=await createOnce(args({generator:()=>key,fetchFn}));
  assert.equal(requests,2);
  assert.equal(payload.length,1);
  assert.equal(payload[0].value,key.secret);
  assert.deepEqual(result.publicJwk,key.publicJwk);
  assert.equal(result.kid,key.kid);
  assert.equal(result.fingerprint,key.fingerprint);
  assert.doesNotMatch(JSON.stringify(result),new RegExp(key.secret.slice(0,40)));
});
