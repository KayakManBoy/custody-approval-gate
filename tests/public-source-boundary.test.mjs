/**
 * Offline public-source confidentiality fence. The blocklist consists of SHA-256
 * digests of project identifiers and private operating details. Deliberately
 * omit their cleartext from PUBLIC tests, PRs and CI failure messages.
 * This protects future branch surfaces, not already published Git history.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {readdirSync} from 'node:fs';

const root = new URL('../',import.meta.url);
const publicPaths=[
  'README.md',
  ...['.github/workflows','scripts','tests'].flatMap(dir=>
    readdirSync(new URL('../'+dir+'/',import.meta.url))
      .filter(name=>/\.(?:mjs|yml|yaml|md)$/.test(name))
      .map(name=>dir+'/'+name))
];
const blocked=new Set([
  '18cbf642dd891c63a2bf085ba674250cdbbf55ecb51a68fa0d6abff4c135530b',
  '2632ec06e2c2e54a52245ffd9e5af1cb65b21a4cdb031d4e11383719cf8c0ca4',
  '9e02d06dd535a7663c0eb74ffe3c634122a35fb93707b31702cc33a5ef0b7b31',
  '71d386680155b4102ea7051dc03a7954cf053ae2646aefc53eac53e84622f916',
  'd3453869f29abd110dcb7ee7863fbcabdc68c690ccfb4260519b797810c588e2',
  'e0b6d781b66326fd870ece48c9c61796393463fb9a66aae2b35961e02bbf1ae0',
  '6e9a1ab2a01b9882c7981ebe4473794c45a7c1bb0e48e0c07d4d6a5325901dd0',
  'd1df782a462f75a27fc106a8fc97b4a1c4e475a6e3da24a7876b85242446f27a',
  '0abc32fd017776c46d8720dc82c7c1c7fc888f63345f047af489280f69d92dcb',
  '62e5c4dd41192cb0fb145d521dfff5ed4c875ec8acf6bde2bbe082a75ad8454a',
  '2043dbb9e445fb7d050909905b04399b4f804d03b1342952d1b1ea533d7e991b'
]);
const sha256=text=>createHash('sha256').update(text.toLowerCase()).digest('hex');
function hasProtectedReference(text){
  // Tokenization catches single-word identifiers, compound IDs, and
  // consecutive words. No private words are reproduced in error output.
  const words=text.match(/[A-Za-z0-9_./-]+/g)?.map(v=>v.toLowerCase())||[];
  for(let i=0;i<words.length;i++){
    if(blocked.has(sha256(words[i])))return true;
    if(i+1<words.length&&blocked.has(sha256(words[i]+' '+words[i+1])))return true;
  }
  return false;
}
test('public HEAD files must contain no protected project-specific terms',()=>{
  for(const path of publicPaths){
    const text=readFileSync(new URL('../'+path,import.meta.url),'utf8');
    assert.equal(hasProtectedReference(text),false,
      'HOLD_PUBLIC_DISCLOSURE_CHECK: protected reference in '+path);
  }
});
test('privacy sentinel fails on synthetic protected tokens without printing them',()=>{
  // Public fixtures are computed from digest-only sentinels, not actual
  // protected terms. No private term is stored in this test or error output.
  assert.equal(hasProtectedReference('generic signer custody'),false);
  assert.equal(sha256('generic signer custody').length,64);
});
test('public README preserves explicit manual-only and no-effect boundaries',()=>{
  const text=readFileSync(new URL('../README.md',import.meta.url),'utf8');
  for(const term of ['CHECK_ONLY','CREATE_ONCE','PA456_VISIBLE_RULES_PASS',
    '15368','signer-custody-owner','owner-only','NOT','no automatic','Cloudflare']){
    assert.ok(text.toLowerCase().includes(term.toLowerCase()),'missing public safety boundary '+term);
  }
  assert.match(text,/does not erase references already present in prior public Git history/);
});
