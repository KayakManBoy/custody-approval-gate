import test from 'node:test';
import assert from 'node:assert/strict';
import {isHeaderSafeGitHubToken} from '../scripts/github-token.mjs';

test('HTTP-header safety works for short and long opaque GitHub installation JWTs',()=>{
  const jwt='ghs_15368_'+('a'.repeat(240))+'.'+('b'.repeat(240))+'.'+('c'.repeat(240));
  assert.ok(jwt.length>512);
  for (const value of ['ghs_'+'a'.repeat(36),jwt,'opaque:synthetic+~bearer/=']) {
    assert.equal(isHeaderSafeGitHubToken(value),true);
  }
});
test('HTTP header control, whitespace, Unicode and missing tokens fail closed',()=>{
  for(const value of ['',null,undefined,3,{},' abc','abc ','abc\rdef',
    'abc\ndef','abc\tdef','abc\u007fdef','abc\u00e9def']){
    assert.equal(isHeaderSafeGitHubToken(value),false);
  }
});
