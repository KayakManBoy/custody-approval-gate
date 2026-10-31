/** Generic one-time Secrets Store RSA-2048 bootstrap. No business identifiers in public source. */
import {generateKeyPairSync, createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const hold = code => { throw Error(code); };
const pre = () => hold('HOLD_PREWRITE');
const unknown = () => hold('HOLD_UNKNOWN_WRITE_NO_RETRY');
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const hex32 = x => typeof x === 'string' && /^[a-f0-9]{32}$/.test(x);
const bytes = x => typeof x === 'string' && /^[a-f0-9]{40}$/.test(x);

async function fetchJSON(fetchFn, url, init, failure, shape = 'array') {
  let r;
  try { r = await fetchFn(url, {...init, redirect: 'manual', signal: AbortSignal.timeout(10000)}); }
  catch { failure(); }
  if (!r || r.status !== 200 || r.ok !== true || r.url !== url) failure();
  let body;
  try { body = await r.text(); } catch { failure(); }
  if (typeof body !== 'string' || body.length > 32768) failure();
  let obj;
  try { obj = JSON.parse(body); } catch { failure(); }
  if (!plain(obj) || obj.success !== true || !Array.isArray(obj.errors) || obj.errors.length ||
    !(shape === 'object' ? plain(obj.result) : Array.isArray(obj.result))) failure();
  return obj;
}


/**
 * Account-scoped token validity prewrite fence. Cloudflare's token-verify GET
 * returns status, expires_on and optional not_before; never returns privileges.
 * A narrow active expiration is necessary but NOT evidence of narrow IAM scope.
 * No access to secret values or authority to create any token is requested.
 */
export async function verifyTokenLifetime({fetchFn = fetch, account, token,
  nowMs = Date.now()} = {}) {
  if (!hex32(account) || typeof token !== 'string' ||
    !/^[A-Za-z0-9_-]{30,512}$/.test(token) || !Number.isSafeInteger(nowMs) ||
    nowMs <= 0 || typeof fetchFn !== 'function') pre();
  const url = 'https://api.cloudflare.com/client/v4/accounts/' + account + '/tokens/verify';
  const verified = await fetchJSON(fetchFn, url, {method:'GET',
    headers:{authorization:'Bearer ' + token, accept:'application/json'}}, pre, 'object');
  const record = verified.result;
  if (!hex32(record.id) || record.status !== 'active' ||
    typeof record.expires_on !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(record.expires_on)) pre();
  const expires = Date.parse(record.expires_on);
  // Reject missing, expired and long-lived authority; preserve at least
  // two minutes for a bounded write and no more than one hour of exposure.
  if (!Number.isFinite(expires) || expires - nowMs < 120000 ||
    expires - nowMs > 3600000) pre();
  if (record.not_before !== undefined && record.not_before !== null) {
    if (typeof record.not_before !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(record.not_before)) pre();
    const starts = Date.parse(record.not_before);
    if (!Number.isFinite(starts) || starts > nowMs) pre();
  }
  return Object.freeze({active: true, boundedExpiration: true});
}

function makeKey() {
  const pair = generateKeyPairSync('rsa', {modulusLength: 2048, publicExponent: 65537});
  const jwk = pair.publicKey.export({format: 'jwk'});
  if (jwk.kty !== 'RSA' || jwk.e !== 'AQAB' || typeof jwk.n !== 'string' ||
    jwk.n.length < 342 || jwk.n.length > 683) pre();
  const message = Buffer.from('ONE-TIME-SIGNER-CUSTODY-CHECK');
  if (!verify('RSA-SHA256', message, pair.publicKey,
    sign('RSA-SHA256', message, pair.privateKey))) pre();
  const publicJwk = {kty: 'RSA', n: jwk.n, e: 'AQAB', alg: 'RS256', key_ops: ['verify'], ext: true};
  const fingerprint = createHash('sha256').update(JSON.stringify({kty: 'RSA', n: jwk.n, e: 'AQAB'})).digest('hex');
  const pkcs8 = pair.privateKey.export({format: 'der', type: 'pkcs8'});
  try { return {secret: pkcs8.toString('base64url'), publicJwk, fingerprint,
    kid: 'rs256-' + fingerprint.slice(0,20)}; }
  finally { pkcs8.fill(0); }
}


/**
 * Defense in depth: the advertised public receipt must cryptographically
 * correspond to the EXACT PKCS8 bytes about to be sent to Cloudflare.
 * Bad encodings, inconsistent kid/fingerprint, wrong key or algorithm HOLD.
 * No secret, key, account identifier or source bytes are logged.
 */
export function verifyPrewriteKeyMaterial(key) {
  if (!plain(key) || !plain(key.publicJwk) ||
    typeof key.secret !== 'string' || key.secret.length < 1000 ||
    key.secret.length > 8192 || !/^[A-Za-z0-9_-]+$/.test(key.secret) ||
    Object.keys(key.publicJwk).sort().join(',') !== 'alg,e,ext,key_ops,kty,n' ||
    key.publicJwk.kty !== 'RSA' || key.publicJwk.e !== 'AQAB' ||
    key.publicJwk.alg !== 'RS256' || key.publicJwk.ext !== true ||
    !Array.isArray(key.publicJwk.key_ops) ||
    key.publicJwk.key_ops.length !== 1 || key.publicJwk.key_ops[0] !== 'verify' ||
    typeof key.publicJwk.n !== 'string' ||
    !/^[A-Za-z0-9_-]{342,683}$/.test(key.publicJwk.n) ||
    typeof key.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(key.fingerprint) ||
    typeof key.kid !== 'string' || !/^rs256-[a-f0-9]{20}$/.test(key.kid)) pre();
  let der;
  try {
    der = Buffer.from(key.secret, 'base64url');
    if (der.byteLength < 900 || der.toString('base64url') !== key.secret) pre();
    const privateKey = createPrivateKey({key: der, format: 'der', type: 'pkcs8'});
    // Some DER decoders accept trailing bytes or noncanonical encodings.
    // Re-export the canonical PKCS8 and require exact equality with input.
    // This also ensures the public receipt corresponds to precise POST bytes.
    let canonical;
    try {
      canonical = privateKey.export({format:'der',type:'pkcs8'});
      if (!canonical.equals(der)) pre();
    } finally { if (canonical) canonical.fill(0); }
    if (privateKey.asymmetricKeyType !== 'rsa' ||
      privateKey.asymmetricKeyDetails?.modulusLength !== 2048 ||
      privateKey.asymmetricKeyDetails?.publicExponent !== 65537n) pre();
    const derived = createPublicKey(privateKey).export({format: 'jwk'});
    if (!plain(derived) || derived.kty !== 'RSA' || derived.e !== 'AQAB' ||
      derived.n !== key.publicJwk.n) pre();
    const fingerprint = createHash('sha256').update(JSON.stringify({
      kty:'RSA', n:derived.n, e:'AQAB'})).digest('hex');
    if (key.fingerprint !== fingerprint ||
      key.kid !== 'rs256-' + fingerprint.slice(0,20)) pre();
    const advertised = createPublicKey({key:key.publicJwk, format:'jwk'});
    const challenge = Buffer.from('PA461-PREWRITE-KEY-RECEIPT-PAIR-CHECK');
    if (!verify('RSA-SHA256',challenge,advertised,
      sign('RSA-SHA256',challenge,privateKey))) pre();
    return true;
  } catch { pre(); }
  finally { if (der) der.fill(0); }
}

export async function createOnce({repo, actor, ref, sha, approvedSha, runAttempt = 1, action, token,
  account, store, secretName, fetchFn = fetch, generator = makeKey,
  tokenVerifier = verifyTokenLifetime, nowMs = Date.now()} = {}) {
  if (repo !== 'KayakManBoy/custody-approval-gate' || actor !== 'KayakManBoy' ||
    ref !== 'refs/heads/main' || runAttempt !== 1 || action !== 'CREATE_ONCE' || !bytes(sha) ||
    sha !== approvedSha || !hex32(account) || !hex32(store) ||
    typeof secretName !== 'string' || !/^[A-Z][A-Z0-9_]{4,80}$/.test(secretName) ||
    typeof token !== 'string' || !/^[A-Za-z0-9_-]{30,512}$/.test(token) ||
    typeof fetchFn !== 'function' || typeof generator !== 'function' ||
    typeof tokenVerifier !== 'function' || !Number.isSafeInteger(nowMs) || nowMs <= 0) pre();
  const endpoint = 'https://api.cloudflare.com/client/v4/accounts/' + account +
    '/secrets_store/stores/' + store + '/secrets';
  const list = endpoint + '?per_page=100&page=1';
  const auth = {authorization: 'Bearer ' + token, accept: 'application/json'};
  // Verify the short-lived account token BEFORE inventory, key generation,
  // or any possible account-wide Secrets Store mutation.
  try { await tokenVerifier({fetchFn, account, token, nowMs}); } catch { pre(); }
  let listing;
  try { listing = await fetchJSON(fetchFn, list, {method: 'GET', headers: auth}, pre); } catch { pre(); }
  const info = listing.result_info;
  // An incomplete inventory must NEVER be interpreted as a missing key.
  if (!plain(info) || info.page !== 1 || info.total_pages !== 1 ||
    !Number.isSafeInteger(info.total_count) ||
    info.total_count !== listing.result.length ||
    !Number.isSafeInteger(info.count) ||
    info.count !== listing.result.length ||
    listing.result.length > 100 || listing.result.some(x => !plain(x) ||
      !hex32(x.id) || x.store_id !== store ||
      !['active','pending','deleted'].includes(x.status) ||
      typeof x.name !== 'string' || !/^[A-Z][A-Z0-9_]{4,80}$/.test(x.name) ||
      x.name === secretName || Object.hasOwn(x,'value'))) pre();
  let key;
  try { key = generator(); } catch { pre(); }
  // Cross-check the exact DER and independently derive the receipt before POST.
  verifyPrewriteKeyMaterial(key);
  // No automatic retry after this point. An uncertain write must be independently read back.
  let created;
  try {
    created = await fetchJSON(fetchFn, endpoint, {method: 'POST',
      headers: {...auth, 'content-type': 'application/json'},
      body: JSON.stringify([{name: secretName, value: key.secret, scopes: ['workers'],
        comment: 'One-time protected private issuer signer'}])}, unknown);
  } catch { unknown(); }
  const record = created.result;
  if (record.length !== 1 || !plain(record[0]) || record[0].name !== secretName ||
    record[0].store_id !== store || !hex32(record[0].id) ||
    !['pending','active'].includes(record[0].status) ||
    !Array.isArray(record[0].scopes) || record[0].scopes.join() !== 'workers' ||
    Object.hasOwn(record[0], 'value')) unknown();
  return Object.freeze({created: true, status: record[0].status, publicJwk: key.publicJwk,
    kid: key.kid, fingerprint: key.fingerprint});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await createOnce({repo: process.env.GITHUB_REPOSITORY,
      actor: process.env.GITHUB_ACTOR, ref: process.env.GITHUB_REF,
      sha: process.env.GITHUB_SHA, approvedSha: process.env.APPROVED_COMMIT_SHA,
      runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
      action: process.env.CUSTODY_ACTION, token: process.env.CF_TEMP_EDIT_TOKEN,
      account: process.env.CF_TARGET_ACCOUNT, store: process.env.CF_TARGET_STORE,
      secretName: process.env.CF_TARGET_SECRET_NAME});
    // Public verification key is not secret; avoid publishing private account/store/name/token.
    process.stdout.write('CREATE_ACCEPTED_PUBLIC_KEY_RECEIPT_FOLLOWS_READBACK_REQUIRED\n');
    process.stdout.write(JSON.stringify({status: result.status, kid: result.kid,
      fingerprint: result.fingerprint, publicJwk: result.publicJwk}) + '\n');
  } catch {
    process.stderr.write('HOLD_CUSTODY_NO_RETRY_INDEPENDENT_READBACK_REQUIRED\n');
    process.exitCode = 1;
  }
}
