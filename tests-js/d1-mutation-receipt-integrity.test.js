'use strict';
// Source-only REST transport negative controls. No real Cloudflare requests.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const child = String.raw`
  const d1 = require('./api/_lib/d1');
  const response = JSON.parse(process.env.CDB_TEST_D1_RESPONSE);
  let requests = 0;
  global.fetch = async (url, options) => {
    requests++;
    if (!url.includes('/d1/database/')) throw Error('Unexpected network target');
    if (options.method !== 'POST') throw Error('Unexpected method');
    return { ok:true, json:async () => response };
  };
  (async () => {
    try {
      const affected = await d1.runMutationWithChanges(
        'UPDATE sample SET value=? WHERE id=?', ['new','case-1']);
      process.stdout.write(JSON.stringify({ok:true,affected,requests}));
    } catch (e) {
      process.stdout.write(JSON.stringify({ok:false,code:e.message,requests}));
    }
  })().catch(e => { process.stderr.write(String(e)); process.exitCode=1; });
`;
function run(result) {
  const env = { ...process.env,
    CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32),
    CLOUDFLARE_D1_DATABASE_ID:'b'.repeat(32),
    CLOUDFLARE_API_TOKEN:'test-only-no-real-credential',
    CDB_TEST_D1_RESPONSE:JSON.stringify({success:true,result})
  };
  const proc = spawnSync(process.execPath, ['-e',child],
    { cwd:root, env, encoding:'utf8', timeout:10000 });
  assert.equal(proc.status,0,proc.stderr);
  return JSON.parse(proc.stdout);
}
const mutation = {success:true,results:[]};
const receipt = affected => ({success:true,results:[{affected}]});

test('accepts a verified zero-row D1 receipt without fabricating a mutation', () => {
  assert.deepEqual(run([mutation,receipt(0)]),{ok:true,affected:0,requests:1});
});
test('accepts a verified one-row D1 receipt', () => {
  assert.deepEqual(run([mutation,receipt(1)]),{ok:true,affected:1,requests:1});
});
test('rejects absent changes() result rather than silently treating it as zero', () => {
  assert.deepEqual(run([mutation]),{ok:false,code:'D1_MUTATION_RECEIPT_UNVERIFIED',requests:1});
});
test('rejects failed mutation even when changes() claims success', () => {
  assert.deepEqual(run([{success:false,results:[]},receipt(1)]),
    {ok:false,code:'D1_MUTATION_RECEIPT_UNVERIFIED',requests:1});
});
test('rejects missing or malformed affected counts', () => {
  for (const value of [undefined,'1',-1,1.5,null]) {
    const result = run([mutation,receipt(value)]);
    assert.equal(result.ok,false,String(value));
    assert.equal(result.code,'D1_MUTATION_RECEIPT_UNVERIFIED');
  }
});
test('rejects ambiguous multi-row changes() receipts', () => {
  assert.deepEqual(run([mutation,{success:true,results:[{affected:1},{affected:0}]}]),
    {ok:false,code:'D1_MUTATION_RECEIPT_UNVERIFIED',requests:1});
});
