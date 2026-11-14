'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(root,'fetch-live-intel.js'),'utf8');
const start=source.indexOf('async function fetchPacketStorm(state) {');
const end=source.indexOf('\nasync function fetchFullDisclosure',start);
assert(start>=0&&end>start,'Packet Storm source boundary must remain explicit');
const body=source.slice(start,end);

test('P0 no unlicensed Packet Storm public RSS, TLS bypass or invented publication date',()=>{
  assert.match(body,/PACKETSTORM_COMMERCIAL_API_REQUIRED/);
  assert.doesNotMatch(body,/fetchWithRetry|fetchUrl|https?\.get|https?\.request|process\.env\.NODE_TLS_REJECT_UNAUTHORIZED/);
  assert.doesNotMatch(source,/packetstormRss\s*:/);
  assert.doesNotMatch(body,/isoNow\(|lastFetch|setSourceLastFetch/);
});

test('P0 Packet Storm source failure is explicit and cannot be counted as a successful empty feed',async()=>{
  const errors=[],context=vm.createContext({
    Error,warn:message=>errors.push(message),
    // If an adapter ever attempts to invoke a new network helper, tests
    // deliberately offer no such API.
  });
  vm.runInContext(body,context,{timeout:1000});
  await assert.rejects(context.fetchPacketStorm({}),
    /PACKETSTORM_COMMERCIAL_API_REQUIRED/);
  assert.equal(errors.length,1);
  assert.match(errors[0],/PacketStorm failed: PACKETSTORM_COMMERCIAL_API_REQUIRED/);
  assert.match(source,/recordSourceFailure\(state,\s*key,\s*e\.message\)/);
});

test('P0 source-bucket coverage remains transparent, not silently removed from monitoring',()=>{
  assert.match(source,/fetchPacketStorm,\s*'packetstorm'/);
  assert.match(source,/recordSourceFailure\(state,\s*key,\s*e\.message\)/);
  assert.match(source,/sourceStats\[k\]=\{fetched:b\.length\}/);
});
