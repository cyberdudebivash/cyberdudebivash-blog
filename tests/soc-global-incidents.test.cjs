// Run with: node --test tests/soc-global-incidents.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync('soc-global-incidents.js', 'utf8');
const context = {window: {}, URL, Set, Date, Number, Object};
vm.runInNewContext(code, context);
const validate = context.window.CDBGlobalIncidents.validate;
const stamp = '2026-10-31T12:00:00Z';
const url = 'https://example.org/advisory';
function feed() {
  return {schema:'cdb.global-incidents.v1', generated_at_utc:stamp, sha256:'a'.repeat(64),
    incidents:[{id:'event-1',title:'Example',category:'breach',first_seen_utc:stamp,
      updated_utc:stamp,status:'confirmed',severity:'critical',confidence:'high',
      sources:[{url,publisher:'Example CERT',published_at_utc:stamp,retrieved_at_utc:stamp}],
      claims:[{text:'Example claim',source_urls:[url],verification_state:'confirmed'}]}]};
}
test('accepts source-backed incident', () => assert.equal(validate(feed()), true));
test('rejects unverified confirmed status', () => {
  const f=feed(); f.incidents[0].claims[0].verification_state='reported';
  assert.equal(validate(f), false);
});
test('rejects insecure source URL', () => {
  const f=feed(); f.incidents[0].sources[0].url='http://example.org';
  assert.equal(validate(f), false);
});
test('rejects evidence link not in sources', () => {
  const f=feed(); f.incidents[0].claims[0].source_urls=['https://other.example'];
  assert.equal(validate(f), false);
});
test('rejects malformed envelope', () => assert.equal(validate({incidents:[]}), false));


test('only incidents updated in last 24h are eligible for the current feed', () => {
  const now = Date.parse('2026-10-31T13:00:00Z');
  const current = feed();
  current.incidents.push({
    id:'event-old',title:'Historical event',category:'breach',
    first_seen_utc:'2026-10-20T12:00:00Z',updated_utc:'2026-10-30T12:59:59Z',
    status:'investigating',severity:'high',confidence:'medium',
    sources:[{url,publisher:'Example CERT',published_at_utc:stamp,retrieved_at_utc:stamp}],
    claims:[{text:'Old claim',source_urls:[url],verification_state:'reported'}]
  });
  const recent = context.window.CDBGlobalIncidents.selectFreshIncidents(current, now);
  assert.deepEqual(Array.from(recent, r => r.id), ['event-1']);
  const oldOnly = feed();
  oldOnly.incidents[0].updated_utc = '2026-10-30T12:59:59Z';
  assert.deepEqual(Array.from(context.window.CDBGlobalIncidents.selectFreshIncidents(oldOnly, now)), []);
});

test('global incident feed fails closed on stale publication or future pipeline clock', () => {
  const base = feed();
  const select = context.window.CDBGlobalIncidents.selectFreshIncidents;
  assert.equal(select(base, Date.parse('2026-11-01T12:00:00Z')), null, 'stale feed must withhold cards');
  assert.equal(select(base, Date.parse('2026-10-31T11:54:59Z')), null, 'feed timestamp beyond allowed clock skew must withhold cards');
  assert.equal(select({incidents:[]}, Date.parse('2026-10-31T13:00:00Z')), null);
});
