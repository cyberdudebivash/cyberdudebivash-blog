'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {classifyDomainBinding,HOSTNAME,WORKER}=require('../scripts/verify-existing-cloudflare-domain.cjs');

const entry=overrides=>({
  id:'synthetic-domain-id',hostname:HOSTNAME,service:WORKER,enabled:true,...overrides
});
const sample=domains=>({
  success:true,result:domains,result_info:{total_pages:1,total_count:domains.length}
});
const result=domains=>classifyDomainBinding(sample(domains));
test('positive: exactly one enabled existing custom domain bound to the expected Worker permits routine release',()=>{
  assert.deepEqual(result([entry()]),{ok:true,code:'DOMAIN_MAPPING_ESTABLISHED'});
});
for(const [title,body,code] of [
  ['no existing custom domain',sample([]),'DOMAIN_NOT_ESTABLISHED'],
  ['wrong Cloudflare worker',sample([entry({service:'unrelated-worker'})]),'DOMAIN_WRONG_WORKER'],
  ['disabled Cloudflare custom domain',sample([entry({enabled:false})]),'DOMAIN_NOT_ENABLED'],
  ['duplicate hostname bindings',sample([entry(),entry({id:'other'})]),'DOMAIN_DUPLICATE'],
  ['missing binding id',sample([entry({id:null})]),'DOMAIN_ID_MISSING'],
  ['invalid API response',{success:false,result:[entry()]},'DOMAIN_API_RESPONSE_INVALID'],
  ['truncated/paginated domain listing',{...sample([entry()]),result_info:{total_pages:2,total_count:101}},'DOMAIN_LIST_NOT_COMPLETE'],
]){
  test('negative: '+title+' fails closed',()=>assert.deepEqual(classifyDomainBinding(body),{ok:false,code}));
}
test('negative: unrelated hostname is not proof of expected domain mapping',()=>{
  assert.deepEqual(result([entry({hostname:'soc.cyberdudebivash.in'})]),{
    ok:false,code:'DOMAIN_NOT_ESTABLISHED',
  });
});
test('negative: a DNS CNAME record without an existing Worker custom domain cannot pass',()=>{
  assert.deepEqual(classifyDomainBinding({success:true,result:[{
    id:'dns-only',type:'CNAME',name:HOSTNAME,content:'legacy.vercel-dns.com'}]}),{
    ok:false,code:'DOMAIN_NOT_ESTABLISHED',
  });
});
test('production workflow neither deletes/restores nor creates DNS records',()=>{
  const yaml=fs.readFileSync(path.resolve(__dirname,'../.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  assert.match(yaml,/if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(yaml,/environment: production/);
  assert.doesNotMatch(yaml,/Retire Vercel DNS and deploy Cloudflare Custom Domain atomically/);
  assert.doesNotMatch(yaml,/curl[^\n]+-X (?:DELETE|POST|PUT|PATCH)[^\n]+dns_records/);
  assert.doesNotMatch(yaml,/rollback_needed|legacy_record|restore_payload/);
  const pre=yaml.indexOf('P0 precondition — verify established Worker Custom Domain');
  const deploy=yaml.indexOf('Deploy Worker assets to the existing, approved domain');
  const post=yaml.indexOf('P0 postcondition — verify existing domain mapping unchanged');
  assert.ok(pre>0&&deploy>pre&&post>deploy,
    'the read-only binding check must surround the only Cloudflare deploy step');
  assert.equal((yaml.match(/node scripts\/verify-existing-cloudflare-domain\.cjs/g)||[]).length,2);
  assert.equal((yaml.match(/npx wrangler deploy --config wrangler\.jsonc/g)||[]).length,1);
  assert.match(yaml,/node scripts\/soc-live-release-parity\.cjs/);
});
test('domain precondition is read-only and token values are never printed',()=>{
  const code=fs.readFileSync(path.resolve(__dirname,'../scripts/verify-existing-cloudflare-domain.cjs'),'utf8');
  assert.match(code,/method:'GET'/);
  assert.match(code,/\/workers\/domains/);
  assert.doesNotMatch(code,/method:'(?:DELETE|PUT|POST|PATCH)'/);
  assert.doesNotMatch(code,/console\.(?:log|error)\([^)]*(?:token|accountId|body)/);
});
