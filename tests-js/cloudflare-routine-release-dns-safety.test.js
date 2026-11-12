'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {classifyDomainBinding,verify,HOSTNAME,SOC_HOSTNAME,HOSTNAMES,WORKER}=require('../scripts/verify-existing-cloudflare-domain.cjs');

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
  ['unexpected second filtered response page',{...sample([entry()]),result_info:{page:2,count:1,per_page:20,total_pages:2,total_count:101}},'DOMAIN_LIST_NOT_COMPLETE'],
  ['count inconsistent with returned filtered records',{...sample([entry()]),result_info:{page:1,count:2,per_page:20,total_pages:5,total_count:99}},'DOMAIN_LIST_NOT_COMPLETE'],
  ['zero page size from API',{...sample([entry()]),result_info:{page:1,count:1,per_page:0,total_pages:1,total_count:1}},'DOMAIN_LIST_NOT_COMPLETE'],
  ['unfiltered unrelated domain record',{...sample([entry(),entry({hostname:'another.example.com',id:'unrelated'})]),result_info:{page:1,count:2,per_page:20,total_count:400,total_pages:20}},'DOMAIN_UNFILTERED_LIST'],
  ['incorrect owning zone',{...sample([entry({zone_name:'unrelated.invalid'})]),result_info:{page:1,count:1,per_page:20}},'DOMAIN_WRONG_ZONE'],
]){
  test('negative: '+title+' fails closed',()=>assert.deepEqual(classifyDomainBinding(body),{ok:false,code}));
}
test('positive: account-wide Cloudflare pagination totals cannot falsely block a filtered singleton',()=>{
  // Cloudflare API example: total_count and total_pages represent broader
  // account inventory, even though hostname-filtered result has one record.
  const response={success:true,result:[entry({zone_name:'cyberdudebivash.in'})],
    result_info:{count:1,page:1,per_page:20,total_count:2000,total_pages:100}};
  assert.deepEqual(classifyDomainBinding(response),{ok:true,code:'DOMAIN_MAPPING_ESTABLISHED'});
});
test('positive: omitted optional result_info is acceptable with one exact hostname',()=>{
  assert.deepEqual(classifyDomainBinding({success:true,result:[entry()]}),
    {ok:true,code:'DOMAIN_MAPPING_ESTABLISHED'});
});
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
  const preDns=yaml.indexOf('P0 precondition — verify no legacy DNS origin before Wrangler mutation');
  const deploy=yaml.indexOf('Deploy Worker assets to the existing, approved domain');
  const post=yaml.indexOf('P0 postcondition — verify existing domain mapping unchanged');
  const postDns=yaml.indexOf('Verify Vercel DNS retirement');
  assert.ok(pre>0&&preDns>pre&&deploy>preDns&&post>deploy&&postDns>post,
    'read-only Worker mapping and legacy DNS proofs MUST precede Wrangler mutation');
  // The separate read-only legacy DNS gate must cover BOTH Custom Domains
  // before and after the Worker mutation, not merely the old blog hostname.
  assert.equal((yaml.match(/for hostname in blog\\.cyberdudebivash\\.in soc\\.cyberdudebivash\\.in; do/g)||[]).length,2);
  assert.equal((yaml.match(/dns_records\\?name=\\$hostname&per_page=100/g)||[]).length,2);
  assert.equal((yaml.match(/dns_valid=\\"\\$\\(jq -r --arg expected/g)||[]).length,2);
  assert.equal((yaml.match(/test "\\$dns_valid" = true/g)||[]).length,2);
  const dnsPrerequisite=yaml.slice(preDns,deploy);
  assert.match(dnsPrerequisite,/vercel_refs/);
  assert.match(dnsPrerequisite,/test "\$vercel_refs" -eq 0/);
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


test('SOC hostname has the same strict existing Worker binding requirement',()=>{
  const soc={...entry(),hostname:SOC_HOSTNAME};
  assert.deepEqual(classifyDomainBinding(sample([soc]),SOC_HOSTNAME),
    {ok:true,code:'DOMAIN_MAPPING_ESTABLISHED'});
  assert.deepEqual(classifyDomainBinding(sample([soc]),HOSTNAME),
    {ok:false,code:'DOMAIN_NOT_ESTABLISHED'});
  assert.deepEqual(classifyDomainBinding(sample([entry({hostname:'unknown.invalid'})]),SOC_HOSTNAME),
    {ok:false,code:'DOMAIN_NOT_ESTABLISHED'});
  assert.deepEqual(classifyDomainBinding(sample([soc]),'unapproved.example'),
    {ok:false,code:'DOMAIN_HOST_NOT_APPROVED'});
});

test('read-only routine release verifier checks BOTH configured Worker custom domains',async()=>{
  const requested=[];
  const fakeFetch=async (url,opts)=>{
    assert.equal(opts.method,'GET');
    assert.equal(opts.redirect,'error');
    const host=url.searchParams.get('hostname');
    requested.push(host);
    assert.ok(HOSTNAMES.includes(host));
    return new Response(JSON.stringify(sample([entry({hostname:host})])),{
      status:200,headers:{'content-type':'application/json'}
    });
  };
  const result=await verify({
    token:'test-only-non-secret-token',accountId:'a'.repeat(32),fetchImpl:fakeFetch
  });
  assert.deepEqual(result,{ok:true,code:'ALL_DEPLOY_DOMAINS_ESTABLISHED'});
  assert.deepEqual(requested,HOSTNAMES,
    'success on blog must never skip the independent SOC mapping proof');
});

test('SOC binding absent or assigned to another Worker blocks BEFORE Wrangler',async()=>{
  for(const bad of [[],[entry({hostname:SOC_HOSTNAME,service:'other-worker'})],
                   [entry({hostname:SOC_HOSTNAME,enabled:false})]]){
    const requested=[];
    const fakeFetch=async url=>{
      const host=url.searchParams.get('hostname');
      requested.push(host);
      return new Response(JSON.stringify(sample(
        host===HOSTNAME?[entry()]:bad)),{status:200});
    };
    await assert.rejects(verify({
      token:'test-only-non-secret-token',accountId:'a'.repeat(32),
      fetchImpl:fakeFetch
    }),/DOMAIN_NOT_ESTABLISHED|DOMAIN_WRONG_WORKER|DOMAIN_NOT_ENABLED/);
    assert.deepEqual(requested,HOSTNAMES);
  }
});

test('verified Worker domain set must match exact Custom Domain routes in Wrangler config',()=>{
  const jsonc=fs.readFileSync(path.resolve(__dirname,'../wrangler.jsonc'),'utf8');
  const matches=[...jsonc.matchAll(/"pattern":\s*"([^"]+)"\s*,\s*"custom_domain":\s*true/g)]
    .map(m=>m[1]).sort();
  assert.deepEqual(matches,[...HOSTNAMES].sort(),
    'changing a Wrangler Custom Domain requires a matching predeploy proof update');
});
