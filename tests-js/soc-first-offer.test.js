'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const ROOT=path.resolve(__dirname,'..');
const source=file=>fs.readFileSync(path.join(ROOT,file),'utf8');
const { PUBLIC_ROOT_FILES, injectCustomerExperience, validatePublicHtmlStructure }=require('../scripts/build-cloudflare-assets.js');
const page=source('soc-readiness-assessment.html');

test('first service is explicitly allowlisted, accessible from SOC overview',()=>{
  assert.ok(PUBLIC_ROOT_FILES.includes('soc-readiness-assessment.html'));
  assert.match(source('soc.html'), /href="\/soc-readiness-assessment\.html">Request a SOC Assessment/);
  assert.match(source('.github/workflows/cloudflare-production-deploy.yml'), /- 'soc-readiness-assessment\.html'/);
});
test('standalone page and full public renderer preserve truthful content and unique SOC navigation',()=>{
  validatePublicHtmlStructure(page,'SOC assessment source');
  const html=injectCustomerExperience(page);
  assert.equal((html.match(/<main\b/g)||[]).length,1);
  assert.equal((html.match(/<\/main>/g)||[]).length,1);
  assert.equal((html.match(/data-soc-platform-shell="v1"/g)||[]).length,1);
  assert.equal((html.match(/soc-platform-ui\.css/g)||[]).length,1);
  assert.match(html,/SENTINEL APEX SOC/);
  assert.match(html,/Scope &amp; Pricing/);
  assert.match(html,/proprietorship business/);
  assert.match(html,/Request a Scoped Proposal/);
  assert.match(html,/customer-assurance\.html/);
  assert.match(html,/enterprise-onboarding\.html/);
  assert.match(html,/rel="canonical" href="https:\/\/blog\.cyberdudebivash\.in\/soc-readiness-assessment\.html"/);
});
test('sales promise fail-closed: no checkout, false acceptance, SOC 2 attestation or customer claim',()=>{
  assert.doesNotMatch(page,/payment-engine|razorpay|href=["']\/?checkout|customer count|verified client logo|Fortune 500 customer|SOC 2 Type II certified/i);
  assert.match(page,/not an active 24\/7 monitoring service or instant checkout/i);
  assert.match(page,/no payment is collected here/i);
  assert.match(page,/not an active 24\/7 monitoring service/i);
  assert.match(page,/No autonomous host isolation/i);
  assert.match(page,/in writing before work begins/i);
  assert.match(page,/mailto:contact@cyberdudebivash\.in\?subject=/);
  assert.match(page,/Do not send credentials, logs, personal data/i);
});
test('written acceptance, evidence inventories, signed scope and service exclusions are explicit',()=>{
  const doc=source('docs/commercial/SOC-FIRST-SELLABLE-SERVICE-2026-10-22.md');
  for(const marker of ['Signed scope and rules of engagement',
    'coverage and evidence inventory','Triage and detection quality matrix','Executive-ready report',
    'Handoff and acceptance receipt','NO-GO for managed SOC subscriptions','NOT VERIFIED']){
    assert.ok(doc.toLowerCase().includes(marker.toLowerCase()),'missing commercial guard: '+marker);
  }
});
