'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8');

test('both lead forms keep currently configured recipient and redirect to the SOC public origin',()=>{
  const contact=read('contact.html'), enterprise=read('enterprise.html');
  for (const [name,html] of [['contact',contact],['enterprise',enterprise]]) {
    assert.match(html,/action="https:\/\/formsubmit\.co\/bivash@cyberdudebivash\.com"/,name+' provider recipient changed without delivery receipt');
    assert.match(html,/name="_next" value="https:\/\/soc\.cyberdudebivash\.in\/contact\.html\?submitted=1"/,name+' redirects away from SOC');
    assert.doesNotMatch(html,/name="_next" value="https:\/\/blog\.cyberdudebivash\.in\//,name+' retains legacy return');
    assert.match(html,/FormSubmit/,name+' must disclose the external processor');
    assert.match(html,/href="\/privacy\.html"/,name+' needs a privacy-policy link');
    assert.match(html,/Do not include credentials/i,name+' should discourage sensitive submissions');
  }
});

test('form-return display never asserts verified inbox delivery or a fabricated sales conversion',()=>{
 const html=read('contact.html');
 assert.match(html,/new URLSearchParams\(window\.location\.search\)\.get\('submitted'\) === '1'/);
 assert.match(html,/cannot independently verify inbox delivery/i);
 assert.match(html,/enterprise_inquiry_form_return/);
 assert.doesNotMatch(html,/enterprise_inquiry_complete/);
 assert.doesNotMatch(html,/Inquiry Received — Thank You!/i);
 assert.match(html,/mailto:contact@cyberdudebivash\.in/);
});

test('customer-facing privacy claims disclose processors and align with the structured SOC origin',()=>{
 const contact=read('contact.html'), enterprise=read('enterprise.html'), privacy=read('privacy.html');
 const schema=contact.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
 assert.ok(schema,'ContactPage structured data missing');
 assert.equal(JSON.parse(schema[1]).url,'https://soc.cyberdudebivash.in/contact.html');
 assert.match(privacy,/<strong>FormSubmit<\/strong>/);
 assert.doesNotMatch(contact,/We never share your information with third parties/);
 assert.doesNotMatch(enterprise,/Your info is used only to respond to your inquiry/);
});
