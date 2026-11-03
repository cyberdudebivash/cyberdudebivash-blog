'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'enterprise.html'), 'utf8');

function plannerScript() {
  const blocks = [...html.matchAll(/<script(?:\\s[^>]*)?>([\\s\\S]*?)<\\/script>/g)];
  const found = blocks.find(match => match[1].includes('function updateCostPlanner()'));
  assert.ok(found, 'Enterprise cost planner inline script missing');
  return found[1];
}

test('enterprise page uses SOC canonical host and avoids unsupported return claims', () => {
  assert.match(html, /rel="canonical" href="https:\/\/soc\.cyberdudebivash\.in\/enterprise\.html"/);
  assert.match(html, /property="og:url" content="https:\/\/soc\.cyberdudebivash\.in\/enterprise\.html"/);
  assert.doesNotMatch(html, /expected incidents prevented|breachCosts|cost avoided|estimated annual ROI|Response in 24 Hours/i);
  assert.match(html, /Not estimated without customer evidence/);
  assert.match(html, /Separate written scope required/);
  assert.doesNotMatch(html, /id="roi-budget"[^>]*value=/);
});

test('cost planner displays price only from validated public catalog, and guards invalid input', async () => {
  const ids = Object.fromEntries(['roi-budget','r-plan-monthly','r-plan-annual','r-plan-share']
    .map(id => [id, { textContent:'', value:'' }]));
  let ready = null;
  const ctx = {
    document: {
      getElementById(id) { assert.ok(ids[id], id); return ids[id]; },
      addEventListener(type, cb) { if (type === 'DOMContentLoaded') ready = cb; }
    },
    window: { IntelCheckout: { pricing() { return Promise.resolve({
      currency:'INR',unit:'paise',tiers:{ENTERPRISE:{usd_monthly:499,usd_annual:4990}}
    }); } } },
    Number
  };
  vm.runInNewContext(plannerScript(),ctx,{timeout:1000});
  assert.equal(typeof ready,'function');
  ready();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(ids['r-plan-annual'].textContent,'$4,990');
  assert.equal(ids['r-plan-monthly'].textContent,'$499');
  assert.equal(ids['r-plan-share'].textContent,'Enter a budget');
  ids['roi-budget'].value='10000';
  ctx.updateCostPlanner();
  assert.equal(ids['r-plan-share'].textContent,'49.9%');
  ids['roi-budget'].value='0';
  ctx.updateCostPlanner();
  assert.equal(ids['r-plan-share'].textContent,'Enter a positive amount');
});

test('missing pricing service never invents a paid amount or ROI', async () => {
  const ids = Object.fromEntries(['roi-budget','r-plan-monthly','r-plan-annual','r-plan-share']
    .map(id => [id, { textContent:'', value:'' }]));
  ids['roi-budget'].value='250000';
  let ready = null;
  const ctx={
    document:{getElementById(id){return ids[id]},addEventListener(event,cb){if(event==='DOMContentLoaded')ready=cb}},
    window:{ IntelCheckout: { pricing(){ return Promise.reject(new Error('price unavailable')); } } },Number
  };
  vm.runInNewContext(plannerScript(),ctx,{timeout:1000});
  ready();
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ids['r-plan-annual'].textContent,'Confirm at checkout');
  assert.equal(ids['r-plan-share'].textContent,'Confirm price at checkout');
});
