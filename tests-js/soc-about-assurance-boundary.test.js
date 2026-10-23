'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const about = fs.readFileSync(path.join(__dirname, '..', 'about.html'), 'utf8');

test('SOC About discloses scoped monitoring and response boundaries', () => {
  assert.match(about, /SENTINEL APEX SOC is a hybrid security operations/);
  assert.match(about, /not offered without a separately approved service agreement and operational acceptance/);
  assert.match(about, /service activation requires explicit scope, acceptance, and applicable terms/);
});

test('SOC About does not promise uncertified pipeline freshness or customer alert delivery', () => {
  assert.match(about, /successful generation alone does not establish timely public publication or customer alert delivery/);
  assert.doesNotMatch(about, /We monitor official vulnerability authorities and global security reporting around the clock/);
  assert.doesNotMatch(about, /pipeline continuously ingests public feeds/);
});

test('SOC About uses SOC canonical metadata and does not promote retired X profile', () => {
  assert.match(about, /<link rel="canonical" href="https:\/\/soc\.cyberdudebivash\.in\/about\.html">/);
  assert.match(about, /<meta property="og:url" content="https:\/\/soc\.cyberdudebivash\.in\/about\.html">/);
  assert.doesNotMatch(about, /https:\/\/x\.com\/cdbsentinelapex/);
});
